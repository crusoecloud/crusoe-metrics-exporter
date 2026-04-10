package collectors

import (
	"bufio"
	_ "embed"
	"encoding/binary"
	"fmt"
	"metrics-exporter/src/log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
)

// Use the working TCP eBPF program for NFS monitoring
// NFS traffic runs over TCP, so we can reuse the TCP latency eBPF program
//
//go:embed ebpf/nfs_latency.o
var nfsLatencyBPF []byte

// NFSConfig holds configuration for NFS latency monitoring
type NFSConfig struct {
	ServerIPs            []string      // NFS server IPs to monitor
	Protocols            []string      // "tcp", "udp", or both
	TargetPorts          []uint16      // Custom ports (default: 2049)
	EnableVolumeID       bool          // Enable volume ID extraction (default: true)
	MountRefreshInterval time.Duration // How often to refresh mount info (default: 30s)
	HostMountsPath       string        // Path to host mounts file (default: /proc/mounts, container: /host/proc/1/mounts)
}

// NFSLatencyCollector monitors NFS request latency using eBPF kprobes
type NFSLatencyCollector struct {
	objs              *ebpf.Collection
	tcpSendLink       link.Link
	tcpRecvLink       link.Link
	retransmitLink    link.Link
	udpSendLink       link.Link
	latencyDesc       *prometheus.Desc
	requestsDesc      *prometheus.Desc
	retransmitDesc    *prometheus.Desc
	latencyHistDesc   *prometheus.Desc
	volumeMapping     *VolumeMapping
	config            NFSConfig
	lastMappingUpdate time.Time
	mappingMutex      sync.RWMutex
}

// NewNFSLatencyCollector creates a new NFS latency collector
func NewNFSLatencyCollector(config NFSConfig) (*NFSLatencyCollector, error) {
	// Set defaults
	if len(config.TargetPorts) == 0 {
		config.TargetPorts = []uint16{2049}
	}
	if len(config.Protocols) == 0 {
		config.Protocols = []string{"tcp"}
	}
	if config.MountRefreshInterval == 0 {
		config.MountRefreshInterval = 30 * time.Second
	}
	if config.HostMountsPath == "" {
		config.HostMountsPath = "/proc/mounts"
	}

	c := &NFSLatencyCollector{
		latencyDesc: prometheus.NewDesc(
			MetricPrefix+"nfs_latency_seconds",
			"NFS request latency in seconds",
			[]string{"protocol", "operation", "volume_id"},
			nil,
		),
		requestsDesc: prometheus.NewDesc(
			MetricPrefix+"nfs_requests_total",
			"Total number of NFS requests",
			[]string{"protocol", "operation", "volume_id"},
			nil,
		),
		retransmitDesc: prometheus.NewDesc(
			MetricPrefix+"nfs_tcp_retransmits_total",
			"Total number of TCP retransmissions to NFS servers",
			[]string{"protocol", "operation", "volume_id"},
			nil,
		),
		latencyHistDesc: prometheus.NewDesc(
			MetricPrefix+"nfs_latency_histogram_seconds",
			"Histogram of NFS request latency in seconds",
			[]string{"protocol", "operation", "volume_id"},
			nil,
		),
		volumeMapping: NewVolumeMapping(),
		config:        config,
	}

	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memory lock: %w", err)
	}

	// Load pre-compiled eBPF program
	spec, err := ebpf.LoadCollectionSpecFromReader(strings.NewReader(string(nfsLatencyBPF)))
	if err != nil {
		// If eBPF fails to load, fail gracefully - don't create a non-functional collector
		return nil, fmt.Errorf("failed to load eBPF program: %w", err)
	}

	c.objs, err = ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	// Configure target ports in eBPF program
	if err := c.configurePorts(); err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to configure ports: %w", err)
	}

	// Populate NFS server IPs in the eBPF map so the probe knows which
	// destinations to track.  We always scan /proc/mounts for NFS IPs
	// (regardless of EnableVolumeID) and merge with config.ServerIPs.
	if err := c.populateNFSServerIPs(); err != nil {
		log.Warnf("failed to populate NFS server IPs: %v", err)
	}

	// Attach kprobes
	if err := c.attachKprobes(); err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to attach kprobes: %w", err)
	}

	// Initial volume mapping update (for volume ID labels)
	if config.EnableVolumeID {
		if err := c.updateVolumeMapping(); err != nil {
			log.Warnf("failed to update volume mapping: %v", err)
		}
	}

	return c, nil
}

// configurePorts sets the target port in the TCP eBPF config map
func (c *NFSLatencyCollector) configurePorts() error {
	configMap := c.objs.Maps["config_map"]
	if configMap == nil {
		return fmt.Errorf("config_map not found in eBPF collection")
	}

	// For NFS, we'll use the first target port (typically 2049)
	if len(c.config.TargetPorts) == 0 {
		return fmt.Errorf("no target ports specified")
	}

	targetPort := c.config.TargetPorts[0] // Use first port for TCP eBPF

	// Config structure matching the TCP eBPF C struct
	config := struct {
		TargetPort uint16
		Padding    uint16
	}{
		TargetPort: targetPort,
		Padding:    0,
	}

	// Key is always 0 for the single config entry in TCP eBPF
	var key uint32 = 0

	if err := configMap.Put(&key, &config); err != nil {
		return fmt.Errorf("failed to set port config: %w", err)
	}

	log.Infof("Configured eBPF to track NFS port %d", targetPort)
	return nil
}

// attachKprobes attaches kprobes to NFS-related functions
func (c *NFSLatencyCollector) attachKprobes() error {
	log.Infof("Attempting to attach NFS kprobes...")

	// Attach TCP probes if enabled
	for _, protocol := range c.config.Protocols {
		if strings.ToLower(protocol) == "tcp" {
			if err := c.attachTCPProbes(); err != nil {
				return fmt.Errorf("failed to attach TCP probes: %w", err)
			}
		}
		if strings.ToLower(protocol) == "udp" {
			if err := c.attachUDPProbes(); err != nil {
				return fmt.Errorf("failed to attach UDP probes: %w", err)
			}
		}
	}

	log.Infof("All NFS eBPF kprobes attached successfully")
	return nil
}

// attachTCPProbes attaches TCP-specific probes using TCP eBPF program
func (c *NFSLatencyCollector) attachTCPProbes() error {
	// Attach to tcp_sendmsg (outbound)
	sendProg := c.objs.Programs["tcp_sendmsg_entry"]
	if sendProg == nil {
		return fmt.Errorf("tcp_sendmsg_entry program not found")
	}

	log.Infof("Attaching kprobe to tcp_sendmsg for NFS...")
	sendLink, err := link.Kprobe("tcp_sendmsg", sendProg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tcp_sendmsg kprobe: %w", err)
	}
	c.tcpSendLink = sendLink

	// Attach to tcp_recvmsg entry (inbound - record socket)
	recvEntryProg := c.objs.Programs["tcp_recvmsg_entry"]
	if recvEntryProg == nil {
		return fmt.Errorf("tcp_recvmsg_entry program not found")
	}

	log.Infof("Attaching kprobe to tcp_recvmsg (entry) for NFS...")
	recvEntryLink, err := link.Kprobe("tcp_recvmsg", recvEntryProg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tcp_recvmsg kprobe: %w", err)
	}
	c.tcpRecvLink = recvEntryLink

	// Attach to tcp_recvmsg exit (inbound - calculate latency)
	recvExitProg := c.objs.Programs["tcp_recvmsg_exit"]
	if recvExitProg == nil {
		return fmt.Errorf("tcp_recvmsg_exit program not found")
	}

	log.Infof("Attaching kretprobe to tcp_recvmsg (exit) for NFS...")
	_, err = link.Kretprobe("tcp_recvmsg", recvExitProg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tcp_recvmsg kretprobe: %w", err)
	}
	// Note: We don't need to store this link as it's handled by the eBPF program

	// Attach to tcp_retransmit_skb (retransmission counter)
	retransmitProg := c.objs.Programs["tcp_retransmit_entry"]
	if retransmitProg != nil {
		log.Infof("Attaching kprobe to tcp_retransmit_skb for NFS...")
		retransmitLink, err := link.Kprobe("tcp_retransmit_skb", retransmitProg, nil)
		if err != nil {
			log.Warnf("failed to attach tcp_retransmit_skb kprobe: %v (retransmit metrics unavailable)", err)
		} else {
			c.retransmitLink = retransmitLink
			log.Infof("Successfully attached tcp_retransmit_skb kprobe for NFS")
		}
	}

	log.Infof("Successfully attached TCP NFS probes")
	return nil
}

// attachUDPProbes attaches UDP-specific probes
func (c *NFSLatencyCollector) attachUDPProbes() error {
	// Attach to udp_sendmsg (outbound)
	sendProg := c.objs.Programs["nfs_udp_sendmsg_entry"]
	if sendProg == nil {
		return fmt.Errorf("nfs_udp_sendmsg_entry program not found")
	}

	log.Infof("Attaching kprobe to udp_sendmsg for NFS...")
	sendLink, err := link.Kprobe("udp_sendmsg", sendProg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach udp_sendmsg kprobe: %w", err)
	}
	c.udpSendLink = sendLink

	log.Infof("Successfully attached UDP NFS probes")
	return nil
}

// resolveDomainName resolves a domain name to all its IP addresses
func (c *NFSLatencyCollector) resolveDomainName(domainName string) []string {
	var ips []string

	// Try to resolve the domain name
	addrs, err := net.LookupHost(domainName)
	if err == nil {
		for _, addr := range addrs {
			// Validate that it's an IP address
			if ip := net.ParseIP(addr); ip != nil {
				ips = append(ips, addr)
			}
		}
	}

	// If DNS resolution failed or returned no IPs, return empty slice
	return ips
}

// extractIPsFromMountOptions extracts all IPs from mount options
func (c *NFSLatencyCollector) extractIPsFromMountOptions(fields []string) []string {
	var ips []string

	// Join all fields from index 5 onwards (options)
	optionsString := strings.Join(fields[5:], " ")

	// Find all addr= occurrences (not mountaddr=)
	searchStart := 0
	for {
		// Look for addr= (not mountaddr=) in the options string
		addrIndex := strings.Index(optionsString[searchStart:], ",addr=")
		if addrIndex == -1 {
			// Try without comma (if it's the first option)
			if searchStart == 0 {
				addrIndex = strings.Index(optionsString, "addr=")
			}
			if addrIndex == -1 {
				break
			}
		}

		// Adjust for search start position
		addrIndex += searchStart

		// Extract the IP starting from addr=
		addrStart := addrIndex + 5 // len("addr=")
		// Skip comma if present
		if optionsString[addrIndex] == ',' {
			addrStart++
		}
		// Find the end of the IP (next comma, space, or closing paren)
		addrEnd := addrStart
		for addrEnd < len(optionsString) {
			char := optionsString[addrEnd]
			if char == ',' || char == ' ' || char == ')' {
				break
			}
			addrEnd++
		}
		if addrEnd > addrStart {
			ip := optionsString[addrStart:addrEnd]
			// Validate IP format
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		}

		// Continue searching from after this IP
		searchStart = addrEnd
	}

	return ips
}

// updateVolumeMapping updates the volume mapping from mount information and
// refreshes the eBPF nfs_server_ips map with ALL discovered NFS server IPs
// (not just those with volume ID mappings).
func (c *NFSLatencyCollector) updateVolumeMapping() error {
	file, err := os.Open(c.config.HostMountsPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", c.config.HostMountsPath, err)
	}
	defer file.Close()

	// mapping: IP → volume ID (only for mounts with :/volumes/ path)
	mapping := make(map[string]string)
	// allNFSIPs: every NFS server IP discovered, regardless of volume mapping
	allNFSIPs := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		serverPath := fields[0]
		fsType := fields[2]

		if fsType != "nfs" && fsType != "nfs4" {
			continue
		}

		// Discover IPs from this NFS mount (addr= option or server part)
		var mountIPs []string
		if len(fields) >= 6 {
			mountIPs = c.extractIPsFromMountOptions(fields)
		}
		if len(mountIPs) == 0 {
			colonIdx := strings.Index(serverPath, ":")
			if colonIdx > 0 {
				serverPart := serverPath[:colonIdx]
				if net.ParseIP(serverPart) != nil {
					mountIPs = []string{serverPart}
				} else {
					mountIPs = c.resolveDomainName(serverPart)
				}
			}
		}

		// Add all discovered IPs to the full set
		for _, ip := range mountIPs {
			allNFSIPs[ip] = true
		}

		// Extract volume ID from server:/volumes/{uuid}
		if strings.Contains(serverPath, ":/volumes/") {
			parts := strings.Split(serverPath, ":/volumes/")
			if len(parts) == 2 {
				volumeID := parts[1]
				for _, ip := range mountIPs {
					mapping[ip] = volumeID
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading /proc/mounts: %w", err)
	}

	// Also include explicitly configured server IPs
	for _, ip := range c.config.ServerIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			allNFSIPs[ip] = true
		} else {
			for _, rip := range c.resolveDomainName(ip) {
				allNFSIPs[rip] = true
			}
		}
	}

	c.volumeMapping.UpdateMapping(mapping)
	c.lastMappingUpdate = time.Now()
	log.Infof("Updated NFS volume mapping: %d volume entries, %d total server IPs", len(mapping), len(allNFSIPs))

	// Update eBPF map with ALL NFS server IPs (not just volume-mapped ones)
	allIPMapping := make(map[string]string)
	for ip := range allNFSIPs {
		if vol, ok := mapping[ip]; ok {
			allIPMapping[ip] = vol
		} else {
			allIPMapping[ip] = ""
		}
	}
	if err := c.updateNFSServerIPsMap(allIPMapping); err != nil {
		log.Warnf("failed to update NFS server IPs map: %v", err)
	}

	return nil
}

// populateNFSServerIPs discovers all NFS server IPs from config and /proc/mounts
// and writes them into the nfs_server_ips eBPF map so the probe knows which
// destinations to track.
func (c *NFSLatencyCollector) populateNFSServerIPs() error {
	serverIPsMap := c.objs.Maps["nfs_server_ips"]
	if serverIPsMap == nil {
		return fmt.Errorf("nfs_server_ips map not found in eBPF collection")
	}

	// Collect unique IPs from all sources
	uniqueIPs := make(map[string]bool)

	// Source 1: Explicit config.ServerIPs
	for _, ip := range c.config.ServerIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		// If it's already a valid IP, add directly
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			uniqueIPs[ip] = true
		} else {
			// Try DNS resolution for hostnames
			resolved := c.resolveDomainName(ip)
			for _, rip := range resolved {
				uniqueIPs[rip] = true
			}
		}
	}

	// Source 2: Scan host mounts for NFS mount IPs
	log.Infof("Scanning %s for NFS mounts...", c.config.HostMountsPath)
	file, err := os.Open(c.config.HostMountsPath)
	if err != nil {
		log.Warnf("cannot read %s for NFS IP discovery: %v", c.config.HostMountsPath, err)
	} else {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 3 {
				continue
			}
			fsType := fields[2]
			if fsType != "nfs" && fsType != "nfs4" {
				continue
			}

			// Extract IPs from mount options (addr=X.X.X.X)
			if len(fields) >= 6 {
				ips := c.extractIPsFromMountOptions(fields)
				for _, ip := range ips {
					uniqueIPs[ip] = true
				}
			}

			// Also try the server part of device (server:/path)
			serverPath := fields[0]
			colonIdx := strings.Index(serverPath, ":")
			if colonIdx > 0 {
				serverPart := serverPath[:colonIdx]
				if parsedIP := net.ParseIP(serverPart); parsedIP != nil {
					uniqueIPs[serverPart] = true
				} else {
					resolved := c.resolveDomainName(serverPart)
					for _, rip := range resolved {
						uniqueIPs[rip] = true
					}
				}
			}
		}
	}

	if len(uniqueIPs) == 0 {
		log.Warnf("no NFS server IPs found from config or /proc/mounts -- eBPF probe will not track any traffic")
		return nil
	}

	// Write all unique IPs into the eBPF array map
	index := uint32(0)
	for ip := range uniqueIPs {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}
		ipv4 := parsedIP.To4()
		if ipv4 == nil {
			log.Warnf("non-IPv4 address %s, skipping", ip)
			continue
		}
		ipUint32 := binary.LittleEndian.Uint32(ipv4)
		if err := serverIPsMap.Update(&index, &ipUint32, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to update nfs_server_ips at index %d with IP %s: %w", index, ip, err)
		}
		log.Infof("NFS eBPF: added server IP %s (0x%08x) at index %d", ip, ipUint32, index)
		index++
		if index >= 64 { // map max_entries
			log.Warnf("nfs_server_ips map full at 64 entries, remaining IPs skipped")
			break
		}
	}

	log.Infof("Populated nfs_server_ips eBPF map with %d IPs", index)
	return nil
}

// updateNFSServerIPsMap updates the eBPF NFS server IPs map with real NFS server IPs.
// It writes the new IPs and then zeros out any remaining slots so the eBPF probe's
// is_nfs_server() loop terminates correctly when the set shrinks.
func (c *NFSLatencyCollector) updateNFSServerIPsMap(mapping map[string]string) error {
	serverIPsMap := c.objs.Maps["nfs_server_ips"]
	if serverIPsMap == nil {
		return fmt.Errorf("nfs_server_ips map not found in eBPF collection")
	}

	// Collect unique NFS server IPs
	uniqueIPs := make(map[string]bool)
	for ip := range mapping {
		uniqueIPs[ip] = true
	}

	// Populate the eBPF map with NFS server IPs
	index := uint32(0)
	for ip := range uniqueIPs {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			log.Warnf("invalid IP address %s, skipping", ip)
			continue
		}
		ipv4 := parsedIP.To4()
		if ipv4 == nil {
			log.Warnf("non-IPv4 address %s, skipping", ip)
			continue
		}
		ipUint32 := binary.LittleEndian.Uint32(ipv4)
		if err := serverIPsMap.Update(&index, &ipUint32, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to update nfs_server_ips map at index %d with IP %s: %w", index, ip, err)
		}
		log.Infof("Added NFS server IP %s to eBPF map at index %d", ip, index)
		index++
		if index >= 64 {
			log.Warnf("nfs_server_ips map full at 64 entries, remaining IPs skipped")
			break
		}
	}

	// Zero out remaining slots so the eBPF is_nfs_server() loop stops
	var zero uint32
	for i := index; i < 64; i++ {
		_ = serverIPsMap.Update(&i, &zero, ebpf.UpdateAny)
	}

	log.Infof("Updated eBPF NFS server IPs map with %d IPs (cleared %d stale slots)", index, 64-index)
	return nil
}

// refreshMountsIfNeeded re-scans /proc/mounts for NFS server IPs and updates
// both the volume mapping and the eBPF nfs_server_ips map.  This is called at
// the start of every Collect so that mounts added after startup are detected.
func (c *NFSLatencyCollector) refreshMountsIfNeeded() {
	c.mappingMutex.RLock()
	needsRefresh := time.Since(c.lastMappingUpdate) > c.config.MountRefreshInterval
	c.mappingMutex.RUnlock()

	if !needsRefresh {
		return
	}

	c.mappingMutex.Lock()
	defer c.mappingMutex.Unlock()

	// Double-check after acquiring write lock
	if time.Since(c.lastMappingUpdate) <= c.config.MountRefreshInterval {
		return
	}

	if err := c.updateVolumeMapping(); err != nil {
		log.Warnf("failed to refresh NFS mounts: %v", err)
	}
}

// getVolumeID returns the volume ID for a given IP and export path hash
func (c *NFSLatencyCollector) getVolumeID(ip string, exportPathHash uint64) string {
	if !c.config.EnableVolumeID {
		return ""
	}

	// Try to resolve volume ID using export path hash first
	volumeID := c.volumeMapping.GetVolumeIDByHash(ip, exportPathHash)
	if volumeID == "" {
		// Fallback to IP-based mapping for backward compatibility
		volumeID = c.volumeMapping.GetVolumeID(ip)
	}

	if volumeID == "" {
		// If no mapping found, use hash-based identifier
		volumeID = fmt.Sprintf("unknown-%x", exportPathHash)
	}

	return volumeID
}

// Describe implements prometheus.Collector
func (c *NFSLatencyCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.latencyDesc
	ch <- c.requestsDesc
	ch <- c.retransmitDesc
	ch <- c.latencyHistDesc
}

// nfsVolumeAgg holds aggregated stats for a single volume_id.
type nfsVolumeAgg struct {
	requestCount    uint64
	totalLatencyNs  uint64
	histogram       [HISTOGRAM_BUCKETS]uint64
	retransmitCount uint64
}

// Collect implements prometheus.Collector
func (c *NFSLatencyCollector) Collect(ch chan<- prometheus.Metric) {
	// Periodically re-scan /proc/mounts for new NFS mounts and update the
	// eBPF server IPs map.  This ensures mounts added after startup are detected.
	c.refreshMountsIfNeeded()

	// Get the nfs_latency_by_ip map from the NFS eBPF program
	latencyMap := c.objs.Maps["nfs_latency_by_ip"]
	if latencyMap == nil {
		log.Errorf("nfs_latency_by_ip map not found in eBPF collection")
		return
	}

	// Iterate over all entries in the map (using TCP eBPF data structure)
	var key struct {
		DstIP uint32
	}
	var value struct {
		RequestCount    uint64
		TotalLatency    uint64
		Histogram       [HISTOGRAM_BUCKETS]uint64
		RetransmitCount uint64
	}

	// Aggregate across all endpoints, keyed by volume_id
	byVolume := make(map[string]*nfsVolumeAgg)

	totalEntries := 0
	iter := latencyMap.Iterate()
	for iter.Next(&key, &value) {
		totalEntries++

		ipStr := ipUint32ToString(key.DstIP)

		volumeID := c.getVolumeID(ipStr, 0)
		if volumeID == "" {
			volumeID = "unknown"
		}

		agg, ok := byVolume[volumeID]
		if !ok {
			agg = &nfsVolumeAgg{}
			byVolume[volumeID] = agg
		}
		agg.requestCount += value.RequestCount
		agg.totalLatencyNs += value.TotalLatency
		agg.retransmitCount += value.RetransmitCount
		for i := 0; i < HISTOGRAM_BUCKETS; i++ {
			agg.histogram[i] += value.Histogram[i]
		}
	}

	if err := iter.Err(); err != nil {
		log.Errorf("Error iterating over nfs_latency_by_ip map: %v", err)
	}

	protocol := "tcp"
	operationName := "nfs"

	for volumeID, agg := range byVolume {
		latencySeconds := float64(agg.totalLatencyNs) / 1e9

		ch <- prometheus.MustNewConstMetric(
			c.requestsDesc,
			prometheus.CounterValue,
			float64(agg.requestCount),
			protocol,
			operationName,
			volumeID,
		)

		ch <- prometheus.MustNewConstMetric(
			c.latencyDesc,
			prometheus.CounterValue,
			latencySeconds,
			protocol,
			operationName,
			volumeID,
		)

		ch <- prometheus.MustNewConstMetric(
			c.retransmitDesc,
			prometheus.CounterValue,
			float64(agg.retransmitCount),
			protocol,
			operationName,
			volumeID,
		)

		histBuckets, histCount, histSum := histogramToBuckets(agg.histogram, histogramBucketBoundaries)
		ch <- prometheus.MustNewConstHistogram(
			c.latencyHistDesc,
			histCount,
			histSum,
			histBuckets,
			protocol,
			operationName,
			volumeID,
		)
	}

	log.Debugf("NFS metrics collection: %d map entries, %d volumes emitted",
		totalEntries, len(byVolume))
}

// Close cleans up eBPF resources
func (c *NFSLatencyCollector) Close() error {
	var errs []error

	if c.tcpSendLink != nil {
		if err := c.tcpSendLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close TCP send link: %w", err))
		}
	}

	if c.tcpRecvLink != nil {
		if err := c.tcpRecvLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close TCP recv link: %w", err))
		}
	}

	if c.retransmitLink != nil {
		if err := c.retransmitLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close retransmit link: %w", err))
		}
	}

	if c.udpSendLink != nil {
		if err := c.udpSendLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close UDP send link: %w", err))
		}
	}

	if c.objs != nil {
		c.objs.Close()
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}

	return nil
}
