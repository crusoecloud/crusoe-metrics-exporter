package collectors

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"metrics-exporter/src/log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
)

//go:embed ebpf/objstore_latency.o
var objstoreLatencyBPF []byte

// ObjStoreConfig holds configuration for object store latency monitoring
type ObjStoreConfig struct {
	InitialIPs      []string      // Initial object store endpoint IPs
	FQDN            string        // FQDN for periodic DNS re-resolution
	TargetPort      uint16        // Port to monitor (e.g., 443)
	RefreshInterval time.Duration // How often to re-resolve FQDN (default 5m)
}

// ObjStoreLatencyCollector monitors object store request latency using eBPF kprobes
type ObjStoreLatencyCollector struct {
	objs              *ebpf.Collection
	sendLink          link.Link
	recvLink          link.Link
	retransmitLink    link.Link
	latencyDesc       *prometheus.Desc
	requestsDesc      *prometheus.Desc
	retransmitDesc    *prometheus.Desc
	bytesSentDesc     *prometheus.Desc
	bytesRecvDesc     *prometheus.Desc
	latencyHistDesc   *prometheus.Desc
	objStoreEndpoints map[uint32]bool // IP addresses of object store endpoints (network byte order)
	endpointMutex     sync.RWMutex
	filterIPs         []string     // IP filter strings (for testing)
	filterNets        []*net.IPNet // Parsed CIDR networks (for testing)
	config            ObjStoreConfig
	lastFQDNRefresh   time.Time
	refreshMutex      sync.RWMutex
}

// NewObjStoreLatencyCollector creates a new object store latency collector
func NewObjStoreLatencyCollector(config ObjStoreConfig) (*ObjStoreLatencyCollector, error) {
	// Set defaults
	if config.TargetPort == 0 {
		config.TargetPort = 443
	}
	if config.RefreshInterval == 0 {
		config.RefreshInterval = 5 * time.Minute
	}

	c := &ObjStoreLatencyCollector{
		latencyDesc: prometheus.NewDesc(
			MetricPrefix+"objectstore_connection_latency_seconds",
			"Object store connection-phase latency in seconds (send-to-recv on same socket)",
			[]string{"endpoint"},
			nil,
		),
		requestsDesc: prometheus.NewDesc(
			MetricPrefix+"objectstore_connections_total",
			"Total number of object store connection phases observed",
			[]string{"endpoint"},
			nil,
		),
		retransmitDesc: prometheus.NewDesc(
			MetricPrefix+"objectstore_tcp_retransmits_total",
			"Total number of TCP retransmissions to object store servers",
			[]string{"endpoint"},
			nil,
		),
		bytesSentDesc: prometheus.NewDesc(
			MetricPrefix+"objectstore_bytes_sent_total",
			"Total bytes sent to object store servers",
			[]string{"endpoint"},
			nil,
		),
		bytesRecvDesc: prometheus.NewDesc(
			MetricPrefix+"objectstore_bytes_recv_total",
			"Total bytes received from object store servers",
			[]string{"endpoint"},
			nil,
		),
		latencyHistDesc: prometheus.NewDesc(
			MetricPrefix+"objectstore_connection_latency_histogram_seconds",
			"Histogram of object store connection-phase latency in seconds",
			[]string{"endpoint"},
			nil,
		),
		objStoreEndpoints: make(map[uint32]bool),
		filterIPs:         config.InitialIPs,
		config:            config,
		lastFQDNRefresh:   time.Now(),
	}

	// Parse filter IPs if provided
	if len(config.InitialIPs) > 0 {
		if err := c.parseIPFilters(); err != nil {
			return nil, fmt.Errorf("failed to parse IP filters: %w", err)
		}
	}

	// Remove memory lock limit to allow eBPF map creation
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warnf("failed to remove memlock limit: %v (trying anyway)", err)
	}

	// Load eBPF program
	if err := c.loadBPF(); err != nil {
		return nil, fmt.Errorf("failed to load eBPF program: %w", err)
	}

	// Configure target port in eBPF program
	if err := c.configurePort(config.TargetPort); err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to configure port: %w", err)
	}

	// Attach kprobes
	if err := c.attachKprobes(); err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to attach kprobes: %w", err)
	}

	// Populate eBPF object store server IPs map with real endpoints
	if err := c.updateObjStoreServerIPsMap(); err != nil {
		log.Warnf("failed to update object store server IPs map: %v", err)
	}

	// Add object store endpoint IPs from filter list
	for _, ipOrHost := range config.InitialIPs {
		if err := c.addObjStoreEndpoint(ipOrHost); err != nil {
			log.Warnf("failed to add object store endpoint %s: %v", ipOrHost, err)
		}
	}

	// If no filters provided, use default S3 endpoint (AWS S3)
	if len(config.InitialIPs) == 0 {
		if err := c.addObjStoreEndpoint("s3.amazonaws.com"); err != nil {
			log.Warnf("failed to resolve s3.amazonaws.com: %v", err)
		}
	}

	return c, nil
}

// loadBPF loads the eBPF program from embedded bytecode
func (c *ObjStoreLatencyCollector) loadBPF() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(strings.NewReader(string(objstoreLatencyBPF)))
	if err != nil {
		return fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	c.objs = coll
	return nil
}

// configurePort sets the target port in the eBPF config map
func (c *ObjStoreLatencyCollector) configurePort(port uint16) error {
	configMap := c.objs.Maps["config_map"]
	if configMap == nil {
		return fmt.Errorf("config_map not found in eBPF collection")
	}

	// Config structure matching the C struct
	config := struct {
		TargetPort uint16
		Padding    uint16
	}{
		TargetPort: port,
		Padding:    0,
	}

	// Key is always 0 for the single config entry
	var key uint32 = 0

	if err := configMap.Put(&key, &config); err != nil {
		return fmt.Errorf("failed to set port config: %w", err)
	}

	// Verify the config was written correctly
	var readConfig struct {
		TargetPort uint16
		Padding    uint16
	}
	if err := configMap.Lookup(&key, &readConfig); err != nil {
		log.Warnf("failed to verify config was written: %v", err)
	} else {
		log.Infof("Configured eBPF to track port %d (verified: config map contains port=%d)", port, readConfig.TargetPort)
	}

	return nil
}

// attachKprobes attaches kprobes to tcp_sendmsg and tcp_recvmsg
func (c *ObjStoreLatencyCollector) attachKprobes() error {
	// Verify kernel symbols exist before attempting to attach
	log.Infof("Attempting to attach kprobes to tcp_sendmsg and tcp_recvmsg...")

	// Attach to tcp_sendmsg (outbound)
	sendProg := c.objs.Programs["tcp_sendmsg_entry"]
	if sendProg == nil {
		return fmt.Errorf("tcp_sendmsg_entry program not found")
	}

	log.Infof("Attaching kprobe to tcp_sendmsg...")
	sendLink, err := link.Kprobe("tcp_sendmsg", sendProg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tcp_sendmsg kprobe: %w", err)
	}
	c.sendLink = sendLink
	log.Infof("Successfully attached kprobe to tcp_sendmsg")

	// Attach to tcp_cleanup_rbuf (called after every successful TCP receive,
	// regardless of syscall path: recvmsg, read, splice, io_uring, etc.)
	recvProg := c.objs.Programs["tcp_cleanup_rbuf_entry"]
	if recvProg == nil {
		return fmt.Errorf("tcp_cleanup_rbuf_entry program not found")
	}

	log.Infof("Attaching kprobe to tcp_cleanup_rbuf...")
	recvLink, err := link.Kprobe("tcp_cleanup_rbuf", recvProg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tcp_cleanup_rbuf kprobe: %w", err)
	}
	c.recvLink = recvLink
	log.Infof("Successfully attached kprobe to tcp_cleanup_rbuf")

	// Attach to tcp_retransmit_skb (retransmission counter)
	retransmitProg := c.objs.Programs["tcp_retransmit_entry"]
	if retransmitProg != nil {
		log.Infof("Attaching kprobe to tcp_retransmit_skb for object store...")
		retransmitLink, err := link.Kprobe("tcp_retransmit_skb", retransmitProg, nil)
		if err != nil {
			log.Warnf("failed to attach tcp_retransmit_skb kprobe: %v (retransmit metrics unavailable)", err)
		} else {
			c.retransmitLink = retransmitLink
			log.Infof("Successfully attached tcp_retransmit_skb kprobe for object store")
		}
	}

	log.Infof("All eBPF kprobes attached successfully")
	return nil
}

// addObjStoreEndpoint resolves a hostname and adds its IPs to the endpoint filter map
func (c *ObjStoreLatencyCollector) addObjStoreEndpoint(hostname string) error {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return err
	}

	c.endpointMutex.Lock()
	defer c.endpointMutex.Unlock()

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			// Convert to match eBPF's byte order on little-endian hosts (x86_64)
			// eBPF reads kernel's network byte order into uint32, which reverses bytes on LE
			ipInt := binary.LittleEndian.Uint32(ipv4)
			c.objStoreEndpoints[ipInt] = true
		}
	}

	return nil
}

// Close cleans up eBPF resources
func (c *ObjStoreLatencyCollector) Close() error {
	var errs []error

	if c.sendLink != nil {
		if err := c.sendLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close send link: %w", err))
		}
	}

	if c.recvLink != nil {
		if err := c.recvLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close recv link: %w", err))
		}
	}

	if c.retransmitLink != nil {
		if err := c.retransmitLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close retransmit link: %w", err))
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

// Describe implements prometheus.Collector
func (c *ObjStoreLatencyCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.latencyDesc
	ch <- c.requestsDesc
	ch <- c.retransmitDesc
	ch <- c.bytesSentDesc
	ch <- c.bytesRecvDesc
	ch <- c.latencyHistDesc
}

// refreshFQDNIfNeeded re-resolves the configured FQDN and updates both the
// in-memory endpoint set and the eBPF server IPs map. Uses double-checked
// locking to avoid redundant work (same pattern as NFS refreshMountsIfNeeded).
func (c *ObjStoreLatencyCollector) refreshFQDNIfNeeded() {
	if c.config.FQDN == "" {
		return
	}

	c.refreshMutex.RLock()
	needsRefresh := time.Since(c.lastFQDNRefresh) > c.config.RefreshInterval
	c.refreshMutex.RUnlock()

	if !needsRefresh {
		return
	}

	c.refreshMutex.Lock()
	defer c.refreshMutex.Unlock()

	// Double-check after acquiring write lock
	if time.Since(c.lastFQDNRefresh) <= c.config.RefreshInterval {
		return
	}

	ips, err := net.LookupIP(c.config.FQDN)
	if err != nil {
		log.Warnf("failed to re-resolve FQDN %s: %v", c.config.FQDN, err)
		DNSResolveFailures.WithLabelValues("objectstore").Inc()
		c.lastFQDNRefresh = time.Now()
		return
	}

	// Build new endpoint set
	newEndpoints := make(map[uint32]bool)
	var newFilterIPs []string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipInt := binary.LittleEndian.Uint32(ipv4)
			newEndpoints[ipInt] = true
			newFilterIPs = append(newFilterIPs, ipv4.String())
		}
	}

	if len(newEndpoints) == 0 {
		log.Warnf("FQDN %s re-resolved to 0 IPv4 addresses, keeping previous IPs", c.config.FQDN)
		c.lastFQDNRefresh = time.Now()
		return
	}

	// Swap in-memory endpoint map
	c.endpointMutex.Lock()
	c.objStoreEndpoints = newEndpoints
	c.filterIPs = newFilterIPs
	c.endpointMutex.Unlock()

	// Update eBPF map
	if err := c.updateObjStoreServerIPsMap(); err != nil {
		log.Warnf("failed to update eBPF map after FQDN re-resolution: %v", err)
	}

	c.lastFQDNRefresh = time.Now()
	log.Infof("Re-resolved FQDN %s to %d IPs: %v", c.config.FQDN, len(newFilterIPs), newFilterIPs)
}

// Collect implements prometheus.Collector
func (c *ObjStoreLatencyCollector) Collect(ch chan<- prometheus.Metric) {
	// Periodically re-resolve FQDN for new IPs
	c.refreshFQDNIfNeeded()

	// Get the objstore_latency_by_ip map from the eBPF collection
	latencyMap := c.objs.Maps["objstore_latency_by_ip"]
	if latencyMap == nil {
		log.Errorf("objstore_latency_by_ip map not found in eBPF collection")
		return
	}

	// Iterate over all entries in the map
	var key struct {
		DstIP uint32
		Pad   uint32
	}
	var value struct {
		RequestCount    uint64
		TotalLatency    uint64
		Histogram       [HISTOGRAM_BUCKETS]uint64
		RetransmitCount uint64
		BytesSent       uint64
		BytesRecv       uint64
	}

	totalEntries := 0
	filteredEntries := 0
	iter := latencyMap.Iterate()
	for iter.Next(&key, &value) {
		totalEntries++
		// Filter by configured object store endpoints
		if !c.matchesTargetIP(key.DstIP) {
			if totalEntries <= 10 {
				log.Debugf("Filtered out IP %s (not in target list)", ipUint32ToString(key.DstIP))
			}
			filteredEntries++
			continue
		}

		// Convert IP to string for the label
		ipStr := ipUint32ToString(key.DstIP)

		// Convert nanoseconds to seconds (Prometheus standard)
		latencySeconds := float64(value.TotalLatency) / 1e9

		// Emit metrics
		ch <- prometheus.MustNewConstMetric(
			c.requestsDesc,
			prometheus.CounterValue,
			float64(value.RequestCount),
			ipStr,
		)

		ch <- prometheus.MustNewConstMetric(
			c.latencyDesc,
			prometheus.CounterValue,
			latencySeconds,
			ipStr,
		)

		ch <- prometheus.MustNewConstMetric(
			c.retransmitDesc,
			prometheus.CounterValue,
			float64(value.RetransmitCount),
			ipStr,
		)

		ch <- prometheus.MustNewConstMetric(
			c.bytesSentDesc,
			prometheus.CounterValue,
			float64(value.BytesSent),
			ipStr,
		)

		ch <- prometheus.MustNewConstMetric(
			c.bytesRecvDesc,
			prometheus.CounterValue,
			float64(value.BytesRecv),
			ipStr,
		)

		histBuckets, histCount, histSum := histogramToBuckets(value.Histogram, objstoreHistogramBucketBoundaries)
		ch <- prometheus.MustNewConstHistogram(
			c.latencyHistDesc,
			histCount,
			histSum,
			histBuckets,
			ipStr,
		)
	}

	if err := iter.Err(); err != nil {
		log.Errorf("Error iterating over objstore_latency_by_ip map: %v", err)
	}

	log.Debugf("Object store metrics collection: %d total entries, %d filtered out, %d emitted",
		totalEntries, filteredEntries, totalEntries-filteredEntries)
}

// matchesTargetIP checks if an IP matches any configured object store endpoint
// Supports both individual IPs and CIDR ranges
func (c *ObjStoreLatencyCollector) matchesTargetIP(ip uint32) bool {
	c.endpointMutex.RLock()
	defer c.endpointMutex.RUnlock()

	// Check for exact match first
	if c.objStoreEndpoints[ip] {
		return true
	}

	// TODO: Add CIDR range matching support if needed
	// For now, only exact IP matches are supported

	return false
}

// parseIPFilters parses the filterIPs strings into IP networks
// Used for testing IP filtering logic
func (c *ObjStoreLatencyCollector) parseIPFilters() error {
	c.filterNets = make([]*net.IPNet, 0, len(c.filterIPs))

	for _, ipStr := range c.filterIPs {
		// Check if it's a CIDR notation
		if strings.Contains(ipStr, "/") {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err != nil {
				return fmt.Errorf("invalid CIDR %s: %w", ipStr, err)
			}
			c.filterNets = append(c.filterNets, ipNet)
		} else {
			// Single IP address - convert to /32 CIDR
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", ipStr)
			}
			_, ipNet, _ := net.ParseCIDR(ipStr + "/32")
			c.filterNets = append(c.filterNets, ipNet)
		}
	}

	return nil
}

// matchesIPFilter checks if an IP string matches the configured filters
// Empty filter list matches all IPs
func (c *ObjStoreLatencyCollector) matchesIPFilter(ipStr string) bool {
	// Empty filter matches all
	if len(c.filterNets) == 0 {
		return true
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check if IP matches any filter network
	for _, ipNet := range c.filterNets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// updateObjStoreServerIPsMap updates the eBPF object store server IPs map with real endpoints
func (c *ObjStoreLatencyCollector) updateObjStoreServerIPsMap() error {
	// Get the object store server IPs map from the eBPF program
	serverIPsMap := c.objs.Maps["objstore_server_ips"]
	if serverIPsMap == nil {
		return fmt.Errorf("objstore_server_ips map not found in eBPF collection")
	}

	// Collect unique object store server IPs from the filter list
	uniqueIPs := make(map[string]bool)
	for _, ipOrHost := range c.filterIPs {
		// Resolve hostname to IPs
		ips, err := net.LookupIP(ipOrHost)
		if err != nil {
			log.Warnf("failed to resolve %s: %v", ipOrHost, err)
			continue
		}

		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				uniqueIPs[ipv4.String()] = true
			}
		}
	}

	// If no filter IPs provided, use default S3 endpoints
	if len(uniqueIPs) == 0 {
		// Add some common S3 endpoints as fallback
		defaultEndpoints := []string{"52.216.1.1", "54.231.192.1"} // Sample S3 IPs
		for _, ip := range defaultEndpoints {
			uniqueIPs[ip] = true
		}
	}

	// Populate the eBPF map with object store server IPs
	index := uint32(0)
	for ip := range uniqueIPs {
		// Convert IP string to uint32
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			log.Warnf("invalid IP address %s, skipping", ip)
			continue
		}

		// Convert to IPv4 uint32 (network byte order)
		ipv4 := parsedIP.To4()
		if ipv4 == nil {
			log.Warnf("non-IPv4 address %s, skipping", ip)
			continue
		}

		ipUint32 := binary.LittleEndian.Uint32(ipv4)

		// Update eBPF map
		if err := serverIPsMap.Update(&index, &ipUint32, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to update objstore_server_ips map at index %d with IP %s: %w", index, ip, err)
		}

		log.Infof("Added object store server IP %s to eBPF map at index %d", ip, index)
		index++
	}

	// Zero out remaining slots so the eBPF is_objstore_server() loop stops
	var zero uint32
	for i := index; i < 64; i++ {
		_ = serverIPsMap.Update(&i, &zero, ebpf.UpdateAny)
	}

	log.Infof("Updated eBPF object store server IPs map with %d IPs (cleared %d stale slots)", index, 64-index)
	return nil
}
