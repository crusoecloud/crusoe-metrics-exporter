package collectors

import (
	"bufio"
	"math/rand"
	"metrics-exporter/src/log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ProbeConfig holds configuration for the health probe collector.
type ProbeConfig struct {
	ObjStoreFQDN   string        // FQDN of the object store endpoint
	HostMountsPath string        // Path to host mounts file for NFS IP discovery
	ProbeInterval  time.Duration // How often to run probes (default 5m)
	MaxJitter      time.Duration // Maximum random jitter before probing (0 = no jitter)
	ProbeTimeout   time.Duration // Timeout for individual probes (default 10s)
}

// ProbeCollector implements prometheus.Collector for health probe metrics.
type ProbeCollector struct {
	config ProbeConfig

	nfsPingDesc       *prometheus.Desc
	nfsRPCDesc        *prometheus.Desc
	objStorePingDesc  *prometheus.Desc
	objStoreHTTPDesc  *prometheus.Desc

	mu                sync.RWMutex
	pingResults       []probeResult
	rpcResults        []probeResult
	objStorePingResults []probeResult
	httpsResults      []probeResult

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewProbeCollector creates a ProbeCollector and starts its background probe loop.
func NewProbeCollector(config ProbeConfig) *ProbeCollector {
	if config.ProbeInterval == 0 {
		config.ProbeInterval = 5 * time.Minute
	}
	// MaxJitter is not defaulted here — 0 means no jitter.
	// Callers should set it explicitly (e.g. 30s for production).
	if config.ProbeTimeout == 0 {
		config.ProbeTimeout = 10 * time.Second
	}

	p := &ProbeCollector{
		config: config,
		nfsPingDesc: prometheus.NewDesc(
			MetricPrefix+"nfs_ping_latency_seconds",
			"ICMP ping RTT to NFS server in seconds (0 if probe failed)",
			[]string{"endpoint"},
			nil,
		),
		nfsRPCDesc: prometheus.NewDesc(
			MetricPrefix+"nfs_rpc_probe_latency_seconds",
			"NFSv4 NULL RPC probe latency in seconds (0 if probe failed)",
			[]string{"endpoint"},
			nil,
		),
		objStorePingDesc: prometheus.NewDesc(
			MetricPrefix+"objectstore_ping_latency_seconds",
			"ICMP ping RTT to object store server in seconds (0 if probe failed)",
			[]string{"endpoint"},
			nil,
		),
		objStoreHTTPDesc: prometheus.NewDesc(
			MetricPrefix+"objectstore_https_probe_latency_seconds",
			"HTTPS probe latency to object store in seconds (0 if probe failed)",
			[]string{"endpoint"},
			nil,
		),
		stopCh: make(chan struct{}),
	}

	p.wg.Add(1)
	go p.probeLoop()

	return p
}

// Describe implements prometheus.Collector.
func (p *ProbeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- p.nfsPingDesc
	ch <- p.nfsRPCDesc
	ch <- p.objStorePingDesc
	ch <- p.objStoreHTTPDesc
}

// Collect implements prometheus.Collector.
func (p *ProbeCollector) Collect(ch chan<- prometheus.Metric) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, r := range p.pingResults {
		val := 0.0
		if r.Success {
			val = r.Latency.Seconds()
		}
		ch <- prometheus.MustNewConstMetric(p.nfsPingDesc, prometheus.GaugeValue, val, r.IP)
	}

	for _, r := range p.rpcResults {
		val := 0.0
		if r.Success {
			val = r.Latency.Seconds()
		}
		ch <- prometheus.MustNewConstMetric(p.nfsRPCDesc, prometheus.GaugeValue, val, r.IP)
	}

	for _, r := range p.objStorePingResults {
		val := 0.0
		if r.Success {
			val = r.Latency.Seconds()
		}
		ch <- prometheus.MustNewConstMetric(p.objStorePingDesc, prometheus.GaugeValue, val, r.IP)
	}

	for _, r := range p.httpsResults {
		val := 0.0
		if r.Success {
			val = r.Latency.Seconds()
		}
		ch <- prometheus.MustNewConstMetric(p.objStoreHTTPDesc, prometheus.GaugeValue, val, r.IP)
	}
}

// Close stops the background probe loop and waits for it to finish.
func (p *ProbeCollector) Close() {
	close(p.stopCh)
	p.wg.Wait()
}

// probeLoop is the background goroutine that runs probes on a timer.
func (p *ProbeCollector) probeLoop() {
	defer p.wg.Done()

	// Run probes once at startup (with jitter)
	select {
	case <-p.stopCh:
		return
	case <-time.After(jitter(p.config.MaxJitter)):
		p.runProbes()
	}

	ticker := time.NewTicker(p.config.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			// Add jitter before probing
			select {
			case <-p.stopCh:
				return
			case <-time.After(jitter(p.config.MaxJitter)):
			}
			p.runProbes()
		}
	}
}

// jitter returns a random duration between 0 and max.
func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(max)))
}

// runProbes discovers IPs and runs all probes in parallel.
func (p *ProbeCollector) runProbes() {
	// Discover NFS IPs from mounts
	nfsIPs := p.discoverNFSIPs()

	// Resolve ObjStore IPs
	objStoreIPs := p.resolveObjStoreIPs()

	log.Infof("Running health probes: %d NFS IPs, %d ObjStore IPs", len(nfsIPs), len(objStoreIPs))

	var wg sync.WaitGroup

	// ICMP ping probes for NFS IPs
	pingResults := make([]probeResult, len(nfsIPs))
	for i, ip := range nfsIPs {
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			pingResults[idx] = p.probeICMPPing(target)
		}(i, ip)
	}

	// NFS RPC probes for NFS IPs
	rpcResults := make([]probeResult, len(nfsIPs))
	for i, ip := range nfsIPs {
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			rpcResults[idx] = p.probeNFSv4NULL(target)
		}(i, ip)
	}

	// ICMP ping probes for ObjStore IPs
	objStorePingResults := make([]probeResult, len(objStoreIPs))
	for i, ip := range objStoreIPs {
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			objStorePingResults[idx] = p.probeICMPPing(target)
		}(i, ip)
	}

	// HTTPS probes for ObjStore IPs
	httpsResults := make([]probeResult, len(objStoreIPs))
	for i, ip := range objStoreIPs {
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			httpsResults[idx] = p.probeHTTPS(target)
		}(i, ip)
	}

	wg.Wait()

	// Log results
	for _, r := range pingResults {
		if r.Success {
			log.Debugf("ICMP ping %s: %.3fms", r.IP, float64(r.Latency.Microseconds())/1000.0)
		} else {
			log.Debugf("ICMP ping %s: failed", r.IP)
		}
	}
	for _, r := range rpcResults {
		if r.Success {
			log.Debugf("NFS RPC %s: %.3fms", r.IP, float64(r.Latency.Microseconds())/1000.0)
		} else {
			log.Debugf("NFS RPC %s: failed", r.IP)
		}
	}
	for _, r := range objStorePingResults {
		if r.Success {
			log.Debugf("ObjStore ICMP ping %s: %.3fms", r.IP, float64(r.Latency.Microseconds())/1000.0)
		} else {
			log.Debugf("ObjStore ICMP ping %s: failed", r.IP)
		}
	}
	for _, r := range httpsResults {
		if r.Success {
			log.Debugf("HTTPS %s: %.3fms", r.IP, float64(r.Latency.Microseconds())/1000.0)
		} else {
			log.Debugf("HTTPS %s: failed", r.IP)
		}
	}

	// Atomically swap results under write lock
	p.mu.Lock()
	p.pingResults = pingResults
	p.rpcResults = rpcResults
	p.objStorePingResults = objStorePingResults
	p.httpsResults = httpsResults
	p.mu.Unlock()
}

// discoverNFSIPs scans the host mounts file for NFS/NFS4 mount entries
// and returns their server IPs.
func (p *ProbeCollector) discoverNFSIPs() []string {
	if p.config.HostMountsPath == "" {
		return nil
	}

	file, err := os.Open(p.config.HostMountsPath)
	if err != nil {
		log.Debugf("Cannot read %s for NFS IP discovery: %v", p.config.HostMountsPath, err)
		return nil
	}
	defer file.Close()

	seen := make(map[string]bool)
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

		// Extract IP from addr= mount option
		if len(fields) >= 6 {
			optionsString := strings.Join(fields[3:], " ")
			for _, opt := range strings.Split(optionsString, ",") {
				opt = strings.TrimSpace(opt)
				if strings.HasPrefix(opt, "addr=") {
					ip := strings.TrimPrefix(opt, "addr=")
					if net.ParseIP(ip) != nil && !seen[ip] {
						seen[ip] = true
					}
				}
			}
		}

		// Fallback: extract from server:/path
		serverPath := fields[0]
		colonIdx := strings.Index(serverPath, ":")
		if colonIdx > 0 {
			serverPart := serverPath[:colonIdx]
			if net.ParseIP(serverPart) != nil && !seen[serverPart] {
				seen[serverPart] = true
			}
		}
	}

	ips := make([]string, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	return ips
}

// resolveObjStoreIPs resolves the configured object store FQDN to IPv4 addresses.
func (p *ProbeCollector) resolveObjStoreIPs() []string {
	if p.config.ObjStoreFQDN == "" {
		return nil
	}

	ips, err := net.LookupIP(p.config.ObjStoreFQDN)
	if err != nil {
		log.Warnf("Failed to resolve ObjStore FQDN %s for probing: %v", p.config.ObjStoreFQDN, err)
		DNSResolveFailures.WithLabelValues("objectstore").Inc()
		return nil
	}

	var ipv4s []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			ipv4s = append(ipv4s, v4.String())
		}
	}
	return ipv4s
}
