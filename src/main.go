package main

import (
	"fmt"
	"metrics-exporter/src/collectors"
	"metrics-exporter/src/log"
	"metrics-exporter/src/nodeutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	registry := prometheus.NewRegistry()

	port := os.Getenv("PORT")
	if port == "" {
		port = "9500"
	}

	// HOST_PROC_PATH is the root of the host's /proc filesystem.
	// In containers it is typically /host/proc (mounted from the host).
	// On bare metal it is just /proc.
	hostProcPath := os.Getenv("HOST_PROC_PATH")
	if hostProcPath == "" {
		if _, err := os.Stat("/host/proc/1/mounts"); err == nil {
			hostProcPath = "/host/proc"
		} else {
			hostProcPath = "/proc"
		}
	}
	log.Infof("Host proc path: %s", hostProcPath)

	// Disk I/O latency collector (eBPF-based with histograms and percentiles)
	diskLatencyCollector, err := collectors.NewDiskLatencyCollector()
	if err != nil {
		log.Errorf("Failed to create disk latency collector: %v (continuing without disk metrics)", err)
	} else {
		registry.MustRegister(diskLatencyCollector)
		defer diskLatencyCollector.Close()
		log.Infof("eBPF disk latency collector enabled")
	}

	// NFS latency collector (eBPF-based with volume ID resolution)
	nfsServerIPs := []string{}
	if ipsStr := os.Getenv("NFS_SERVER_IPS"); ipsStr != "" {
		for _, ip := range strings.Split(ipsStr, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				nfsServerIPs = append(nfsServerIPs, ip)
			}
		}
	}

	protocols := []string{"tcp", "udp"}
	if protosStr := os.Getenv("NFS_PROTOCOLS"); protosStr != "" {
		protocols = []string{}
		for _, proto := range strings.Split(protosStr, ",") {
			proto = strings.TrimSpace(strings.ToLower(proto))
			if proto == "tcp" || proto == "udp" {
				protocols = append(protocols, proto)
			}
		}
		if len(protocols) == 0 {
			protocols = []string{"tcp", "udp"}
		}
	}

	targetPorts := []uint16{2049}
	if portsStr := os.Getenv("NFS_TARGET_PORTS"); portsStr != "" {
		targetPorts = []uint16{}
		for _, portStr := range strings.Split(portsStr, ",") {
			if port, err := strconv.ParseUint(strings.TrimSpace(portStr), 10, 16); err == nil {
				targetPorts = append(targetPorts, uint16(port))
			}
		}
		if len(targetPorts) == 0 {
			targetPorts = []uint16{2049}
		}
	}

	mountRefreshInterval := 5 * time.Minute
	if intervalStr := os.Getenv("NFS_MOUNT_REFRESH_INTERVAL"); intervalStr != "" {
		if interval, err := time.ParseDuration(intervalStr); err == nil {
			mountRefreshInterval = interval
		}
	}

	enableVolumeID := os.Getenv("NFS_ENABLE_VOLUME_ID") != "false"

	hostMountsPath := hostProcPath + "/1/mounts"

	nfsConfig := collectors.NFSConfig{
		ServerIPs:            nfsServerIPs,
		Protocols:            protocols,
		TargetPorts:          targetPorts,
		EnableVolumeID:       enableVolumeID,
		MountRefreshInterval: mountRefreshInterval,
		HostMountsPath:       hostMountsPath,
	}

	nfsCollector, err := collectors.NewNFSLatencyCollector(nfsConfig)
	if err != nil {
		log.Errorf("Failed to create NFS latency collector: %v (continuing without NFS metrics)", err)
	} else {
		registry.MustRegister(nfsCollector)
		defer nfsCollector.Close()
		log.Infof("NFS latency collector enabled - protocols: %v, ports: %v, volume_id: %v",
			protocols, targetPorts, enableVolumeID)
	}

	// NFS stats collector (mountstats-based: RPC counts, RTT, exe time, backlog)
	mountStatsPath := os.Getenv("MOUNTSTATS_PATH")
	if mountStatsPath == "" {
		mountStatsPath = hostProcPath + "/1/mountstats"
	}
	nfsStatsCollector := collectors.NewNFSStatsCollector(mountStatsPath)
	registry.MustRegister(nfsStatsCollector)
	log.Infof("NFS stats collector enabled (mountstats: %s)", mountStatsPath)

	// NFS xprt collector (per-nconnect-lane metrics from mountstats:
	// sends, recvs, connect_count, bad_xids, max_slots, idle_seconds,
	// backlog_utilization per xprt_idx). Complements the per-volume
	// aggregate metrics above by exposing the same /proc/self/mountstats
	// data at lane granularity — needed for "how many of N nconnect
	// lanes are alive" diagnostics.
	nfsXprtCollector := collectors.NewNFSXprtCollector(mountStatsPath)
	registry.MustRegister(nfsXprtCollector)
	log.Infof("NFS xprt collector enabled (mountstats: %s)", mountStatsPath)

	// NFS mount-events collector (per-mount kernel events, byte counters,
	// and mount age from mountstats events:/bytes:/age: lines). Adds
	// per-mount diagnostic signals (delay events, congestion_wait,
	// direct/server bytes) that aren't visible in the per-op aggregate
	// or per-xprt views.
	nfsMountEventsCollector := collectors.NewNFSMountEventsCollector(mountStatsPath)
	registry.MustRegister(nfsMountEventsCollector)
	log.Infof("NFS mount-events collector enabled (mountstats: %s)", mountStatsPath)

	// Disk usage collector (bytes used, inodes used per vd* device)
	diskUsageCollector := collectors.NewDiskUsageCollector(hostMountsPath, hostProcPath+"/1/root")
	registry.MustRegister(diskUsageCollector)
	log.Infof("Disk usage collector enabled (mounts: %s)", hostMountsPath)

	// NVMe controller collector — passthrough drives only; one-shot probe at
	// startup decides whether to register (no passthrough → silent skip).
	nvmeCollector := collectors.NewNVMeCollector()
	if ok, reason := nvmeCollector.Probe(); ok {
		registry.MustRegister(nvmeCollector)
		log.Infof("NVMe controller collector enabled")
	} else {
		log.Infof("NVMe controller collector disabled: %s", reason)
	}

	// Object store latency collector (eBPF-based)
	//
	// FQDN resolution order:
	//  1. Explicit OBJSTORE_ENDPOINT_FQDN env var (operator override).
	//  2. Derive from NODE_NAME: extract region from the Crusoe node name
	//     (e.g. "np-88fe80e2-1.us-west1-a.compute.internal" → "us-west1-a")
	//     and construct "object.<region>.crusoecloudcompute.com".
	//  3. Legacy OBJSTORE_ENDPOINT_IPS (comma-separated IPs, no re-resolution).
	//  4. Skip object store probes.
	objStoreIPs := []string{}
	objStoreFQDN := ""
	if fqdn := os.Getenv("OBJSTORE_ENDPOINT_FQDN"); fqdn != "" {
		fqdn = strings.TrimSpace(fqdn)
		objStoreFQDN = fqdn
		resolved, err := resolveObjStoreFQDN(fqdn)
		if err != nil {
			log.Errorf("Failed to resolve OBJSTORE_ENDPOINT_FQDN=%q: %v", fqdn, err)
		} else {
			objStoreIPs = resolved
			log.Infof("Resolved OBJSTORE_ENDPOINT_FQDN=%q to %d IPs: %v", fqdn, len(resolved), resolved)
		}
	} else if region, err := nodeutil.RegionFromNodeName(os.Getenv("NODE_NAME")); err == nil {
		fqdn := nodeutil.ObjStoreEndpoint(region)
		objStoreFQDN = fqdn
		resolved, err := resolveObjStoreFQDN(fqdn)
		if err != nil {
			log.Errorf("Derived OBJSTORE_ENDPOINT_FQDN=%q from NODE_NAME but DNS resolution failed: %v", fqdn, err)
		} else {
			objStoreIPs = resolved
			log.Infof("Derived OBJSTORE_ENDPOINT_FQDN=%q from NODE_NAME, resolved to %d IPs: %v", fqdn, len(resolved), resolved)
		}
	} else if ipsStr := os.Getenv("OBJSTORE_ENDPOINT_IPS"); ipsStr != "" {
		for _, ip := range strings.Split(ipsStr, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				objStoreIPs = append(objStoreIPs, ip)
			}
		}
	} else {
		log.Warnf("OBJSTORE_ENDPOINT_FQDN not set and could not derive region from NODE_NAME: %v; skipping objectstore probes", err)
	}

	var objStorePorts []uint16
	if portStr := os.Getenv("OBJSTORE_ENDPOINT_PORT"); portStr != "" {
		for _, ps := range strings.Split(portStr, ",") {
			ps = strings.TrimSpace(ps)
			if port, err := strconv.ParseUint(ps, 10, 16); err == nil {
				objStorePorts = append(objStorePorts, uint16(port))
			} else {
				log.Warnf("Invalid port '%s' in OBJSTORE_ENDPOINT_PORT, skipping", ps)
			}
		}
	}
	// Default [443, 80] is applied inside NewObjStoreLatencyCollector if empty.

	if len(objStoreIPs) > 0 {
		objStoreConfig := collectors.ObjStoreConfig{
			InitialIPs:  objStoreIPs,
			FQDN:        objStoreFQDN,
			TargetPorts: objStorePorts,
		}

		objStoreCollector, err := collectors.NewObjStoreLatencyCollector(objStoreConfig)
		if err != nil {
			log.Errorf("Failed to create object store latency collector: %v (continuing without object store metrics)", err)
		} else {
			registry.MustRegister(objStoreCollector)
			defer objStoreCollector.Close()
			log.Infof("Object store latency collector enabled for IPs: %v, ports: %v, fqdn: %q", objStoreIPs, objStorePorts, objStoreFQDN)
		}
	}

	// Health probe collector (ICMP ping, NFS RPC, HTTPS probes)
	probeInterval := 5 * time.Minute
	if intervalStr := os.Getenv("PROBE_INTERVAL"); intervalStr != "" {
		if d, err := time.ParseDuration(intervalStr); err == nil && d > 0 {
			probeInterval = d
		} else {
			log.Warnf("Invalid PROBE_INTERVAL '%s', using default 5m", intervalStr)
		}
	}

	probeConfig := collectors.ProbeConfig{
		ObjStoreFQDN:   objStoreFQDN,
		HostMountsPath: hostMountsPath,
		ProbeInterval:  probeInterval,
		MaxJitter:      30 * time.Second,
	}
	probeCollector := collectors.NewProbeCollector(probeConfig)
	registry.MustRegister(probeCollector)
	defer probeCollector.Close()
	log.Infof("Health probe collector enabled (objstore_fqdn: %q, mounts: %s)", objStoreFQDN, hostMountsPath)

	// Register shared DNS metrics
	registry.MustRegister(collectors.DNSResolveTotal)
	registry.MustRegister(collectors.DNSResolveSuccesses)
	registry.MustRegister(collectors.DNSResolveFailures)
	registry.MustRegister(collectors.DNSResolveLatency)

	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	log.Infof("Starting metrics exporter on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// resolveObjStoreFQDN resolves an FQDN to its IPv4 addresses via DNS.
// It returns an error if the hostname cannot be resolved or yields no IPv4 addresses.
func resolveObjStoreFQDN(fqdn string) ([]string, error) {
	ips, err := collectors.LookupIP(fqdn, "objectstore")
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", fqdn, err)
	}

	var ipv4s []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			ipv4s = append(ipv4s, v4.String())
		}
	}

	if len(ipv4s) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses found for %s", fqdn)
	}

	return ipv4s, nil
}
