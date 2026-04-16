package main

import (
	"fmt"
	"metrics-exporter/src/collectors"
	"metrics-exporter/src/log"
	"net"
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

	// Object store latency collector (eBPF-based)
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
	} else if ipsStr := os.Getenv("OBJSTORE_ENDPOINT_IPS"); ipsStr != "" {
		for _, ip := range strings.Split(ipsStr, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				objStoreIPs = append(objStoreIPs, ip)
			}
		}
	}

	objStorePort := uint16(443)
	if portStr := os.Getenv("OBJSTORE_ENDPOINT_PORT"); portStr != "" {
		if port, err := strconv.ParseUint(portStr, 10, 16); err == nil {
			objStorePort = uint16(port)
		} else {
			log.Warnf("Invalid OBJSTORE_ENDPOINT_PORT '%s', using default 443", portStr)
		}
	}

	if len(objStoreIPs) > 0 {
		objStoreConfig := collectors.ObjStoreConfig{
			InitialIPs:      objStoreIPs,
			FQDN:            objStoreFQDN,
			TargetPort:      objStorePort,
		}

		objStoreCollector, err := collectors.NewObjStoreLatencyCollector(objStoreConfig)
		if err != nil {
			log.Errorf("Failed to create object store latency collector: %v (continuing without object store metrics)", err)
		} else {
			registry.MustRegister(objStoreCollector)
			defer objStoreCollector.Close()
			log.Infof("Object store latency collector enabled for IPs: %v, port: %d, fqdn: %q", objStoreIPs, objStorePort, objStoreFQDN)
		}
	}

	// Health probe collector (ICMP ping, NFS RPC, HTTPS probes)
	probeConfig := collectors.ProbeConfig{
		ObjStoreFQDN:   objStoreFQDN,
		HostMountsPath: hostMountsPath,
	}
	probeCollector := collectors.NewProbeCollector(probeConfig)
	registry.MustRegister(probeCollector)
	defer probeCollector.Close()
	log.Infof("Health probe collector enabled (objstore_fqdn: %q, mounts: %s)", objStoreFQDN, hostMountsPath)

	// Register shared DNS failure counter
	registry.MustRegister(collectors.DNSResolveFailures)

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
	ips, err := net.LookupIP(fqdn)
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
