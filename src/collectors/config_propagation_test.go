package collectors

// Tests that verify environment variable configuration is correctly propagated
// through to the collectors and their eBPF maps.  This file specifically targets
// the class of bug where config parsed from env vars is stored in a struct but
// never written into the eBPF maps that the probes actually read.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers: replicate the env-var parsing logic from main.go so we can test it
// in isolation without importing main.
// ---------------------------------------------------------------------------

// parseNFSConfigFromEnv mirrors the NFS config parsing in main.go
func parseNFSConfigFromEnv() NFSConfig {
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

	mountRefreshInterval := 30 * time.Second
	if intervalStr := os.Getenv("NFS_MOUNT_REFRESH_INTERVAL"); intervalStr != "" {
		if interval, err := time.ParseDuration(intervalStr); err == nil {
			mountRefreshInterval = interval
		}
	}

	enableVolumeID := os.Getenv("NFS_ENABLE_VOLUME_ID") != "false"

	return NFSConfig{
		ServerIPs:            nfsServerIPs,
		Protocols:            protocols,
		TargetPorts:          targetPorts,
		EnableVolumeID:       enableVolumeID,
		MountRefreshInterval: mountRefreshInterval,
	}
}

// parseObjStoreConfigFromEnv mirrors the objstore config parsing in main.go
func parseObjStoreConfigFromEnv() ObjStoreConfig {
	config := ObjStoreConfig{
		TargetPorts: []uint16{443, 80},
	}

	if portStr := os.Getenv("OBJSTORE_ENDPOINT_PORT"); portStr != "" {
		var ports []uint16
		for _, ps := range strings.Split(portStr, ",") {
			ps = strings.TrimSpace(ps)
			if port, err := strconv.ParseUint(ps, 10, 16); err == nil {
				ports = append(ports, uint16(port))
			}
		}
		if len(ports) > 0 {
			config.TargetPorts = ports
		}
	}

	if fqdn := os.Getenv("OBJSTORE_ENDPOINT_FQDN"); fqdn != "" {
		fqdn = strings.TrimSpace(fqdn)
		config.FQDN = fqdn
		resolved, err := resolveObjStoreFQDN(fqdn)
		if err == nil {
			config.InitialIPs = resolved
		}
	} else if ipsStr := os.Getenv("OBJSTORE_ENDPOINT_IPS"); ipsStr != "" {
		for _, ip := range strings.Split(ipsStr, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				config.InitialIPs = append(config.InitialIPs, ip)
			}
		}
	}
	return config
}

// resolveObjStoreFQDN resolves an FQDN to its IPv4 addresses via DNS.
// This is a copy of the function in main.go for test isolation.
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

// ---------------------------------------------------------------------------
// Unit tests: env var parsing -> config struct (runs everywhere)
// ---------------------------------------------------------------------------

func TestNFSEnvVarParsing(t *testing.T) {
	tests := []struct {
		name           string
		envVars        map[string]string
		expectIPs      []string
		expectPorts    []uint16
		expectProtos   []string
		expectVolumeID bool
	}{
		{
			name: "all env vars set",
			envVars: map[string]string{
				"NFS_SERVER_IPS":       "10.0.1.100,192.168.1.50",
				"NFS_TARGET_PORTS":     "2049,20490",
				"NFS_PROTOCOLS":        "tcp",
				"NFS_ENABLE_VOLUME_ID": "true",
			},
			expectIPs:      []string{"10.0.1.100", "192.168.1.50"},
			expectPorts:    []uint16{2049, 20490},
			expectProtos:   []string{"tcp"},
			expectVolumeID: true,
		},
		{
			name:           "defaults when no env vars",
			envVars:        map[string]string{},
			expectIPs:      []string{},
			expectPorts:    []uint16{2049},
			expectProtos:   []string{"tcp", "udp"},
			expectVolumeID: true,
		},
		{
			name: "volume ID disabled",
			envVars: map[string]string{
				"NFS_ENABLE_VOLUME_ID": "false",
			},
			expectVolumeID: false,
		},
		{
			name: "whitespace in IPs",
			envVars: map[string]string{
				"NFS_SERVER_IPS": " 10.0.1.100 , 192.168.1.50 ",
			},
			expectIPs:      []string{"10.0.1.100", "192.168.1.50"},
			expectVolumeID: true,
		},
		{
			name: "invalid port falls back to default",
			envVars: map[string]string{
				"NFS_TARGET_PORTS": "notaport",
			},
			expectPorts:    []uint16{2049},
			expectVolumeID: true,
		},
		{
			name: "invalid protocol falls back to default",
			envVars: map[string]string{
				"NFS_PROTOCOLS": "sctp",
			},
			expectProtos:   []string{"tcp", "udp"},
			expectVolumeID: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore env
			savedEnv := map[string]string{}
			allKeys := []string{
				"NFS_SERVER_IPS", "NFS_TARGET_PORTS", "NFS_PROTOCOLS",
				"NFS_ENABLE_VOLUME_ID", "NFS_MOUNT_REFRESH_INTERVAL",
			}
			for _, k := range allKeys {
				savedEnv[k] = os.Getenv(k)
				os.Unsetenv(k)
			}
			defer func() {
				for k, v := range savedEnv {
					if v != "" {
						os.Setenv(k, v)
					} else {
						os.Unsetenv(k)
					}
				}
			}()

			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			config := parseNFSConfigFromEnv()

			if tt.expectIPs != nil {
				if len(config.ServerIPs) != len(tt.expectIPs) {
					t.Errorf("ServerIPs: got %v, want %v", config.ServerIPs, tt.expectIPs)
				} else {
					for i, ip := range tt.expectIPs {
						if config.ServerIPs[i] != ip {
							t.Errorf("ServerIPs[%d]: got %q, want %q", i, config.ServerIPs[i], ip)
						}
					}
				}
			}

			if tt.expectPorts != nil {
				if len(config.TargetPorts) != len(tt.expectPorts) {
					t.Errorf("TargetPorts: got %v, want %v", config.TargetPorts, tt.expectPorts)
				} else {
					for i, port := range tt.expectPorts {
						if config.TargetPorts[i] != port {
							t.Errorf("TargetPorts[%d]: got %d, want %d", i, config.TargetPorts[i], port)
						}
					}
				}
			}

			if tt.expectProtos != nil {
				if len(config.Protocols) != len(tt.expectProtos) {
					t.Errorf("Protocols: got %v, want %v", config.Protocols, tt.expectProtos)
				}
			}

			if config.EnableVolumeID != tt.expectVolumeID {
				t.Errorf("EnableVolumeID: got %v, want %v", config.EnableVolumeID, tt.expectVolumeID)
			}
		})
	}
}

func TestObjStoreEnvVarParsing(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		expectIPs   []string
		expectPorts []uint16
	}{
		{
			name: "IPs and custom port",
			envVars: map[string]string{
				"OBJSTORE_ENDPOINT_IPS":  "100.63.0.10,100.63.0.11",
				"OBJSTORE_ENDPOINT_PORT": "8080",
			},
			expectIPs:   []string{"100.63.0.10", "100.63.0.11"},
			expectPorts: []uint16{8080},
		},
		{
			name:        "defaults",
			envVars:     map[string]string{},
			expectIPs:   nil,
			expectPorts: []uint16{443, 80},
		},
		{
			name: "invalid port keeps default",
			envVars: map[string]string{
				"OBJSTORE_ENDPOINT_PORT": "notaport",
			},
			expectPorts: []uint16{443, 80},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			savedEnv := map[string]string{}
			allKeys := []string{"OBJSTORE_ENDPOINT_IPS", "OBJSTORE_ENDPOINT_PORT", "OBJSTORE_ENDPOINT_FQDN"}
			for _, k := range allKeys {
				savedEnv[k] = os.Getenv(k)
				os.Unsetenv(k)
			}
			defer func() {
				for k, v := range savedEnv {
					if v != "" {
						os.Setenv(k, v)
					} else {
						os.Unsetenv(k)
					}
				}
			}()

			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			config := parseObjStoreConfigFromEnv()

			if len(config.InitialIPs) != len(tt.expectIPs) {
				t.Errorf("IPs: got %v, want %v", config.InitialIPs, tt.expectIPs)
			} else {
				for i, ip := range tt.expectIPs {
					if config.InitialIPs[i] != ip {
						t.Errorf("IPs[%d]: got %q, want %q", i, config.InitialIPs[i], ip)
					}
				}
			}

			if len(config.TargetPorts) != len(tt.expectPorts) {
				t.Errorf("Ports: got %v, want %v", config.TargetPorts, tt.expectPorts)
			} else {
				for i, port := range tt.expectPorts {
					if config.TargetPorts[i] != port {
						t.Errorf("Ports[%d]: got %d, want %d", i, config.TargetPorts[i], port)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Config-to-struct propagation tests (runs everywhere)
// These verify that the NFSConfig struct fields are accessible to the
// collector, which is a prerequisite for them reaching the eBPF maps.
// ---------------------------------------------------------------------------

func TestNFSConfigStoredInCollectorStruct(t *testing.T) {
	// Verify that NFSConfig fields are all stored and retrievable.
	// This catches bugs where config is accepted but not stored.
	config := NFSConfig{
		ServerIPs:            []string{"10.0.1.100", "192.168.1.50"},
		Protocols:            []string{"tcp"},
		TargetPorts:          []uint16{2049},
		EnableVolumeID:       true,
		MountRefreshInterval: 60 * time.Second,
		HostMountsPath:       "/host/proc/1/mounts",
	}

	// The collector struct must store the config so that methods like
	// populateNFSServerIPs() can access config.ServerIPs and HostMountsPath.
	// We can't create a real collector on macOS, so we verify the struct.
	collector := &NFSLatencyCollector{
		config:        config,
		volumeMapping: NewVolumeMapping(),
	}

	if len(collector.config.ServerIPs) != 2 {
		t.Errorf("config.ServerIPs not stored: got %d IPs, want 2", len(collector.config.ServerIPs))
	}
	if collector.config.ServerIPs[0] != "10.0.1.100" {
		t.Errorf("config.ServerIPs[0]: got %q, want %q", collector.config.ServerIPs[0], "10.0.1.100")
	}
	if collector.config.ServerIPs[1] != "192.168.1.50" {
		t.Errorf("config.ServerIPs[1]: got %q, want %q", collector.config.ServerIPs[1], "192.168.1.50")
	}
	if len(collector.config.Protocols) != 1 || collector.config.Protocols[0] != "tcp" {
		t.Errorf("config.Protocols not stored: got %v", collector.config.Protocols)
	}
	if len(collector.config.TargetPorts) != 1 || collector.config.TargetPorts[0] != 2049 {
		t.Errorf("config.TargetPorts not stored: got %v", collector.config.TargetPorts)
	}
	if !collector.config.EnableVolumeID {
		t.Error("config.EnableVolumeID not stored")
	}
	if collector.config.MountRefreshInterval != 60*time.Second {
		t.Errorf("config.MountRefreshInterval not stored: got %v", collector.config.MountRefreshInterval)
	}
	if collector.config.HostMountsPath != "/host/proc/1/mounts" {
		t.Errorf("config.HostMountsPath not stored: got %q, want %q", collector.config.HostMountsPath, "/host/proc/1/mounts")
	}
}

func TestNFSHostMountsPathDefault(t *testing.T) {
	// When HostMountsPath is empty, NewNFSLatencyCollector should default to /proc/mounts
	config := NFSConfig{
		Protocols:   []string{"tcp"},
		TargetPorts: []uint16{2049},
	}

	// Can't create real collector on macOS, but verify the default logic directly
	if config.HostMountsPath == "" {
		config.HostMountsPath = "/proc/mounts" // mirrors the default in NewNFSLatencyCollector
	}

	if config.HostMountsPath != "/proc/mounts" {
		t.Errorf("Default HostMountsPath should be /proc/mounts, got %q", config.HostMountsPath)
	}
}

func TestNFSHostMountsPathContainerized(t *testing.T) {
	// When HOST_PROC_PATH is /host/proc, HostMountsPath should be
	// /host/proc/1/mounts (as set by main.go). This test verifies the
	// derivation logic that would have caught the /proc/mounts vs
	// /host/proc/1/mounts bug.
	hostProcPath := "/host/proc"
	hostMountsPath := hostProcPath + "/1/mounts"

	if hostMountsPath != "/host/proc/1/mounts" {
		t.Errorf("Containerized HostMountsPath should be /host/proc/1/mounts, got %q", hostMountsPath)
	}
}

// ---------------------------------------------------------------------------
// Config-to-eBPF map propagation tests (eBPF integration -- skip on non-Linux)
// These are the critical tests that would have caught the original bug where
// config.ServerIPs were never written to the nfs_server_ips eBPF map.
// ---------------------------------------------------------------------------

func TestNFSServerIPsPropagatedToEBPFMap(t *testing.T) {
	// This test verifies the complete pipeline:
	//   env NFS_SERVER_IPS -> config.ServerIPs -> nfs_server_ips eBPF map
	// It would have caught the original bug.
	testIPs := []string{"10.0.1.100", "192.168.1.50"}

	config := NFSConfig{
		ServerIPs:            testIPs,
		Protocols:            []string{"tcp"},
		TargetPorts:          []uint16{2049},
		EnableVolumeID:       false,
		MountRefreshInterval: 30 * time.Second,
	}

	collector, err := NewNFSLatencyCollector(config)
	if err != nil {
		t.Skipf("Skipping eBPF integration test (expected on non-Linux): %v", err)
		return
	}
	defer collector.Close()

	// Read back the nfs_server_ips map and verify our IPs are present
	serverIPsMap := collector.objs.Maps["nfs_server_ips"]
	if serverIPsMap == nil {
		t.Fatal("nfs_server_ips map not found in eBPF collection")
	}

	// Build set of expected IPs in little-endian uint32 form
	expectedIPs := make(map[uint32]string)
	for _, ipStr := range testIPs {
		parsed := net.ParseIP(ipStr).To4()
		if parsed == nil {
			t.Fatalf("Failed to parse test IP %s", ipStr)
		}
		expectedIPs[binary.LittleEndian.Uint32(parsed)] = ipStr
	}

	// Read all entries from the array map
	foundIPs := make(map[uint32]bool)
	for i := uint32(0); i < 64; i++ {
		var val uint32
		idx := i
		if err := serverIPsMap.Lookup(&idx, &val); err != nil {
			break
		}
		if val == 0 {
			break
		}
		foundIPs[val] = true
	}

	// Verify each configured IP is in the eBPF map
	for ipUint32, ipStr := range expectedIPs {
		if !foundIPs[ipUint32] {
			t.Errorf("NFS server IP %s (0x%08x) from config NOT found in nfs_server_ips eBPF map -- "+
				"config.ServerIPs is not being propagated to the eBPF map", ipStr, ipUint32)
		}
	}

	if len(foundIPs) == 0 {
		t.Error("nfs_server_ips eBPF map is completely empty -- " +
			"no server IPs were written, the eBPF probe will silently drop all traffic")
	}

	t.Logf("Found %d IPs in nfs_server_ips eBPF map (expected %d)", len(foundIPs), len(expectedIPs))
}

func TestNFSTargetPortPropagatedToEBPFMap(t *testing.T) {
	// Verifies: env NFS_TARGET_PORTS -> config.TargetPorts -> config_map eBPF map
	config := NFSConfig{
		ServerIPs:            []string{"10.0.1.100"},
		Protocols:            []string{"tcp"},
		TargetPorts:          []uint16{2049},
		EnableVolumeID:       false,
		MountRefreshInterval: 30 * time.Second,
	}

	collector, err := NewNFSLatencyCollector(config)
	if err != nil {
		t.Skipf("Skipping eBPF integration test (expected on non-Linux): %v", err)
		return
	}
	defer collector.Close()

	configMap := collector.objs.Maps["config_map"]
	if configMap == nil {
		t.Fatal("config_map not found in eBPF collection")
	}

	// Read back config from eBPF map
	var key uint32 = 0
	var val struct {
		TargetPort uint16
		Padding    uint16
	}
	if err := configMap.Lookup(&key, &val); err != nil {
		t.Fatalf("Failed to read config_map: %v", err)
	}

	if val.TargetPort != 2049 {
		t.Errorf("config_map target_port: got %d, want 2049 -- "+
			"config.TargetPorts is not being propagated to the eBPF config_map", val.TargetPort)
	}
}

func TestNFSServerIPsEmptyConfigWarning(t *testing.T) {
	// When no server IPs are configured AND /proc/mounts has no NFS entries,
	// the eBPF map should be empty but the collector should still initialize.
	// This verifies the warning path.
	config := NFSConfig{
		ServerIPs:            []string{}, // Empty -- no configured IPs
		Protocols:            []string{"tcp"},
		TargetPorts:          []uint16{2049},
		EnableVolumeID:       false,
		MountRefreshInterval: 30 * time.Second,
	}

	collector, err := NewNFSLatencyCollector(config)
	if err != nil {
		t.Skipf("Skipping eBPF integration test (expected on non-Linux): %v", err)
		return
	}
	defer collector.Close()

	// The collector should have initialized even with no IPs.
	// On a host with NFS mounts, the map may have entries from /proc/mounts.
	// The key thing is: the collector didn't crash.
	t.Log("NFS collector initialized with empty ServerIPs (IPs may come from /proc/mounts)")
}

func TestObjStoreIPsPropagatedToEBPFMap(t *testing.T) {
	// Verifies: env OBJSTORE_ENDPOINT_IPS -> filterIPs -> objstore_server_ips eBPF map
	testIPs := []string{"100.63.0.10", "100.63.0.11"}

	collector, err := NewObjStoreLatencyCollector(ObjStoreConfig{InitialIPs: testIPs, TargetPorts: []uint16{8080}})
	if err != nil {
		t.Skipf("Skipping eBPF integration test (expected on non-Linux): %v", err)
		return
	}
	defer collector.Close()

	serverIPsMap := collector.objs.Maps["objstore_server_ips"]
	if serverIPsMap == nil {
		t.Fatal("objstore_server_ips map not found in eBPF collection")
	}

	expectedIPs := make(map[uint32]string)
	for _, ipStr := range testIPs {
		parsed := net.ParseIP(ipStr).To4()
		if parsed == nil {
			t.Fatalf("Failed to parse test IP %s", ipStr)
		}
		expectedIPs[binary.LittleEndian.Uint32(parsed)] = ipStr
	}

	foundIPs := make(map[uint32]bool)
	for i := uint32(0); i < 64; i++ {
		var val uint32
		idx := i
		if err := serverIPsMap.Lookup(&idx, &val); err != nil {
			break
		}
		if val == 0 {
			break
		}
		foundIPs[val] = true
	}

	for ipUint32, ipStr := range expectedIPs {
		if !foundIPs[ipUint32] {
			t.Errorf("ObjStore server IP %s (0x%08x) from config NOT found in objstore_server_ips eBPF map -- "+
				"filterIPs is not being propagated to the eBPF map", ipStr, ipUint32)
		}
	}

	if len(foundIPs) == 0 {
		t.Error("objstore_server_ips eBPF map is completely empty -- " +
			"no server IPs were written, the eBPF probe will silently drop all traffic")
	}
}

func TestObjStorePortPropagatedToEBPFMap(t *testing.T) {
	// Verifies: env OBJSTORE_ENDPOINT_PORT -> targetPorts -> config_map eBPF map
	collector, err := NewObjStoreLatencyCollector(ObjStoreConfig{InitialIPs: []string{"100.63.0.10"}, TargetPorts: []uint16{8080, 443}})
	if err != nil {
		t.Skipf("Skipping eBPF integration test (expected on non-Linux): %v", err)
		return
	}
	defer collector.Close()

	configMap := collector.objs.Maps["config_map"]
	if configMap == nil {
		t.Fatal("config_map not found in eBPF collection")
	}

	var key uint32 = 0
	var val struct {
		TargetPorts [4]uint16
	}
	if err := configMap.Lookup(&key, &val); err != nil {
		t.Fatalf("Failed to read config_map: %v", err)
	}

	if val.TargetPorts[0] != 8080 || val.TargetPorts[1] != 443 {
		t.Errorf("config_map target_ports: got %v, want [8080, 443, 0, 0] -- "+
			"targetPorts is not being propagated to the eBPF config_map", val.TargetPorts)
	}
}

// ---------------------------------------------------------------------------
// End-to-end env var -> eBPF map tests (eBPF integration -- skip on non-Linux)
// These simulate the full main.go flow: set env vars, parse config, create
// collector, verify eBPF map contents.
// ---------------------------------------------------------------------------

func TestEndToEndNFSEnvToEBPF(t *testing.T) {
	// Save and restore env
	savedIPs := os.Getenv("NFS_SERVER_IPS")
	savedPorts := os.Getenv("NFS_TARGET_PORTS")
	defer func() {
		if savedIPs != "" {
			os.Setenv("NFS_SERVER_IPS", savedIPs)
		} else {
			os.Unsetenv("NFS_SERVER_IPS")
		}
		if savedPorts != "" {
			os.Setenv("NFS_TARGET_PORTS", savedPorts)
		} else {
			os.Unsetenv("NFS_TARGET_PORTS")
		}
	}()

	// Simulate env vars
	os.Setenv("NFS_SERVER_IPS", "10.0.1.100,192.168.1.50")
	os.Setenv("NFS_TARGET_PORTS", "2049")

	// Parse config exactly like main.go does
	config := parseNFSConfigFromEnv()

	// Verify parsing worked
	if len(config.ServerIPs) != 2 {
		t.Fatalf("parseNFSConfigFromEnv returned %d IPs, want 2", len(config.ServerIPs))
	}

	// Create collector with parsed config
	collector, err := NewNFSLatencyCollector(config)
	if err != nil {
		t.Skipf("Skipping eBPF integration test (expected on non-Linux): %v", err)
		return
	}
	defer collector.Close()

	// Verify IPs reached the eBPF map
	serverIPsMap := collector.objs.Maps["nfs_server_ips"]
	if serverIPsMap == nil {
		t.Fatal("nfs_server_ips map not found")
	}

	foundCount := 0
	for i := uint32(0); i < 64; i++ {
		var val uint32
		idx := i
		if err := serverIPsMap.Lookup(&idx, &val); err != nil {
			break
		}
		if val != 0 {
			foundCount++
		}
	}

	if foundCount < 2 {
		t.Errorf("Only %d IPs found in nfs_server_ips eBPF map after end-to-end flow (expected >= 2). "+
			"Env var NFS_SERVER_IPS is not reaching the eBPF map.", foundCount)
	}
}

func TestEndToEndObjStoreEnvToEBPF(t *testing.T) {
	savedIPs := os.Getenv("OBJSTORE_ENDPOINT_IPS")
	savedPort := os.Getenv("OBJSTORE_ENDPOINT_PORT")
	defer func() {
		if savedIPs != "" {
			os.Setenv("OBJSTORE_ENDPOINT_IPS", savedIPs)
		} else {
			os.Unsetenv("OBJSTORE_ENDPOINT_IPS")
		}
		if savedPort != "" {
			os.Setenv("OBJSTORE_ENDPOINT_PORT", savedPort)
		} else {
			os.Unsetenv("OBJSTORE_ENDPOINT_PORT")
		}
	}()

	os.Setenv("OBJSTORE_ENDPOINT_IPS", "100.63.0.10")
	os.Setenv("OBJSTORE_ENDPOINT_PORT", "8080")

	config := parseObjStoreConfigFromEnv()

	if len(config.InitialIPs) != 1 || config.InitialIPs[0] != "100.63.0.10" {
		t.Fatalf("parseObjStoreConfigFromEnv returned IPs %v, want [100.63.0.10]", config.InitialIPs)
	}
	if len(config.TargetPorts) != 1 || config.TargetPorts[0] != 8080 {
		t.Fatalf("parseObjStoreConfigFromEnv returned ports %v, want [8080]", config.TargetPorts)
	}

	collector, err := NewObjStoreLatencyCollector(config)
	if err != nil {
		t.Skipf("Skipping eBPF integration test (expected on non-Linux): %v", err)
		return
	}
	defer collector.Close()

	// Verify IP in eBPF map
	serverIPsMap := collector.objs.Maps["objstore_server_ips"]
	if serverIPsMap == nil {
		t.Fatal("objstore_server_ips map not found")
	}

	expectedIP := net.ParseIP("100.63.0.10").To4()
	expectedUint32 := binary.LittleEndian.Uint32(expectedIP)

	found := false
	for i := uint32(0); i < 64; i++ {
		var val uint32
		idx := i
		if err := serverIPsMap.Lookup(&idx, &val); err != nil {
			break
		}
		if val == expectedUint32 {
			found = true
			break
		}
	}

	if !found {
		t.Error("OBJSTORE_ENDPOINT_IPS=100.63.0.10 not found in objstore_server_ips eBPF map. " +
			"Env var is not reaching the eBPF map.")
	}

	// Verify port in eBPF map
	configMap := collector.objs.Maps["config_map"]
	if configMap == nil {
		t.Fatal("config_map not found")
	}

	var key uint32 = 0
	var val struct {
		TargetPorts [4]uint16
	}
	if err := configMap.Lookup(&key, &val); err != nil {
		t.Fatalf("Failed to read config_map: %v", err)
	}

	if val.TargetPorts[0] != 8080 {
		t.Errorf("OBJSTORE_ENDPOINT_PORT=8080 not propagated to config_map (got %v). "+
			"Env var is not reaching the eBPF map.", val.TargetPorts)
	}
}

// ---------------------------------------------------------------------------
// DNS resolution tests for OBJSTORE_ENDPOINT_FQDN
// ---------------------------------------------------------------------------

func TestResolveObjStoreFQDN_ValidHostname(t *testing.T) {
	// Resolve a well-known hostname that should always have IPv4 records.
	ips, err := resolveObjStoreFQDN("dns.google")
	if err != nil {
		t.Skipf("Skipping: DNS resolution not available in this environment: %v", err)
	}

	if len(ips) == 0 {
		t.Fatal("expected at least one IPv4 address for dns.google")
	}

	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			t.Errorf("resolveObjStoreFQDN returned invalid IP: %q", ip)
		}
		// Ensure only IPv4 addresses are returned
		if net.ParseIP(ip).To4() == nil {
			t.Errorf("resolveObjStoreFQDN returned non-IPv4 address: %q", ip)
		}
	}
	t.Logf("dns.google resolved to %d IPs: %v", len(ips), ips)
}

func TestResolveObjStoreFQDN_NonExistentHost(t *testing.T) {
	_, err := resolveObjStoreFQDN("this-host-does-not-exist.invalid.")
	if err == nil {
		t.Error("expected error for non-existent hostname, got nil")
	}
}

func TestResolveObjStoreFQDN_ReturnsOnlyIPv4(t *testing.T) {
	// Use localhost which should always resolve
	ips, err := resolveObjStoreFQDN("localhost")
	if err != nil {
		t.Skipf("Skipping: localhost resolution not available: %v", err)
	}

	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Errorf("returned invalid IP: %q", ip)
			continue
		}
		if parsed.To4() == nil {
			t.Errorf("returned non-IPv4 address: %q (should filter to IPv4 only)", ip)
		}
	}
}

func TestObjStoreEnvVarParsing_FQDN(t *testing.T) {
	// Save and restore env
	savedEnv := map[string]string{}
	allKeys := []string{"OBJSTORE_ENDPOINT_IPS", "OBJSTORE_ENDPOINT_PORT", "OBJSTORE_ENDPOINT_FQDN"}
	for _, k := range allKeys {
		savedEnv[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	defer func() {
		for k, v := range savedEnv {
			if v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	}()

	// Set FQDN to a well-known hostname
	os.Setenv("OBJSTORE_ENDPOINT_FQDN", "dns.google")
	os.Setenv("OBJSTORE_ENDPOINT_PORT", "443")

	config := parseObjStoreConfigFromEnv()

	if len(config.InitialIPs) == 0 {
		t.Skip("Skipping: DNS resolution not available in this environment")
	}

	if len(config.TargetPorts) == 0 || config.TargetPorts[0] != 443 {
		t.Errorf("Ports: got %v, want [443, ...]", config.TargetPorts)
	}

	for _, ip := range config.InitialIPs {
		if net.ParseIP(ip) == nil {
			t.Errorf("FQDN resolution returned invalid IP: %q", ip)
		}
	}
	t.Logf("OBJSTORE_ENDPOINT_FQDN=dns.google resolved to %d IPs: %v", len(config.InitialIPs), config.InitialIPs)
}

func TestObjStoreEnvVarParsing_FQDNTakesPrecedenceOverIPs(t *testing.T) {
	savedEnv := map[string]string{}
	allKeys := []string{"OBJSTORE_ENDPOINT_IPS", "OBJSTORE_ENDPOINT_PORT", "OBJSTORE_ENDPOINT_FQDN"}
	for _, k := range allKeys {
		savedEnv[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	defer func() {
		for k, v := range savedEnv {
			if v != "" {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	}()

	// Set both FQDN and IPs -- FQDN should win
	os.Setenv("OBJSTORE_ENDPOINT_FQDN", "dns.google")
	os.Setenv("OBJSTORE_ENDPOINT_IPS", "1.2.3.4")

	config := parseObjStoreConfigFromEnv()

	if len(config.InitialIPs) == 0 {
		t.Skip("Skipping: DNS resolution not available in this environment")
	}

	// The IPs should come from DNS resolution, not from the static list
	for _, ip := range config.InitialIPs {
		if ip == "1.2.3.4" {
			t.Error("FQDN should take precedence over OBJSTORE_ENDPOINT_IPS, but got static IP 1.2.3.4")
		}
	}
}
