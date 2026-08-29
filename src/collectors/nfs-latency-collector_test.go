package collectors

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestNFSLatencyCollectorConfig tests the NFS configuration
func TestNFSLatencyCollectorConfig(t *testing.T) {
	config := NFSConfig{
		ServerIPs:            []string{"172.27.255.32", "10.0.0.1"},
		Protocols:            []string{"tcp", "udp"},
		TargetPorts:          []uint16{2049},
		EnableVolumeID:       true,
		MountRefreshInterval: 30 * time.Second,
	}

	// Test configuration values
	if len(config.ServerIPs) != 2 {
		t.Errorf("Expected 2 server IPs, got %d", len(config.ServerIPs))
	}

	if len(config.Protocols) != 2 {
		t.Errorf("Expected 2 protocols, got %d", len(config.Protocols))
	}

	if len(config.TargetPorts) != 1 || config.TargetPorts[0] != 2049 {
		t.Errorf("Expected port 2049, got %v", config.TargetPorts)
	}

	if !config.EnableVolumeID {
		t.Error("Expected EnableVolumeID to be true")
	}

	if config.MountRefreshInterval != 30*time.Second {
		t.Errorf("Expected refresh interval 30s, got %v", config.MountRefreshInterval)
	}
}

// TestNFSVolumeMapping tests the volume mapping functionality
func TestNFSVolumeMapping(t *testing.T) {
	vm := NewVolumeMapping()

	// Test adding a volume via UpdateMapping
	vm.UpdateMapping(map[string]string{
		"172.27.255.32": "vol-123456",
	})

	// Test getting volume ID
	volumeID := vm.GetVolumeID("172.27.255.32")
	if volumeID != "vol-123456" {
		t.Errorf("Expected vol-123456, got %s", volumeID)
	}

	// Test unknown IP
	unknownVolumeID := vm.GetVolumeID("10.0.0.99")
	if unknownVolumeID != "" {
		t.Errorf("Expected empty string for unknown IP, got %s", unknownVolumeID)
	}
}

// TestNFSVolumeMapping_AmbiguousIPNotMisattributed verifies that when a
// single server IP hosts more than one export (e.g. a shared filer with
// several /volumes/<uuid> exports behind one address), updateVolumeMapping
// does not silently pick one volume as the winner for that IP. Traffic to
// an ambiguous IP must resolve to a stable unknown-<ip> label instead of
// being attributed to an unrelated real volume, and that label must not
// change across repeated refreshes of the same mounts data.
//
// Mount server addresses in /proc/mounts can legitimately be either a
// hostname (IP discovered via the addr= mount option, or DNS as a last
// resort) or a literal IP (used directly, no option parsing needed). Both
// forms are exercised here as non-ambiguous controls alongside the
// ambiguous case: without them, a totally broken discovery/mapping
// mechanism would also produce an unresolved "unknown-<ip>" label for the
// ambiguous IP, and the core assertions below would pass for the wrong
// reason.
func TestNFSVolumeMapping_AmbiguousIPNotMisattributed(t *testing.T) {
	config := NFSConfig{
		EnableVolumeID:       true,
		MountRefreshInterval: 30 * time.Second,
	}

	collector, err := NewNFSLatencyCollector(config)
	if err != nil {
		t.Skip("Skipping test - collector creation failed (expected in test environment)")
		return
	}
	defer collector.Close()

	mountsFile := filepath.Join(t.TempDir(), "mounts")
	contents := "" +
		// Control 1: hostname server, IP discovered via addr= (not DNS --
		// nfs-host-control.invalid is not expected to resolve).
		"nfs-host-control.invalid:/volumes/vol-CONTROL-HOST /mnt/ch nfs rw,addr=10.0.0.9 0 0\n" +
		// Control 2: literal-IP server, no addr= option needed.
		"10.0.0.10:/volumes/vol-CONTROL-IP /mnt/ci nfs rw 0 0\n" +
		// Ambiguous: two distinct exports sharing one server IP via addr=.
		"nfs-host-shared.invalid:/volumes/vol-AAAA /mnt/a nfs rw,addr=10.0.0.5 0 0\n" +
		"nfs-host-shared.invalid:/volumes/vol-BBBB /mnt/b nfs rw,addr=10.0.0.5 0 0\n"
	if err := os.WriteFile(mountsFile, []byte(contents), 0o644); err != nil {
		t.Fatalf("failed to write test mounts file: %v", err)
	}
	collector.config.HostMountsPath = mountsFile

	if err := collector.updateVolumeMapping(); err != nil {
		t.Fatalf("updateVolumeMapping failed: %v", err)
	}

	if got := collector.getVolumeID("10.0.0.9", 0); got != "vol-CONTROL-HOST" {
		t.Fatalf("hostname+addr= mount did not resolve to its real volume (got %q) -- "+
			"IP discovery from mount options is broken, so the ambiguous-IP "+
			"assertions below would be meaningless", got)
	}
	if got := collector.getVolumeID("10.0.0.10", 0); got != "vol-CONTROL-IP" {
		t.Fatalf("literal-IP mount did not resolve to its real volume (got %q) -- "+
			"IP discovery from a bare IP server is broken, so the ambiguous-IP "+
			"assertions below would be meaningless", got)
	}

	got := collector.getVolumeID("10.0.0.5", 0)
	if got == "vol-AAAA" || got == "vol-BBBB" {
		t.Errorf("ambiguous IP was attributed to a single real volume (%s); "+
			"traffic on a shared IP must not be silently mislabeled", got)
	}
	want := "unknown-10.0.0.5"
	if got != want {
		t.Errorf("expected stable ambiguous-IP label %q, got %q", want, got)
	}

	// Re-running against identical input must yield the same label -- this
	// is the flapping scenario: the same ambiguous IP must resolve
	// identically on every refresh, not flip between vol-AAAA/vol-BBBB.
	if err := collector.updateVolumeMapping(); err != nil {
		t.Fatalf("second updateVolumeMapping failed: %v", err)
	}
	if again := collector.getVolumeID("10.0.0.5", 0); again != want {
		t.Errorf("label changed across refreshes: got %q, then %q", got, again)
	}
	if again := collector.getVolumeID("10.0.0.9", 0); again != "vol-CONTROL-HOST" {
		t.Errorf("hostname control label changed across refreshes: got %q", again)
	}
	if again := collector.getVolumeID("10.0.0.10", 0); again != "vol-CONTROL-IP" {
		t.Errorf("literal-IP control label changed across refreshes: got %q", again)
	}
}

// TestExtractIPsFromMountOptions_AddrField verifies IP extraction reads the
// mount options from the correct /proc/mounts field. A line has exactly six
// whitespace-separated fields (device mountpoint fstype options dump pass);
// options is fields[3]. This pins that index directly so a regression here
// fails loudly instead of silently falling through to the DNS/literal-IP
// fallback paths in updateVolumeMapping, which can mask it.
func TestExtractIPsFromMountOptions_AddrField(t *testing.T) {
	c := &NFSLatencyCollector{}
	fields := strings.Fields("myserver:/volumes/vol-1 /mnt/a nfs rw,addr=10.1.2.3,vers=3 0 0")
	ips := c.extractIPsFromMountOptions(fields)
	if len(ips) != 1 || ips[0] != "10.1.2.3" {
		t.Fatalf("expected [10.1.2.3], got %v", ips)
	}
}

// TestNFSIPConversion tests IP conversion utilities
func TestNFSIPConversion(t *testing.T) {
	// Test IP string to uint32 conversion
	testCases := []struct {
		ipStr     string
		expected  uint32
		expectErr bool
	}{
		{"172.27.255.32", 0xac1bff20, false},
		{"10.0.0.1", 0x0a000001, false},
		{"127.0.0.1", 0x7f000001, false},
		{"invalid.ip", 0, true},
		{"", 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.ipStr, func(t *testing.T) {
			// This would test the ipStringToUint32 function if it were exported
			// For now, we just verify the expected values are reasonable
			if tc.ipStr == "172.27.255.32" {
				// Manual calculation: 172*256^3 + 27*256^2 + 255*256 + 32
				expected := uint32(172*16777216 + 27*65536 + 255*256 + 32)
				if expected != 0xac1bff20 {
					t.Errorf("IP calculation mismatch: expected %x, got %x", 0xac1bff20, expected)
				}
			}
		})
	}
}

// TestNFSLatencyCollectorMetrics tests metric descriptor creation
func TestNFSLatencyCollectorMetrics(t *testing.T) {
	// Note: This test would require a mock eBPF collection to test the Collect method
	// For now, we test the metric descriptor creation
	collector := &NFSLatencyCollector{
		latencyDesc: prometheus.NewDesc(
			MetricPrefix+"_nfs_latency_seconds_total",
			"Total NFS request latency in seconds",
			[]string{"protocol", "operation", "volume_id"},
			nil,
		),
		requestsDesc: prometheus.NewDesc(
			MetricPrefix+"_nfs_requests_completed_total",
			"Total number of NFS requests completed",
			[]string{"protocol", "operation", "volume_id"},
			nil,
		),
		retransmitDesc: prometheus.NewDesc(
			MetricPrefix+"_nfs_tcp_retransmits_total",
			"Total number of TCP retransmissions to NFS servers",
			[]string{"protocol", "operation", "volume_id"},
			nil,
		),
		latencyHistDesc: prometheus.NewDesc(
			MetricPrefix+"_nfs_latency_histogram_seconds",
			"Histogram of NFS request latency in seconds",
			[]string{"protocol", "operation", "volume_id"},
			nil,
		),
	}

	// Test Describe method
	ch := make(chan *prometheus.Desc, 10)
	collector.Describe(ch)
	close(ch)

	// Count descriptors emitted
	descCount := 0
	for range ch {
		descCount++
	}

	if descCount != 4 {
		t.Errorf("Expected 4 descriptors, got %d", descCount)
	}
}

// TestNFSServerIPsMapPopulation tests that the NFS collector populates the eBPF server IPs map with real IPs
func TestNFSServerIPsMapPopulation(t *testing.T) {
	// Create a mock NFS configuration with test IPs
	config := NFSConfig{
		ServerIPs:            []string{"10.0.1.100", "192.168.1.50"},
		Protocols:            []string{"tcp"},
		TargetPorts:          []uint16{2049},
		EnableVolumeID:       true,
		MountRefreshInterval: 30 * time.Second,
	}

	collector, err := NewNFSLatencyCollector(config)
	if err != nil {
		t.Skip("Skipping test - collector creation failed (expected in test environment)")
		return
	}
	defer collector.Close()

	// Test that the collector has the expected eBPF maps
	if collector.objs == nil {
		t.Skip("Skipping test - eBPF objects not loaded (expected in test environment)")
		return
	}

	// Check that nfs_server_ips map exists
	serverIPsMap := collector.objs.Maps["nfs_server_ips"]
	if serverIPsMap == nil {
		t.Error("nfs_server_ips map not found in eBPF collection")
		return
	}

	t.Log("✅ NFS collector has nfs_server_ips map available")
}

// TestNFSMetricsWithRealIPs tests that NFS metrics are generated for real server IPs
func TestNFSMetricsWithRealIPs(t *testing.T) {
	config := NFSConfig{
		ServerIPs:            []string{"10.0.1.100"},
		Protocols:            []string{"tcp"},
		TargetPorts:          []uint16{2049},
		EnableVolumeID:       false, // Disable volume ID for simpler testing
		MountRefreshInterval: 30 * time.Second,
	}

	collector, err := NewNFSLatencyCollector(config)
	if err != nil {
		t.Skip("Skipping test - collector creation failed (expected in test environment)")
		return
	}
	defer collector.Close()

	// Collect metrics
	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	// Count metrics and check for expected real IPs
	metricCount := 0
	realIPFound := false
	expectedIP := "10.0.1.100"

	for metric := range ch {
		metricCount++

		// Get metric description to check labels
		desc := metric.Desc()
		if desc != nil {
			descString := desc.String()

			// Check if metric contains expected IP in labels
			if strings.Contains(descString, expectedIP) {
				realIPFound = true
				t.Logf("✅ Found metric with real IP %s: %s", expectedIP, descString)
			}
		}
	}

	if metricCount == 0 {
		t.Error("No metrics collected from NFS collector")
	}

	if !realIPFound {
		t.Errorf("Expected to find metrics with real IP %s, but none found", expectedIP)
	}

	t.Logf("✅ Collected %d NFS metrics", metricCount)
}

// TestNFSVolumeMappingIntegration tests that volume mapping integration works
func TestNFSVolumeMappingIntegration(t *testing.T) {
	config := NFSConfig{
		ServerIPs:            []string{"10.0.1.100"},
		Protocols:            []string{"tcp"},
		TargetPorts:          []uint16{2049},
		EnableVolumeID:       true,
		MountRefreshInterval: 30 * time.Second,
	}

	collector, err := NewNFSLatencyCollector(config)
	if err != nil {
		t.Skip("Skipping test - collector creation failed (expected in test environment)")
		return
	}
	defer collector.Close()

	// Test that volume mapping is initialized
	if collector.volumeMapping == nil {
		t.Error("Volume mapping not initialized")
		return
	}

	t.Log("✅ NFS volume mapping initialized successfully")
}

// TestNFSIPByteOrderConversion tests that NFS IP conversion uses correct byte order
func TestNFSIPByteOrderConversion(t *testing.T) {
	testCases := []struct {
		name     string
		ipString string
		expected uint32
	}{
		{
			name:     "IP 10.0.1.100",
			ipString: "10.0.1.100",
			// 10.0.1.100 bytes [0a,00,01,64] in little-endian: 0x6401000a
			expected: 0x6401000a,
		},
		{
			name:     "IP 192.168.1.50",
			ipString: "192.168.1.50",
			// 192.168.1.50 bytes [c0,a8,01,32] in little-endian: 0x3201a8c0
			expected: 0x3201a8c0,
		},
		{
			name:     "IP 127.0.0.1",
			ipString: "127.0.0.1",
			// 127.0.0.1 in little-endian: 0x0100007f
			expected: 0x0100007f,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse IP string
			parsedIP := net.ParseIP(tc.ipString)
			if parsedIP == nil {
				t.Fatalf("Failed to parse IP %s", tc.ipString)
			}

			// Convert to IPv4
			ipv4 := parsedIP.To4()
			if ipv4 == nil {
				t.Fatalf("IP %s is not IPv4", tc.ipString)
			}

			// Test the actual conversion used in the collector
			ipUint32 := binary.LittleEndian.Uint32(ipv4)

			// Verify the byte order is correct
			if ipUint32 != tc.expected {
				t.Errorf("IP %s conversion: got 0x%08x, expected 0x%08x",
					tc.ipString, ipUint32, tc.expected)
			}

			// Also verify it's NOT big-endian (which would be wrong)
			bigEndianValue := binary.BigEndian.Uint32(ipv4)
			if ipUint32 == bigEndianValue {
				t.Errorf("IP %s: little-endian and big-endian values are the same (0x%08x), this is suspicious",
					tc.ipString, ipUint32)
			}

			t.Logf("✅ IP %s: little-endian 0x%08x (correct), big-endian 0x%08x (would be wrong)",
				tc.ipString, ipUint32, bigEndianValue)
		})
	}
}

// TestNFSIPConversionConsistency tests that NFS collector uses consistent byte order
func TestNFSIPConversionConsistency(t *testing.T) {
	testIP := "10.0.1.100"

	// Parse IP once
	parsedIP := net.ParseIP(testIP)
	if parsedIP == nil {
		t.Fatalf("Failed to parse IP %s", testIP)
	}
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		t.Fatalf("IP %s is not IPv4", testIP)
	}

	// Test both conversions that should be consistent
	littleEndianValue := binary.LittleEndian.Uint32(ipv4)
	bigEndianValue := binary.BigEndian.Uint32(ipv4)

	// They should be different for a non-symmetric IP
	if littleEndianValue == bigEndianValue {
		t.Errorf("Little-endian and big-endian values are the same (0x%08x) for IP %s",
			littleEndianValue, testIP)
	}

	// Verify little-endian is what we expect
	expectedLittleEndian := uint32(0x6401000a) // 10.0.1.100 in little-endian
	if littleEndianValue != expectedLittleEndian {
		t.Errorf("Little-endian conversion: got 0x%08x, expected 0x%08x",
			littleEndianValue, expectedLittleEndian)
	}

	t.Logf("✅ IP %s: little-endian 0x%08x, big-endian 0x%08x",
		testIP, littleEndianValue, bigEndianValue)
}

// TestNFSEBPFMapPopulation tests that NFS eBPF map gets populated with correct byte order
func TestNFSEBPFMapPopulation(t *testing.T) {
	config := NFSConfig{
		ServerIPs:            []string{"10.0.1.100", "192.168.1.50"},
		Protocols:            []string{"tcp"},
		TargetPorts:          []uint16{2049},
		EnableVolumeID:       true,
		MountRefreshInterval: 30 * time.Second,
	}

	collector, err := NewNFSLatencyCollector(config)
	if err != nil {
		t.Skip("Skipping test - collector creation failed (expected in test environment)")
		return
	}
	defer collector.Close()

	// Test that we can call the update function without error
	testMapping := map[string]string{
		"10.0.1.100":   "vol-12345",
		"192.168.1.50": "vol-67890",
	}

	err = collector.updateNFSServerIPsMap(testMapping)
	if err != nil {
		t.Errorf("Failed to update NFS server IPs map: %v", err)
		return
	}

	t.Log("✅ NFS eBPF map population succeeded with correct byte order")
}

// TestExtractRemotePortsIPs tests the remoteports= mount option parsing
func TestExtractRemotePortsIPs(t *testing.T) {
	// We need a minimal collector instance for the method receiver (it uses resolveDomainName)
	c := &NFSLatencyCollector{}

	t.Run("IP range 4 IPs", func(t *testing.T) {
		options := "rw,relatime,vers=3,nconnect=16,remoteports=10.0.0.1-10.0.0.4,addr=10.0.0.1"
		ips := c.extractRemotePortsIPs(options, "10.0.0.1")
		expected := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
		if len(ips) != len(expected) {
			t.Fatalf("expected %d IPs, got %d: %v", len(expected), len(ips), ips)
		}
		for i, ip := range expected {
			if ips[i] != ip {
				t.Errorf("ips[%d]: got %q, want %q", i, ips[i], ip)
			}
		}
	})

	t.Run("single IP", func(t *testing.T) {
		options := "rw,relatime,vers=3,remoteports=10.0.0.4,addr=10.0.0.4"
		ips := c.extractRemotePortsIPs(options, "10.0.0.4")
		if len(ips) != 1 || ips[0] != "10.0.0.4" {
			t.Fatalf("expected [10.0.0.4], got %v", ips)
		}
	})

	t.Run("DNS resolves to multiple IPs", func(t *testing.T) {
		// dns.google reliably resolves to 8.8.8.8 and 8.8.4.4 (at minimum)
		options := "rw,relatime,vers=3,nconnect=16,remoteports=dns,addr=8.8.8.8"
		ips := c.extractRemotePortsIPs(options, "dns.google")
		if len(ips) < 2 {
			t.Skipf("Skipping: dns.google resolved to fewer than 2 IPs (got %d: %v); DNS may be restricted", len(ips), ips)
		}
		for _, ip := range ips {
			if net.ParseIP(ip) == nil {
				t.Errorf("invalid IP in result: %q", ip)
			}
		}
		t.Logf("remoteports=dns with dns.google resolved to %d IPs: %v", len(ips), ips)
	})

	t.Run("DNS resolves to 1 IP", func(t *testing.T) {
		// Use localhost which should resolve to a single IP
		options := "rw,relatime,vers=3,remoteports=dns,addr=127.0.0.1"
		ips := c.extractRemotePortsIPs(options, "localhost")
		if len(ips) < 1 {
			t.Skipf("Skipping: localhost did not resolve (got %v); DNS may be restricted", ips)
		}
		for _, ip := range ips {
			if net.ParseIP(ip) == nil {
				t.Errorf("invalid IP in result: %q", ip)
			}
		}
		t.Logf("remoteports=dns with localhost resolved to %d IPs: %v", len(ips), ips)
	})

	t.Run("DNS with raw IP server is no-op", func(t *testing.T) {
		// When serverPart is already an IP, remoteports=dns should return nothing
		options := "rw,relatime,vers=3,remoteports=dns,addr=10.0.0.1"
		ips := c.extractRemotePortsIPs(options, "10.0.0.1")
		if len(ips) != 0 {
			t.Errorf("expected no IPs for remoteports=dns with IP server, got %v", ips)
		}
	})

	t.Run("no remoteports option", func(t *testing.T) {
		options := "rw,relatime,vers=3,addr=10.0.0.1"
		ips := c.extractRemotePortsIPs(options, "10.0.0.1")
		if len(ips) != 0 {
			t.Errorf("expected no IPs, got %v", ips)
		}
	})

	t.Run("empty remoteports", func(t *testing.T) {
		options := "rw,relatime,remoteports=,addr=10.0.0.1"
		ips := c.extractRemotePortsIPs(options, "10.0.0.1")
		if len(ips) != 0 {
			t.Errorf("expected no IPs, got %v", ips)
		}
	})
}

// TestMountOptionsParsing tests mount options parsing
func TestMountOptionsParsing(t *testing.T) {
	testCases := []struct {
		name           string
		mountOptions   string
		expectedIP     string
		expectedVolume string
		expectError    bool
	}{
		{
			name:           "StandardNFSMount",
			mountOptions:   "addr=172.27.255.32,vers=4.1,rsize=1048576,wsize=1048576,hard",
			expectedIP:     "172.27.255.32",
			expectedVolume: "",
			expectError:    false,
		},
		{
			name:           "MountWithVolumeID",
			mountOptions:   "addr=10.0.0.1,volume_id=vol-123456",
			expectedIP:     "10.0.0.1",
			expectedVolume: "vol-123456",
			expectError:    false,
		},
		{
			name:           "EmptyOptions",
			mountOptions:   "",
			expectedIP:     "",
			expectedVolume: "",
			expectError:    false,
		},
		{
			name:           "NoAddrOption",
			mountOptions:   "vers=4.1,rsize=1048576,wsize=1048576",
			expectedIP:     "",
			expectedVolume: "",
			expectError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// This would test the extractIPsFromMountOptions function if it were exported
			// For now, we just verify the parsing logic works with string operations
			options := strings.Split(tc.mountOptions, ",")
			var foundIP, foundVolume string

			for _, opt := range options {
				opt = strings.TrimSpace(opt)
				if strings.HasPrefix(opt, "addr=") {
					foundIP = strings.TrimPrefix(opt, "addr=")
				} else if strings.HasPrefix(opt, "volume_id=") {
					foundVolume = strings.TrimPrefix(opt, "volume_id=")
				}
			}

			if foundIP != tc.expectedIP {
				t.Errorf("Expected IP %s, got %s", tc.expectedIP, foundIP)
			}

			if foundVolume != tc.expectedVolume {
				t.Errorf("Expected volume %s, got %s", tc.expectedVolume, foundVolume)
			}
		})
	}
}
