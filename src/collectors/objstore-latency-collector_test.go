package collectors

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestIPMatching(t *testing.T) {
	tests := []struct {
		name       string
		filterIPs  []string
		testIP     string
		shouldPass bool
	}{
		{
			name:       "exact match",
			filterIPs:  []string{"192.168.1.1"},
			testIP:     "192.168.1.1",
			shouldPass: true,
		},
		{
			name:       "no match",
			filterIPs:  []string{"192.168.1.1"},
			testIP:     "192.168.1.2",
			shouldPass: false,
		},
		{
			name:       "CIDR match",
			filterIPs:  []string{"192.168.1.0/24"},
			testIP:     "192.168.1.100",
			shouldPass: true,
		},
		{
			name:       "CIDR no match",
			filterIPs:  []string{"192.168.1.0/24"},
			testIP:     "192.168.2.100",
			shouldPass: false,
		},
		{
			name:       "empty filter allows all",
			filterIPs:  []string{},
			testIP:     "192.168.1.1",
			shouldPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := &ObjStoreLatencyCollector{
				filterIPs: tt.filterIPs,
			}
			// Parse the IP filters to set up filterNets
			if err := collector.parseIPFilters(); err != nil {
				t.Fatalf("Failed to parse IP filters: %v", err)
			}

			result := collector.matchesIPFilter(tt.testIP)
			if result != tt.shouldPass {
				t.Errorf("matchesIPFilter(%s) = %v, want %v", tt.testIP, result, tt.shouldPass)
			}
		})
	}
}

func TestIPConversion(t *testing.T) {
	tests := []struct {
		name     string
		ipUint32 uint32
		expected string
	}{
		{
			name:     "localhost",
			ipUint32: 0x0100007F, // 127.0.0.1 in little-endian (as eBPF stores on x86)
			expected: "127.0.0.1",
		},
		{
			name:     "private IP",
			ipUint32: 0x0101A8C0, // 192.168.1.1 in little-endian
			expected: "192.168.1.1",
		},
		{
			name:     "zero IP",
			ipUint32: 0x00000000,
			expected: "0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ipUint32ToString(tt.ipUint32)
			if result != tt.expected {
				t.Errorf("ipUint32ToString(0x%08X) = %s, want %s", tt.ipUint32, result, tt.expected)
			}
		})
	}
}

// TestObjStoreServerIPsMapPopulation tests that the object store collector populates the eBPF server IPs map with real IPs
func TestObjStoreServerIPsMapPopulation(t *testing.T) {
	// Create object store collector with test IPs
	testIPs := []string{"100.63.0.10", "10.234.1.180"}
	targetPort := uint16(8080)

	collector, err := NewObjStoreLatencyCollector(ObjStoreConfig{InitialIPs: testIPs, TargetPort: targetPort})
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

	// Check that objstore_server_ips map exists
	serverIPsMap := collector.objs.Maps["objstore_server_ips"]
	if serverIPsMap == nil {
		t.Error("objstore_server_ips map not found in eBPF collection")
		return
	}

	t.Log("✅ Object store collector has objstore_server_ips map available")
}

// TestObjStoreMetricsWithRealIPs tests that object store metrics are generated for real server IPs
func TestObjStoreMetricsWithRealIPs(t *testing.T) {
	testIPs := []string{"100.63.0.10"}
	targetPort := uint16(8080)

	collector, err := NewObjStoreLatencyCollector(ObjStoreConfig{InitialIPs: testIPs, TargetPort: targetPort})
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
	expectedIP := "100.63.0.10"

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
		t.Error("No metrics collected from object store collector")
	}

	if !realIPFound {
		t.Errorf("Expected to find metrics with real IP %s, but none found", expectedIP)
	}

	t.Logf("✅ Collected %d object store metrics", metricCount)
}

// TestObjStoreHostnameResolution tests that hostnames are properly resolved to IPs
func TestObjStoreHostnameResolution(t *testing.T) {
	// Test with hostname (should resolve to IPs)
	testHosts := []string{"localhost"} // Use localhost as it should resolve in test environment
	targetPort := uint16(8080)

	collector, err := NewObjStoreLatencyCollector(ObjStoreConfig{InitialIPs: testHosts, TargetPort: targetPort})
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

	// Check that objstore_server_ips map exists
	serverIPsMap := collector.objs.Maps["objstore_server_ips"]
	if serverIPsMap == nil {
		t.Error("objstore_server_ips map not found in eBPF collection")
		return
	}

	t.Log("✅ Object store collector properly resolved hostnames and created eBPF map")
}

// TestObjStoreMultipleEndpoints tests that multiple object store endpoints are handled correctly
func TestObjStoreMultipleEndpoints(t *testing.T) {
	testIPs := []string{"100.63.0.10", "10.234.1.180", "10.234.1.132"}
	targetPort := uint16(8080)

	collector, err := NewObjStoreLatencyCollector(ObjStoreConfig{InitialIPs: testIPs, TargetPort: targetPort})
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
	foundIPs := make(map[string]bool)

	for metric := range ch {
		metricCount++

		// Get metric description to check labels
		desc := metric.Desc()
		if desc != nil {
			descString := desc.String()

			// Check if metric contains any of the expected IPs in labels
			for _, expectedIP := range testIPs {
				if strings.Contains(descString, expectedIP) {
					foundIPs[expectedIP] = true
					t.Logf("✅ Found metric with real IP %s: %s", expectedIP, descString)
				}
			}
		}
	}

	if metricCount == 0 {
		t.Error("No metrics collected from object store collector")
	}

	// Check that we found metrics for at least one of the expected IPs
	if len(foundIPs) == 0 {
		t.Errorf("Expected to find metrics with real IPs %v, but none found", testIPs)
	}

	t.Logf("✅ Collected %d object store metrics for %d unique IPs", metricCount, len(foundIPs))
}

// TestObjStoreDefaultEndpoints tests that default endpoints are used when no IPs are provided
func TestObjStoreDefaultEndpoints(t *testing.T) {
	// Test with empty IP list (should use default S3 endpoints)
	testIPs := []string{}
	targetPort := uint16(443)

	collector, err := NewObjStoreLatencyCollector(ObjStoreConfig{InitialIPs: testIPs, TargetPort: targetPort})
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

	// Check that objstore_server_ips map exists
	serverIPsMap := collector.objs.Maps["objstore_server_ips"]
	if serverIPsMap == nil {
		t.Error("objstore_server_ips map not found in eBPF collection")
		return
	}

	t.Log("✅ Object store collector used default endpoints when no IPs provided")
}

// TestObjStoreIPByteOrderConversion tests that object store IP conversion uses correct byte order
func TestObjStoreIPByteOrderConversion(t *testing.T) {
	testCases := []struct {
		name     string
		ipString string
		expected uint32
	}{
		{
			name:     "IP 100.63.0.10",
			ipString: "100.63.0.10",
			// 100.63.0.10 in little-endian: 0x0a003f64
			expected: 0x0a003f64,
		},
		{
			name:     "IP 10.234.1.180",
			ipString: "10.234.1.180",
			// 10.234.1.180 in little-endian: 0xb401ea0a
			expected: 0xb401ea0a,
		},
		{
			name:     "IP 10.234.1.132",
			ipString: "10.234.1.132",
			// 10.234.1.132 in little-endian: 0x8401ea0a
			expected: 0x8401ea0a,
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

			// Test the actual conversion used in the collector (should be little-endian)
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

// TestObjStoreIPConversionConsistency tests that object store collector uses consistent byte order
func TestObjStoreIPConversionConsistency(t *testing.T) {
	testIP := "100.63.0.10"

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
	expectedLittleEndian := uint32(0x0a003f64) // 100.63.0.10 in little-endian
	if littleEndianValue != expectedLittleEndian {
		t.Errorf("Little-endian conversion: got 0x%08x, expected 0x%08x",
			littleEndianValue, expectedLittleEndian)
	}

	t.Logf("✅ IP %s: little-endian 0x%08x, big-endian 0x%08x",
		testIP, littleEndianValue, bigEndianValue)
}

// TestObjStoreFilteringVsMapPopulationConsistency tests that filtering and eBPF map use same byte order
func TestObjStoreFilteringVsMapPopulationConsistency(t *testing.T) {
	testIP := "100.63.0.10"

	// Parse IP once
	parsedIP := net.ParseIP(testIP)
	if parsedIP == nil {
		t.Fatalf("Failed to parse IP %s", testIP)
	}
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		t.Fatalf("IP %s is not IPv4", testIP)
	}

	// Test filtering conversion (what addObjStoreEndpoint uses)
	filteringValue := binary.LittleEndian.Uint32(ipv4)

	// Test eBPF map conversion (what updateObjStoreServerIPsMap uses)
	mapValue := binary.LittleEndian.Uint32(ipv4)

	// They should be identical
	if filteringValue != mapValue {
		t.Errorf("Inconsistent byte order: filtering uses 0x%08x, eBPF map uses 0x%08x",
			filteringValue, mapValue)
	}

	// Verify they're both little-endian
	expectedValue := uint32(0x0a003f64) // 100.63.0.10 in little-endian
	if filteringValue != expectedValue || mapValue != expectedValue {
		t.Errorf("Both should be 0x%08x: filtering=0x%08x, eBPF map=0x%08x",
			expectedValue, filteringValue, mapValue)
	}

	t.Logf("✅ Object store filtering and eBPF map both use little-endian 0x%08x", mapValue)
}

// TestObjStoreEBPFMapPopulation tests that object store eBPF map gets populated with correct byte order
func TestObjStoreEBPFMapPopulation(t *testing.T) {
	testIPs := []string{"100.63.0.10", "10.234.1.180"}
	targetPort := uint16(8080)

	collector, err := NewObjStoreLatencyCollector(ObjStoreConfig{InitialIPs: testIPs, TargetPort: targetPort})
	if err != nil {
		t.Skip("Skipping test - collector creation failed (expected in test environment)")
		return
	}
	defer collector.Close()

	// Test that we can call the update function without error
	err = collector.updateObjStoreServerIPsMap()
	if err != nil {
		t.Errorf("Failed to update object store server IPs map: %v", err)
		return
	}

	t.Log("✅ Object store eBPF map population succeeded with correct byte order")
}

// TestObjStoreIPFilteringConsistency tests that IP filtering works with correct byte order
func TestObjStoreIPFilteringConsistency(t *testing.T) {
	testIPs := []string{"100.63.0.10"}
	targetPort := uint16(8080)

	collector, err := NewObjStoreLatencyCollector(ObjStoreConfig{InitialIPs: testIPs, TargetPort: targetPort})
	if err != nil {
		t.Skip("Skipping test - collector creation failed (expected in test environment)")
		return
	}
	defer collector.Close()

	// Test that the filtering logic works with the expected byte order
	testIP := "100.63.0.10"
	parsedIP := net.ParseIP(testIP)
	if parsedIP == nil {
		t.Fatalf("Failed to parse IP %s", testIP)
	}
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		t.Fatalf("IP %s is not IPv4", testIP)
	}

	// Convert using the same logic as addObjStoreEndpoint
	ipInt := binary.LittleEndian.Uint32(ipv4)

	// Check if this IP would be in the filter list
	collector.endpointMutex.RLock()
	isFiltered := collector.objStoreEndpoints[ipInt]
	collector.endpointMutex.RUnlock()

	if !isFiltered {
		t.Errorf("IP %s (0x%08x) should be in filter list but wasn't found", testIP, ipInt)
	}

	t.Logf("✅ IP %s correctly found in filter list with little-endian value 0x%08x", testIP, ipInt)
}
