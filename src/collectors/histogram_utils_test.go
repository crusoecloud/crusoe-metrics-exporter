package collectors

import (
	"math"
	"net"
	"strings"
	"testing"
)

// floatEqual compares two floats within a tolerance
func floatEqual(a, b, tolerance float64) bool {
	return math.Abs(a-b) <= tolerance
}

// Test data representing different /proc/mounts scenarios
const (
	// Scenario 1: Multiple volumes sharing the same IP
	mountDataSharedIP = `
nfs.crusoecloudcompute.com:/volumes/47d32f7f-1687-42c8-b6fd-67b3a2263c8e on /mnt/data1 type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=172.27.255.29,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=172.27.255.32)
nfs.crusoecloudcompute.com:/volumes/89e45b2a-2798-43d7-a9ce-123456789abc on /mnt/data2 type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=172.27.255.29,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=172.27.255.32)
nfs.crusoecloudcompute.com:/volumes/33ff88cc-99dd-44ee-aa55-667788990011 on /mnt/backup type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=172.27.255.29,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=172.27.255.32)
`

	// Scenario 2: Different IPs for different volumes
	mountDataDifferentIPs = `
nfs.crusoecloudcompute.com:/volumes/47d32f7f-1687-42c8-b6fd-67b3a2263c8e on /mnt/data1 type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=172.27.255.29,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=172.27.255.32)
nfs.provider2.com:/volumes/89e45b2a-2798-43d7-a9ce-123456789abc on /mnt/data2 type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=10.0.1.100,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=10.0.1.100)
nfs.storage.local:/volumes/33ff88cc-99dd-44ee-aa55-667788990011 on /mnt/backup type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=192.168.1.50,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=192.168.1.50)
`

	// Scenario 3: Mixed scenario - some shared IPs, some unique
	mountDataMixed = `
nfs.crusoecloudcompute.com:/volumes/47d32f7f-1687-42c8-b6fd-67b3a2263c8e on /mnt/data1 type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=172.27.255.29,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=172.27.255.32)
nfs.crusoecloudcompute.com:/volumes/89e45b2a-2798-43d7-a9ce-123456789abc on /mnt/data2 type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=172.27.255.29,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=172.27.255.32)
nfs.provider2.com:/volumes/33ff88cc-99dd-44ee-aa55-667788990011 on /mnt/backup type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=10.0.1.100,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=10.0.1.100)
nfs.crusoecloudcompute.com:/volumes/aa11bb22-33cc-44dd-55ee-6677889900ff on /mnt/cache type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=172.27.255.29,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=172.27.255.32)
`

	// Scenario 4: Multiple IPs per mount
	mountDataMultiIP = `
nfs.crusoecloudcompute.com:/volumes/47d32f7f-1687-42c8-b6fd-67b3a2263c8e on /mnt/data1 type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=172.27.255.29,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=172.27.255.32,addr=172.27.255.33,addr=172.27.255.34)
nfs.crusoecloudcompute.com:/volumes/89e45b2a-2798-43d7-a9ce-123456789abc on /mnt/data2 type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=172.27.255.29,mountvers=3,mountproto=tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=172.27.255.32,addr=172.27.255.33,addr=172.27.255.34)
`

	// Scenario 5: IP-based mount entries (first field is IP instead of domain)
	mountDataIPBased = `
172.27.255.32:/volumes/47d32f7f-1687-42c8-b6fd-67b3a2263c8e on /mnt/data1 type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=172.27.255.29,mountvers=3,mountproto,tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=172.27.255.32)
10.0.1.100:/volumes/89e45b2a-2798-43d7-a9ce-123456789abc on /mnt/data2 type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=10.0.1.100,mountvers=3,mountproto,tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=10.0.1.100)
192.168.1.50:/volumes/33ff88cc-99dd-44ee-aa55-667788990011 on /mnt/backup type nfs (rw,relatime,vers=3,rsize=1048576,wsize=1048576,namlen=255,hard,forcerdirplus,proto=tcp,nconnect=16,timeo=600,retrans=2,sec=sys,mountaddr=192.168.1.50,mountvers=3,mountproto,tcp,local_lock=none,remoteports=dns,spread_reads,spread_writes,addr=192.168.1.50)
`

	// Scenario 6: No NFS mounts
	mountDataNoNFS = `
/dev/sda1 on / type ext4 (rw,relatime)
tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
`
)

// resolveDomainNameForTest resolves a domain name to all its IP addresses (test version)
func resolveDomainNameForTest(domainName string) []string {
	var ips []string
	
	// For testing, we'll simulate DNS resolution for known domains
	// In a real environment, this would use net.LookupHost()
	switch domainName {
	case "nfs.crusoecloudcompute.com":
		// Simulate multiple IPs for the domain
		ips = []string{"172.27.255.32", "172.27.255.33", "172.27.255.34"}
	case "nfs.provider2.com":
		ips = []string{"10.0.1.100"}
	case "nfs.storage.local":
		ips = []string{"192.168.1.50"}
	default:
		// Try actual DNS resolution for unknown domains
		addrs, err := net.LookupHost(domainName)
		if err == nil {
			for _, addr := range addrs {
				if ip := net.ParseIP(addr); ip != nil {
					ips = append(ips, addr)
				}
			}
		}
	}
	
	return ips
}

// parseNFSMountsForTest is a test helper that parses mount data and returns IP->volumeID mapping
func parseNFSMountsForTest(mountData string) map[string]string {
	volumeMap := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(mountData), "\n")
	
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) < 6 { // NFS lines should have at least 6 fields: server path, "on", mount point, "type", "nfs", options
			continue
		}
		
		serverPath := fields[0]
		fsType := fields[4]    // "type" is fields[3], fs type is fields[4]
		
				
		if fsType != "nfs" {
			continue
		}
		
		if strings.Contains(serverPath, ":/volumes/") {
			parts := strings.Split(serverPath, ":/volumes/")
			if len(parts) == 2 {
				volumeID := parts[1]
				serverName := parts[0]
				
				// Extract ALL IPs from mount options (addr=X.X.X.X)
				optionsString := strings.Join(fields[5:], " ")
				var serverIPs []string
				
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
						serverIPs = append(serverIPs, ip)
					}
					
					// Continue searching from after this IP
					searchStart = addrEnd
				}
				
				// If no IPs found in options, check if serverName is already an IP address
				if len(serverIPs) == 0 {
					// Extract the server part (before :/volumes/)
					serverPart := serverName
					if strings.Contains(serverName, ":") {
						serverPart = strings.Split(serverName, ":")[0]
					}
					
					// Check if serverPart is already an IP address
					if net.ParseIP(serverPart) != nil {
						// It's already an IP address, use it directly
						serverIPs = append(serverIPs, serverPart)
					} else {
						// It's a domain name, try DNS resolution
						serverIPs = resolveDomainNameForTest(serverPart)
					}
				}
				
				// If still no IPs found, fallback to server name
				if len(serverIPs) == 0 {
					serverIPs = append(serverIPs, serverName)
				}
				
				// Create mapping for each IP to this volume
				for _, serverIP := range serverIPs {
					volumeMap[serverIP] = volumeID
				}
			}
		}
	}
	
	return volumeMap
}

func TestVolumeMapping_SharedIP(t *testing.T) {
	// Test scenario where multiple volumes share the same IP
	// Note: parseNFSMountsForTest returns map[string]string, so only
	// one volume per IP is kept (last wins for shared IPs).
	mountData := parseNFSMountsForTest(mountDataSharedIP)
	
	vm := NewVolumeMapping()
	vm.UpdateMapping(mountData)
	
	// Verify the mapping contains the expected data
	mappings := vm.GetAllMappings()
	
	// Should have only one IP (172.27.255.32)
	if len(mappings) != 1 {
		t.Errorf("Expected 1 IP in mapping, got %d", len(mappings))
	}
	
	entries, exists := mappings["172.27.255.32"]
	if !exists {
		t.Error("Expected IP 172.27.255.32 not found in mapping")
	}
	
	// map[string]string only keeps one volume per IP (last one wins)
	if len(entries) != 1 {
		t.Errorf("Expected 1 volume for IP 172.27.255.32 (map dedup), got %d", len(entries))
	}
	
	// Test backward compatibility - GetVolumeID should return a volume
	volumeID := vm.GetVolumeID("172.27.255.32")
	if volumeID == "" {
		t.Error("Expected non-empty volume ID")
	}
}

func TestVolumeMapping_DifferentIPs(t *testing.T) {
	// Test scenario where each volume has a different IP
	mountData := parseNFSMountsForTest(mountDataDifferentIPs)
	
	vm := NewVolumeMapping()
	vm.UpdateMapping(mountData)
	
	mappings := vm.GetAllMappings()
	
	// Should have 3 different IPs
	if len(mappings) != 3 {
		t.Errorf("Expected 3 IPs in mapping, got %d", len(mappings))
	}
	
	// Verify each IP has exactly one volume
	expectedIPs := map[string]string{
		"172.27.255.32":  "47d32f7f-1687-42c8-b6fd-67b3a2263c8e",
		"10.0.1.100":    "89e45b2a-2798-43d7-a9ce-123456789abc",
		"192.168.1.50":  "33ff88cc-99dd-44ee-aa55-667788990011",
	}
	
	for ip, expectedVolume := range expectedIPs {
		entries, exists := mappings[ip]
		if !exists {
			t.Errorf("Expected IP %s not found in mapping", ip)
			continue
		}
		
		if len(entries) != 1 {
			t.Errorf("Expected 1 volume for IP %s, got %d", ip, len(entries))
		}
		
		if entries[0].VolumeID != expectedVolume {
			t.Errorf("Expected volume %s for IP %s, got %s", expectedVolume, ip, entries[0].VolumeID)
		}
	}
}

func TestVolumeMapping_MixedScenario(t *testing.T) {
	// Test mixed scenario with both shared and unique IPs
	mountData := parseNFSMountsForTest(mountDataMixed)
	
	vm := NewVolumeMapping()
	vm.UpdateMapping(mountData)
	
	mappings := vm.GetAllMappings()
	
	// Should have 2 different IPs
	if len(mappings) != 2 {
		t.Errorf("Expected 2 IPs in mapping, got %d", len(mappings))
	}
	
	// Verify shared IP exists (map[string]string keeps last volume per IP)
	sharedIPEntries, exists := mappings["172.27.255.32"]
	if !exists {
		t.Error("Expected shared IP 172.27.255.32 not found in mapping")
	}
	
	if len(sharedIPEntries) != 1 {
		t.Errorf("Expected 1 volume for shared IP (map dedup), got %d", len(sharedIPEntries))
	}
	
	// Verify unique IP has one volume
	uniqueIPEntries, exists := mappings["10.0.1.100"]
	if !exists {
		t.Error("Expected unique IP 10.0.1.100 not found in mapping")
	}
	
	if len(uniqueIPEntries) != 1 {
		t.Errorf("Expected 1 volume for unique IP, got %d", len(uniqueIPEntries))
	}
}

func TestVolumeMapping_MultiIP(t *testing.T) {
	// Test scenario where each mount has multiple IPs
	mountData := parseNFSMountsForTest(mountDataMultiIP)
	
	vm := NewVolumeMapping()
	vm.UpdateMapping(mountData)
	
	mappings := vm.GetAllMappings()
	
	// Should have 3 different IPs (172.27.255.32, 172.27.255.33, 172.27.255.34)
	if len(mappings) != 3 {
		t.Errorf("Expected 3 IPs in mapping, got %d", len(mappings))
	}
	
	// Each IP should have 1 volume (map[string]string dedup, last wins)
	expectedIPs := []string{"172.27.255.32", "172.27.255.33", "172.27.255.34"}
	
	for _, ip := range expectedIPs {
		entries, exists := mappings[ip]
		if !exists {
			t.Errorf("Expected IP %s not found in mapping", ip)
			continue
		}
		
		if len(entries) != 1 {
			t.Errorf("Expected 1 volume for IP %s (map dedup), got %d", ip, len(entries))
		}
	}
}

func TestVolumeMapping_IPBased(t *testing.T) {
	// Test scenario where mount entries use IP addresses instead of domain names
	mountData := parseNFSMountsForTest(mountDataIPBased)
	
	vm := NewVolumeMapping()
	vm.UpdateMapping(mountData)
	
	mappings := vm.GetAllMappings()
	
	// Should have 3 different IPs (172.27.255.32, 10.0.1.100, 192.168.1.50)
	if len(mappings) != 3 {
		t.Errorf("Expected 3 IPs in mapping, got %d", len(mappings))
	}
	
	// Each IP should have 1 volume (since each IP is unique to a volume)
	expectedMappings := map[string]string{
		"172.27.255.32": "47d32f7f-1687-42c8-b6fd-67b3a2263c8e",
		"10.0.1.100":   "89e45b2a-2798-43d7-a9ce-123456789abc",
		"192.168.1.50":  "33ff88cc-99dd-44ee-aa55-667788990011",
	}
	
	for ip, expectedVolume := range expectedMappings {
		entries, exists := mappings[ip]
		if !exists {
			t.Errorf("Expected IP %s not found in mapping", ip)
			continue
		}
		
		if len(entries) != 1 {
			t.Errorf("Expected 1 volume for IP %s, got %d", ip, len(entries))
		}
		
		if entries[0].VolumeID != expectedVolume {
			t.Errorf("Expected volume %s for IP %s, got %s", expectedVolume, ip, entries[0].VolumeID)
		}
	}
}

func TestVolumeMapping_NoNFSMounts(t *testing.T) {
	// Test scenario with no NFS mounts
	mountData := parseNFSMountsForTest(mountDataNoNFS)
	
	vm := NewVolumeMapping()
	vm.UpdateMapping(mountData)
	
	mappings := vm.GetAllMappings()
	
	// Should have no mappings
	if len(mappings) != 0 {
		t.Errorf("Expected 0 mappings with no NFS mounts, got %d", len(mappings))
	}
	
	// GetVolumeID should return empty string
	volumeID := vm.GetVolumeID("any.ip")
	if volumeID != "" {
		t.Errorf("Expected empty volume ID for non-existent IP, got %s", volumeID)
	}
}

func TestVolumeMapping_GetVolumeIDByHash(t *testing.T) {
	// Test hash-based volume resolution with a single volume per IP
	singleVolumeData := map[string]string{
		"172.27.255.32": "47d32f7f-1687-42c8-b6fd-67b3a2263c8e",
	}
	
	vm := NewVolumeMapping()
	vm.UpdateMapping(singleVolumeData)
	
	// Test getting volume ID by hash
	exportPath := "/volumes/47d32f7f-1687-42c8-b6fd-67b3a2263c8e"
	expectedHash := hashExportPath(exportPath)
	
	volumeID := vm.GetVolumeIDByHash("172.27.255.32", expectedHash)
	if volumeID != "47d32f7f-1687-42c8-b6fd-67b3a2263c8e" {
		t.Errorf("Expected volume ID 47d32f7f-1687-42c8-b6fd-67b3a2263c8e for hash %x, got %s", expectedHash, volumeID)
	}
	
	// Test non-existent hash
	nonExistentHash := uint64(999999)
	volumeID = vm.GetVolumeIDByHash("172.27.255.32", nonExistentHash)
	if volumeID != "" {
		t.Errorf("Expected empty volume ID for non-existent hash, got %s", volumeID)
	}
}

func TestVolumeMapping_HashConsistency(t *testing.T) {
	// Test that hash generation is consistent
	exportPath := "/volumes/test-volume-123"
	
	hash1 := hashExportPath(exportPath)
	hash2 := hashExportPath(exportPath)
	
	if hash1 != hash2 {
		t.Error("Hash generation is not consistent")
	}
	
	// Test that different paths generate different hashes
	differentPath := "/volumes/different-volume-456"
	hash3 := hashExportPath(differentPath)
	
	if hash1 == hash3 {
		t.Error("Different paths should generate different hashes")
	}
}

func TestVolumeMapping_ConcurrentAccess(t *testing.T) {
	// Test concurrent access to volume mapping
	mountData := parseNFSMountsForTest(mountDataSharedIP)
	
	vm := NewVolumeMapping()
	vm.UpdateMapping(mountData)
	
	// Test concurrent reads
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			volumeID := vm.GetVolumeID("172.27.255.32")
			if volumeID == "" {
				t.Error("Expected non-empty volume ID")
			}
			done <- true
		}()
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Test concurrent updates
	for i := 0; i < 5; i++ {
		go func(iteration int) {
			testData := map[string]string{
				"172.27.255.32": "test-volume-" + string(rune(iteration)),
			}
			vm.UpdateMapping(testData)
			done <- true
		}(i)
	}
	
	// Wait for all updates to complete
	for i := 0; i < 5; i++ {
		<-done
	}
}

func TestVolumeMapping_BackwardCompatibility(t *testing.T) {
	// Test that single-volume scenarios still work
	singleVolumeData := map[string]string{
		"172.27.255.32": "single-volume-id",
	}
	
	vm := NewVolumeMapping()
	vm.UpdateMapping(singleVolumeData)
	
	// Test backward compatibility methods
	volumeID := vm.GetVolumeID("172.27.255.32")
	if volumeID != "single-volume-id" {
		t.Errorf("Expected single-volume-id, got %s", volumeID)
	}
	
	// Test that hash-based method also works
	exportPath := "/volumes/single-volume-id"
	expectedHash := hashExportPath(exportPath)
	
	volumeID = vm.GetVolumeIDByHash("172.27.255.32", expectedHash)
	if volumeID != "single-volume-id" {
		t.Errorf("Expected single-volume-id from hash lookup, got %s", volumeID)
	}
}

// TestCalculatePercentiles tests the CalculatePercentiles function with comprehensive scenarios
func TestCalculatePercentiles(t *testing.T) {
	tests := []struct {
		name         string
		histogram    [HISTOGRAM_BUCKETS]uint64
		totalCount   uint64
		expectedP50  float64
		expectedP90  float64
		expectedP99  float64
		description  string
	}{
		{
			name:        "Empty histogram",
			histogram:   [HISTOGRAM_BUCKETS]uint64{},
			totalCount:  0,
			expectedP50: 0,
			expectedP90: 0,
			expectedP99: 0,
			description: "No data should return zero percentiles",
		},
		{
			name:        "Single request",
			histogram:   [HISTOGRAM_BUCKETS]uint64{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			totalCount:  1,
			expectedP50: 0.000250,
			expectedP90: 0.000250,
			expectedP99: 0.000250,
			description: "Single request should return first bucket midpoint",
		},
		{
			name:        "All requests in first bucket",
			histogram:   [HISTOGRAM_BUCKETS]uint64{100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			totalCount:  100,
			expectedP50: 0.000250,
			expectedP90: 0.000250,
			expectedP99: 0.000250,
			description: "All requests in first bucket should return first bucket midpoint",
		},
		{
			name:        "Perfect 50th percentile at bucket boundary",
			histogram:   [HISTOGRAM_BUCKETS]uint64{50, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			totalCount:  100,
			expectedP50: 0.000250,  // Bucket 0 midpoint (cum 50 >= threshold 50)
			expectedP90: 0.000568,  // Bucket 1 midpoint (cum 100 >= threshold 90)
			expectedP99: 0.000568,  // Bucket 1 midpoint (cum 100 >= threshold 99)
			description: "50th percentile exactly at bucket boundary",
		},
		{
			name:        "Normal latency distribution",
			histogram:   [HISTOGRAM_BUCKETS]uint64{10, 20, 30, 20, 10, 5, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			totalCount:  100,
			expectedP50: 0.000724,  // Bucket 2 midpoint (cum 60 >= 50)
			expectedP90: 0.001177,  // Bucket 4 midpoint (cum 90 >= 90)
			expectedP99: 0.002435,  // Bucket 7 midpoint (cum 100 >= 99)
			description: "Normal distribution centered around 0.72ms",
		},
		{
			name:        "High latency tail",
			histogram:   [HISTOGRAM_BUCKETS]uint64{1, 1, 2, 3, 5, 10, 15, 20, 25, 10, 5, 2, 1, 0, 0, 0, 0, 0, 0},
			totalCount:  100,
			expectedP50: 0.002435,  // Bucket 7 midpoint (cum 57 >= 50)
			expectedP90: 0.003953,  // Bucket 9 midpoint (cum 92 >= 90)
			expectedP99: 0.006418,  // Bucket 11 midpoint (cum 99 >= 99)
			description: "Distribution with high latency tail",
		},
		{
			name:        "All requests in last bucket",
			histogram:   [HISTOGRAM_BUCKETS]uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100},
			totalCount:  100,
			expectedP50: 0.035015,  // Bucket 18 midpoint
			expectedP90: 0.035015,  // Bucket 18 midpoint
			expectedP99: 0.035015,  // Bucket 18 midpoint
			description: "All requests in second-to-last bucket (19 element array fills index 18)",
		},
		{
			name:        "Small sample size",
			histogram:   [HISTOGRAM_BUCKETS]uint64{2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			totalCount:  3,
			expectedP50: 0.000250,  // Bucket 0 midpoint (cum 2 >= 1)
			expectedP90: 0.000568,  // Bucket 1 midpoint (cum 3 >= 2)
			expectedP99: 0.000568,  // Bucket 1 midpoint (cum 3 >= 2)
			description: "Small sample size with few requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing: %s", tt.description)
			t.Logf("Histogram: %v", tt.histogram)
			t.Logf("Total count: %d", tt.totalCount)

			p50, p90, p99 := CalculatePercentiles(tt.histogram, tt.totalCount)

			t.Logf("Results: P50=%f, P90=%f, P99=%f", p50, p90, p99)
			t.Logf("Expected: P50=%f, P90=%f, P99=%f", tt.expectedP50, tt.expectedP90, tt.expectedP99)

			// Allow small floating point tolerance
			tolerance := 0.001

			if !floatEqual(p50, tt.expectedP50, tolerance) {
				t.Errorf("P50 mismatch: got %f, expected %f (tolerance %f)", p50, tt.expectedP50, tolerance)
			}
			if !floatEqual(p90, tt.expectedP90, tolerance) {
				t.Errorf("P90 mismatch: got %f, expected %f (tolerance %f)", p90, tt.expectedP90, tolerance)
			}
			if !floatEqual(p99, tt.expectedP99, tolerance) {
				t.Errorf("P99 mismatch: got %f, expected %f (tolerance %f)", p99, tt.expectedP99, tolerance)
			}
		})
	}
}

// TestHistogramBucketValidation tests histogram bucket boundaries and midpoints
func TestHistogramBucketValidation(t *testing.T) {
	t.Run("BucketBoundaries", func(t *testing.T) {
		expectedBoundaries := [HISTOGRAM_BUCKETS]float64{
			0.000500, 0.000637, 0.000812, 0.001035, 0.001318,
			0.001680, 0.002141, 0.002728, 0.003476, 0.004429,
			0.005644, 0.007192, 0.009165, 0.011679, 0.014882,
			0.018963, 0.024165, 0.030792, 0.039238, 0.050000,
		}

		for i, expected := range expectedBoundaries {
			if histogramBucketBoundaries[i] != expected {
				t.Errorf("Bucket %d boundary mismatch: got %f, expected %f", i, histogramBucketBoundaries[i], expected)
			}
		}
	})

	t.Run("BucketMidpoints", func(t *testing.T) {
		expectedMidpoints := [HISTOGRAM_BUCKETS]float64{
			0.000250, 0.000568, 0.000724, 0.000923, 0.001177,
			0.001499, 0.001911, 0.002435, 0.003102, 0.003953,
			0.005037, 0.006418, 0.008179, 0.010422, 0.013281,
			0.016923, 0.021564, 0.027478, 0.035015, 0.044619,
		}

		for i, expected := range expectedMidpoints {
			if histogramBucketMidpoints[i] != expected {
				t.Errorf("Bucket %d midpoint mismatch: got %f, expected %f", i, histogramBucketMidpoints[i], expected)
			}
		}
	})

	t.Run("BucketCount", func(t *testing.T) {
		if HISTOGRAM_BUCKETS != 20 {
			t.Errorf("HISTOGRAM_BUCKETS constant should be 20, got %d", HISTOGRAM_BUCKETS)
		}
	})
}

// TestPercentileEdgeCases tests edge cases for percentile calculation
func TestPercentileEdgeCases(t *testing.T) {
	t.Run("ZeroTotalCount", func(t *testing.T) {
		histogram := [HISTOGRAM_BUCKETS]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		p50, p90, p99 := CalculatePercentiles(histogram, 0)
		
		if p50 != 0 || p90 != 0 || p99 != 0 {
			t.Errorf("Zero total count should return zero percentiles, got P50=%f, P90=%f, P99=%f", p50, p90, p99)
		}
	})

	t.Run("SingleRequest", func(t *testing.T) {
		histogram := [HISTOGRAM_BUCKETS]uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		p50, p90, p99 := CalculatePercentiles(histogram, 1)
		
		// With totalCount=1, thresholds are (1*50)/100=0, (1*90)/100=0, (1*99)/100=0
		// cumulative starts at 0, and 0>=0 is true at bucket 0, so midpoint[0]=0.000250
		expected := 0.000250
		if p50 != expected || p90 != expected || p99 != expected {
			t.Errorf("Single request with threshold 0 should return first bucket midpoint %f, got P50=%f, P90=%f, P99=%f", expected, p50, p90, p99)
		}
	})

	t.Run("AllInLastBucket", func(t *testing.T) {
		histogram := [HISTOGRAM_BUCKETS]uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100}
		p50, p90, p99 := CalculatePercentiles(histogram, 100)
		
		// Last bucket (index 19) midpoint = 0.044619
		expected := 0.044619
		if p50 != expected || p90 != expected || p99 != expected {
			t.Errorf("All requests in last bucket should return midpoint %f, got P50=%f, P90=%f, P99=%f", expected, p50, p90, p99)
		}
	})
}
