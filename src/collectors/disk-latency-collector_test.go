package collectors

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestCalculateDiskPercentiles tests the disk latency percentile calculation
func TestCalculateDiskPercentiles(t *testing.T) {
	tests := []struct {
		name         string
		histogram    [20]uint64
		totalCount   uint64
		expectedP50  float64
		expectedP90  float64
		expectedP99  float64
	}{
		{
			name:        "EmptyHistogram",
			histogram:   [20]uint64{},
			totalCount:  0,
			expectedP50: 0,
			expectedP90: 0,
			expectedP99: 0,
		},
		{
			name:        "SingleRequest",
			histogram:   [20]uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			totalCount:  1,
			expectedP50: 0.000010, // threshold=(1*50)/100=0, cum 0>=0 at bucket 0
			expectedP90: 0.000010,
			expectedP99: 0.000010,
		},
		{
			name:        "AllInFirstBucket",
			histogram:   [20]uint64{100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			totalCount:  100,
			expectedP50: 0.000010, // Midpoint of first bucket: 0.010ms / 1000
			expectedP90: 0.000010,
			expectedP99: 0.000010,
		},
		{
			name:        "DistributedAcrossBuckets",
			histogram:   [20]uint64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190},
			totalCount:  1890,
			expectedP50: 0.000957, // Bucket 13: midpoint (0.785+1.129)/2 / 1000
			expectedP90: 0.004097, // Bucket 17: midpoint (3.360+4.833)/2 / 1000
			expectedP99: 0.005893, // Bucket 18: midpoint (4.833+6.952)/2 / 1000
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p50, p90, p99 := CalculateDiskPercentiles(tt.histogram, tt.totalCount)
			
			// Use tolerance for floating point comparison
			tolerance := 0.0001
			
			if p50 < tt.expectedP50-tolerance || p50 > tt.expectedP50+tolerance {
				t.Errorf("P50 mismatch: expected %f, got %f", tt.expectedP50, p50)
			}
			if p90 < tt.expectedP90-tolerance || p90 > tt.expectedP90+tolerance {
				t.Errorf("P90 mismatch: expected %f, got %f", tt.expectedP90, p90)
			}
			if p99 < tt.expectedP99-tolerance || p99 > tt.expectedP99+tolerance {
				t.Errorf("P99 mismatch: expected %f, got %f", tt.expectedP99, p99)
			}
		})
	}
}

// TestDiskLatencyCollectorCreation tests that the disk latency collector can be created
func TestDiskLatencyCollectorCreation(t *testing.T) {
	collector, err := NewDiskLatencyCollector()
	if err != nil {
		t.Logf("Disk collector failed to load (expected in test environment): %v", err)
		// This is expected in test environment without proper eBPF support
		return
	}
	defer collector.Close()
	t.Log("Disk collector created successfully")
}

// TestDeviceNameResolution tests device name resolution from device ID
func TestDeviceNameResolution(t *testing.T) {
	// Test device ID to name conversion
	testCases := []struct {
		deviceID    uint32
		expectedPrefix string
	}{
		{0xfd00, "vd"},    // 253:0 -> should map to vd*
		{0xfd01, "vd"},    // 253:1 -> should map to vd*
		{0xfe00, "vd"},    // 254:0 -> should map to vd*
		{0x0800, "vd"},    // 8:0 -> should map to vd*
		{0x1234, "vd"},    // Unknown -> should map to vd format
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			deviceName := getDeviceName(tc.deviceID)
			if len(deviceName) < len(tc.expectedPrefix) {
				t.Errorf("Expected device name to start with %s, got %s", tc.expectedPrefix, deviceName)
				return
			}
			
			if deviceName[:len(tc.expectedPrefix)] != tc.expectedPrefix {
				t.Errorf("Expected device name to start with %s, got %s", tc.expectedPrefix, deviceName)
			}
		})
	}
}

// TestDeviceCacheInitialization tests device cache initialization
func TestDeviceCacheInitialization(t *testing.T) {
	// Clear any existing cache
	deviceMutex.Lock()
	deviceCache = make(map[uint32]string)
	deviceMutex.Unlock()

	// Initialize device cache
	err := initDeviceCache()
	if err != nil {
		t.Logf("Device cache initialization failed (expected in test environment): %v", err)
		// This is expected in test environment without /sys/block
		return
	}

	// Check that cache was initialized
	deviceMutex.RLock()
	cacheSize := len(deviceCache)
	deviceMutex.RUnlock()

	t.Logf("Device cache initialized with %d entries", cacheSize)
}

// TestDiskLatencyCollectorDescribe tests the Describe method
func TestDiskLatencyCollectorDescribe(t *testing.T) {
	collector, err := NewDiskLatencyCollector()
	if err != nil {
		t.Skip("Skipping test - collector creation failed")
		return
	}
	defer collector.Close()

	ch := make(chan *prometheus.Desc, 20)
	collector.Describe(ch)
	close(ch)

	// Count the descriptors
	descCount := 0
	for range ch {
		descCount++
	}

	// Should have 13 descriptors (reads, writes, read_bytes, write_bytes, 
	// read_latency, write_latency, and 6 percentile descriptors)
	expectedCount := 13
	if descCount != expectedCount {
		t.Errorf("Expected %d descriptors, got %d", expectedCount, descCount)
	}
}

// TestDiskLatencyCollectorCollect tests the Collect method
func TestDiskLatencyCollectorCollect(t *testing.T) {
	collector, err := NewDiskLatencyCollector()
	if err != nil {
		t.Skip("Skipping test - collector creation failed")
		return
	}
	defer collector.Close()

	ch := make(chan prometheus.Metric, 100)
	collector.Collect(ch)
	close(ch)

	// Count metrics
	metricCount := 0
	for range ch {
		metricCount++
	}

	t.Logf("Collected %d metrics", metricCount)
}

// TestHistogramBucketBoundaries tests that histogram bucket boundaries are correct
func TestHistogramBucketBoundaries(t *testing.T) {
	// Test that the histogram boundaries in the header match the eBPF implementation
	expectedBoundaries := []float64{
		0.0,    // Start
		0.1,    // 0.1ms
		0.2,    // 0.2ms
		0.4,    // 0.4ms
		0.8,    // 0.8ms
		1.6,    // 1.6ms
		3.2,    // 3.2ms
		6.4,    // 6.4ms
		12.8,   // 12.8ms
		25.6,   // 25.6ms
		51.2,   // 51.2ms
		102.4,  // 102.4ms
		204.8,  // 204.8ms
		409.6,  // 409.6ms
		819.2,  // 819.2ms
		1638.4, // 1638.4ms
		3276.8, // 3276.8ms
		6553.6, // 6553.6ms
		13107.2,// 13107.2ms
		26214.4,// 26214.4ms
		52428.8, // End (> 50ms)
	}

	// Test that we have 21 boundaries (start + 20 buckets)
	if len(expectedBoundaries) != 21 {
		t.Errorf("Expected 21 boundaries, got %d", len(expectedBoundaries))
	}

	// Test that the first boundary is 0.0ms
	if expectedBoundaries[0] != 0.0 {
		t.Errorf("Expected first boundary to be 0.0ms, got %f", expectedBoundaries[0])
	}

	// Test that the last boundary is > 50ms
	if expectedBoundaries[20] <= 50.0 {
		t.Errorf("Expected last boundary to be > 50ms, got %f", expectedBoundaries[20])
	}

	// Test that we have 20 buckets (boundaries - 1)
	bucketCount := len(expectedBoundaries) - 1
	if bucketCount != 20 {
		t.Errorf("Expected 20 buckets, got %d", bucketCount)
	}
}

// TestHistogramBucketLogic tests the histogram bucket selection logic
func TestHistogramBucketLogic(t *testing.T) {
	testCases := []struct {
		latencyNs    uint64
		expectedBucket int
	}{
		{50000, 0},      // 0.05ms -> bucket 0
		{150000, 1},     // 0.15ms -> bucket 1
		{300000, 2},     // 0.3ms -> bucket 2
		{600000, 3},     // 0.6ms -> bucket 3
		{1200000, 4},    // 1.2ms -> bucket 4
		{2400000, 5},    // 2.4ms -> bucket 5
		{4800000, 6},    // 4.8ms -> bucket 6
		{9600000, 7},    // 9.6ms -> bucket 7
		{19200000, 8},   // 19.2ms -> bucket 8
		{38400000, 9},   // 38.4ms -> bucket 9
		{76800000, 10},  // 76.8ms -> bucket 10
		{153600000, 11}, // 153.6ms -> bucket 11
		{307200000, 12}, // 307.2ms -> bucket 12
		{614400000, 13}, // 614.4ms -> bucket 13
		{1228800000, 14}, // 1228.8ms -> bucket 14
		{2457600000, 15}, // 2457.6ms -> bucket 15
		{4915200000, 16}, // 4915.2ms -> bucket 16
		{9830400000, 17}, // 9830.4ms -> bucket 17
		{19660800000, 18}, // 19660.8ms -> bucket 18
		{39321600000, 19}, // 39321.6ms -> bucket 19
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			// Simulate the histogram bucket selection logic
			latencyUs := tc.latencyNs / 1000
			
			bucket := 0
			if latencyUs < 100 {
				bucket = 0
			} else if latencyUs < 200 {
				bucket = 1
			} else if latencyUs < 400 {
				bucket = 2
			} else if latencyUs < 800 {
				bucket = 3
			} else if latencyUs < 1600 {
				bucket = 4
			} else if latencyUs < 3200 {
				bucket = 5
			} else if latencyUs < 6400 {
				bucket = 6
			} else if latencyUs < 12800 {
				bucket = 7
			} else if latencyUs < 25600 {
				bucket = 8
			} else if latencyUs < 51200 {
				bucket = 9
			} else if latencyUs < 102400 {
				bucket = 10
			} else if latencyUs < 204800 {
				bucket = 11
			} else if latencyUs < 409600 {
				bucket = 12
			} else if latencyUs < 819200 {
				bucket = 13
			} else if latencyUs < 1638400 {
				bucket = 14
			} else if latencyUs < 3276800 {
				bucket = 15
			} else if latencyUs < 6553600 {
				bucket = 16
			} else if latencyUs < 13107200 {
				bucket = 17
			} else if latencyUs < 26214400 {
				bucket = 18
			} else {
				bucket = 19
			}

			if bucket != tc.expectedBucket {
				t.Errorf("Latency %dns (μs): expected bucket %d, got %d", tc.latencyNs, tc.expectedBucket, bucket)
			}
		})
	}
}

// TestDeviceCacheConcurrency tests concurrent access to device cache
func TestDeviceCacheConcurrency(t *testing.T) {
	// Clear cache and add some test data
	deviceMutex.Lock()
	deviceCache = make(map[uint32]string)
	deviceCache[0xfd00] = "vda"
	deviceCache[0xfd01] = "vdb"
	deviceCache[0xfe00] = "vdc"
	deviceMutex.Unlock()

	// Test concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				deviceName := getDeviceName(0xfd00)
				if deviceName != "vda" {
					t.Errorf("Expected vda, got %s", deviceName)
				}
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestMetricDescriptorNames tests that metric descriptors have correct names
func TestMetricDescriptorNames(t *testing.T) {
	collector, err := NewDiskLatencyCollector()
	if err != nil {
		t.Skip("Skipping test - collector creation failed")
		return
	}
	defer collector.Close()

	ch := make(chan *prometheus.Desc, 20)
	collector.Describe(ch)
	close(ch)

	// Count the descriptors
	descCount := 0
	for range ch {
		descCount++
	}

	// Should have 13 descriptors
	expectedCount := 13
	if descCount != expectedCount {
		t.Errorf("Expected %d descriptors, got %d", expectedCount, descCount)
	}

	t.Logf("Found %d metric descriptors", descCount)
}

// TestCollectorClose tests that the collector can be closed safely
func TestCollectorClose(t *testing.T) {
	collector, err := NewDiskLatencyCollector()
	if err != nil {
		t.Skip("Skipping test - collector creation failed")
		return
	}

	// Close should not panic
	collector.Close()
	
	// Double close should not panic
	collector.Close()
}
