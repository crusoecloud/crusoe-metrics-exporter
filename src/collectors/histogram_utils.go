package collectors

import (
	"net"
	"sync"
)

// Histogram buckets for latency distribution
const HISTOGRAM_BUCKETS = 20

// NFS histogram bucket upper boundaries in seconds.
// 20 geometric buckets from 0.5ms to 50ms.
// Must match the eBPF bucket boundaries in nfs_latency.c.
var histogramBucketBoundaries = [HISTOGRAM_BUCKETS]float64{
	0.000500, // 0.50ms
	0.000637, // 0.64ms
	0.000812, // 0.81ms
	0.001035, // 1.04ms
	0.001318, // 1.32ms
	0.001680, // 1.68ms
	0.002141, // 2.14ms
	0.002728, // 2.73ms
	0.003476, // 3.48ms
	0.004429, // 4.43ms
	0.005644, // 5.64ms
	0.007192, // 7.19ms
	0.009165, // 9.17ms
	0.011679, // 11.68ms
	0.014882, // 14.88ms
	0.018963, // 18.96ms
	0.024165, // 24.17ms
	0.030792, // 30.79ms
	0.039238, // 39.24ms
	0.050000, // 50ms
}

// NFS bucket midpoints in seconds for percentile estimation
var histogramBucketMidpoints = [HISTOGRAM_BUCKETS]float64{
	0.000250, // 0.25ms (midpoint of <0.50ms)
	0.000568, // 0.57ms (midpoint of 0.50-0.64ms)
	0.000724, // 0.72ms (midpoint of 0.64-0.81ms)
	0.000923, // 0.92ms (midpoint of 0.81-1.04ms)
	0.001177, // 1.18ms (midpoint of 1.04-1.32ms)
	0.001499, // 1.50ms (midpoint of 1.32-1.68ms)
	0.001911, // 1.91ms (midpoint of 1.68-2.14ms)
	0.002435, // 2.44ms (midpoint of 2.14-2.73ms)
	0.003102, // 3.10ms (midpoint of 2.73-3.48ms)
	0.003953, // 3.95ms (midpoint of 3.48-4.43ms)
	0.005037, // 5.04ms (midpoint of 4.43-5.64ms)
	0.006418, // 6.42ms (midpoint of 5.64-7.19ms)
	0.008179, // 8.18ms (midpoint of 7.19-9.17ms)
	0.010422, // 10.42ms (midpoint of 9.17-11.68ms)
	0.013281, // 13.28ms (midpoint of 11.68-14.88ms)
	0.016923, // 16.92ms (midpoint of 14.88-18.96ms)
	0.021564, // 21.56ms (midpoint of 18.96-24.17ms)
	0.027478, // 27.48ms (midpoint of 24.17-30.79ms)
	0.035015, // 35.02ms (midpoint of 30.79-39.24ms)
	0.044619, // 44.62ms (midpoint of 39.24-50ms)
}

// CalculatePercentiles computes p50, p90, and p99 latencies from histogram buckets
// This is a shared function used by all latency collectors
func CalculatePercentiles(histogram [HISTOGRAM_BUCKETS]uint64, totalCount uint64) (p50, p90, p99 float64) {
	if totalCount == 0 {
		return 0, 0, 0
	}

	p50Threshold := (totalCount * 50) / 100
	p90Threshold := (totalCount * 90) / 100
	p99Threshold := (totalCount * 99) / 100

	var cumulative uint64
	p50Found := false
	p90Found := false
	p99Found := false

	for i := 0; i < HISTOGRAM_BUCKETS; i++ {
		cumulative += histogram[i]

		if !p50Found && cumulative >= p50Threshold {
			p50 = histogramBucketMidpoints[i]
			p50Found = true
		}

		if !p90Found && cumulative >= p90Threshold {
			p90 = histogramBucketMidpoints[i]
			p90Found = true
		}

		if !p99Found && cumulative >= p99Threshold {
			p99 = histogramBucketMidpoints[i]
			p99Found = true
		}

		if p50Found && p90Found && p99Found {
			break
		}
	}

	// If percentiles not found in histogram, use last bucket boundary
	if !p50Found {
		p50 = histogramBucketBoundaries[HISTOGRAM_BUCKETS-1]
	}
	if !p90Found {
		p90 = histogramBucketBoundaries[HISTOGRAM_BUCKETS-1]
	}
	if !p99Found {
		p99 = histogramBucketBoundaries[HISTOGRAM_BUCKETS-1]
	}

	return p50, p90, p99
}

// VolumeMapping represents a mapping from server IP to multiple volume IDs
type VolumeMapping struct {
	mapping map[string][]VolumeEntry // IP -> list of volumes
	mutex   sync.RWMutex
}

// VolumeEntry represents a single volume with its export path and ID
type VolumeEntry struct {
	ExportPath     string // e.g., "/volumes/vol-123-abc"
	VolumeID       string // e.g., "vol-123-abc"
	ExportPathHash uint64 // Hash of export path for eBPF correlation
}

// NewVolumeMapping creates a new volume mapping
func NewVolumeMapping() *VolumeMapping {
	return &VolumeMapping{
		mapping: make(map[string][]VolumeEntry),
	}
}

// UpdateMapping updates the volume mapping with new data from /proc/mounts
func (vm *VolumeMapping) UpdateMapping(newMapping map[string]string) {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// Convert simple IP->volume mapping to IP->[]VolumeEntry
	vm.mapping = make(map[string][]VolumeEntry)

	for ip, volumeID := range newMapping {
		// Create export path from volume ID
		exportPath := "/volumes/" + volumeID
		exportPathHash := hashExportPath(exportPath)

		entry := VolumeEntry{
			ExportPath:     exportPath,
			VolumeID:       volumeID,
			ExportPathHash: exportPathHash,
		}

		vm.mapping[ip] = append(vm.mapping[ip], entry)
	}
}

// GetVolumeID returns the volume ID for a given IP (fallback for single volume)
func (vm *VolumeMapping) GetVolumeID(ip string) string {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	entries := vm.mapping[ip]
	if len(entries) == 0 {
		return ""
	}

	// Return the first volume ID for backward compatibility
	return entries[0].VolumeID
}

// GetVolumeIDByHash returns the volume ID for a given IP and export path hash
func (vm *VolumeMapping) GetVolumeIDByHash(ip string, exportPathHash uint64) string {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	entries := vm.mapping[ip]
	for _, entry := range entries {
		if entry.ExportPathHash == exportPathHash {
			return entry.VolumeID
		}
	}

	return ""
}

// GetAllMappings returns a copy of all mappings
func (vm *VolumeMapping) GetAllMappings() map[string][]VolumeEntry {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	result := make(map[string][]VolumeEntry, len(vm.mapping))
	for k, v := range vm.mapping {
		result[k] = append([]VolumeEntry{}, v...)
	}
	return result
}

// hashExportPath creates a hash of the export path (same algorithm as eBPF)
func hashExportPath(path string) uint64 {
	hash := uint64(5381) // DJB2 hash algorithm
	for _, char := range path {
		hash = ((hash << 5) + hash) + uint64(char) // hash * 33 + char
	}
	return hash
}

// Disk latency histogram bucket upper bounds in seconds.
// 20 geometric buckets from 10us to 10ms.
// Must match the eBPF bucket boundaries in disk_latency.c.
var diskHistogramBucketBoundaries = [20]float64{
	0.000010, 0.000014, 0.000021, 0.000030, 0.000043,
	0.000062, 0.000089, 0.000127, 0.000183, 0.000264,
	0.000379, 0.000546, 0.000785, 0.001129, 0.001624,
	0.002336, 0.003360, 0.004833, 0.006952, 0.010000,
}

// Object store latency histogram bucket upper bounds in seconds.
// 20 geometric buckets from 1ms to 1000ms (ratio ~1.468).
// Must match the eBPF bucket boundaries in objstore_latency.c.
var objstoreHistogramBucketBoundaries = [20]float64{
	0.001000, 0.001468, 0.002154, 0.003162, 0.004642,
	0.006813, 0.010000, 0.014678, 0.021544, 0.031623,
	0.046416, 0.068129, 0.100000, 0.146780, 0.215443,
	0.316228, 0.464159, 0.681292, 1.000000, 1.468000,
}

// histogramToBuckets converts a fixed-size eBPF histogram array and its
// bucket upper-bound array into the cumulative bucket map expected by
// prometheus.MustNewConstHistogram.  It also returns the total count and
// an approximate sum (using bucket midpoints).
func histogramToBuckets(histogram [HISTOGRAM_BUCKETS]uint64, boundaries [HISTOGRAM_BUCKETS]float64) (buckets map[float64]uint64, count uint64, sum float64) {
	buckets = make(map[float64]uint64, HISTOGRAM_BUCKETS)
	var cumulative uint64
	for i := 0; i < HISTOGRAM_BUCKETS; i++ {
		cumulative += histogram[i]
		buckets[boundaries[i]] = cumulative

		// Estimate sum using bucket midpoints
		var midpoint float64
		if i == 0 {
			midpoint = boundaries[i] / 2
		} else {
			midpoint = (boundaries[i-1] + boundaries[i]) / 2
		}
		sum += float64(histogram[i]) * midpoint
	}
	count = cumulative
	return
}

// ipUint32ToString converts a uint32 IP address to a string
func ipUint32ToString(ip uint32) string {
	ipBytes := make([]byte, 4)
	ipBytes[0] = byte(ip & 0xFF)
	ipBytes[1] = byte((ip >> 8) & 0xFF)
	ipBytes[2] = byte((ip >> 16) & 0xFF)
	ipBytes[3] = byte((ip >> 24) & 0xFF)
	return net.IP(ipBytes).String()
}
