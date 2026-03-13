package collectors

import (
	"bytes"
	_ "embed"
	"fmt"
	"metrics-exporter/src/log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
)

//go:embed ebpf/disk_latency.o
var diskLatencyBPF []byte

// DiskLatencyCollector monitors disk I/O latency and throughput using eBPF tracepoints
type DiskLatencyCollector struct {
	objs             *ebpf.Collection
	ioStartLink      link.Link
	ioDoneLink       link.Link
	readsDesc        *prometheus.Desc
	writesDesc       *prometheus.Desc
	readBytesDesc    *prometheus.Desc
	writeBytesDesc   *prometheus.Desc
	readLatencyDesc  *prometheus.Desc
	writeLatencyDesc *prometheus.Desc
	readHistDesc     *prometheus.Desc
	writeHistDesc    *prometheus.Desc
	collectionErrors *prometheus.Desc
}

var (
	deviceCache = make(map[uint32]string)
	deviceMutex sync.RWMutex
)

// NewDiskLatencyCollector creates a new disk latency collector using eBPF
func NewDiskLatencyCollector() (*DiskLatencyCollector, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warnf("failed to remove memory limit: %v", err)
	}

	// Load eBPF collection
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(diskLatencyBPF))
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF collection: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	// Attach kprobes for block I/O tracking
	ioStartProg := coll.Programs["io_start"]
	if ioStartProg == nil {
		coll.Close()
		return nil, fmt.Errorf("io_start program not found in eBPF collection")
	}
	ioStartLink, err := link.Kprobe("blk_mq_start_request", ioStartProg, nil)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to attach kprobe to blk_mq_start_request: %w", err)
	}

	ioDoneProg := coll.Programs["io_done"]
	if ioDoneProg == nil {
		ioStartLink.Close()
		coll.Close()
		return nil, fmt.Errorf("io_done program not found in eBPF collection")
	}
	ioDoneLink, err := link.Kprobe("blk_mq_end_request", ioDoneProg, nil)
	if err != nil {
		ioStartLink.Close()
		coll.Close()
		return nil, fmt.Errorf("failed to attach kprobe to blk_mq_end_request: %w", err)
	}

	log.Infof("Successfully attached disk I/O kprobes to blk_mq_start_request and blk_mq_end_request")

	// Initialize device cache
	if err := initDeviceCache(); err != nil {
		log.Warnf("failed to initialize device cache: %v", err)
	}

	collector := &DiskLatencyCollector{
		objs:        coll,
		ioStartLink: ioStartLink,
		ioDoneLink:  ioDoneLink,
		readsDesc: prometheus.NewDesc(
			MetricPrefix+"disk_reads_completed_total",
			"Total number of disk read operations completed",
			[]string{"device"},
			nil,
		),
		writesDesc: prometheus.NewDesc(
			MetricPrefix+"disk_writes_completed_total",
			"Total number of disk write operations completed",
			[]string{"device"},
			nil,
		),
		readBytesDesc: prometheus.NewDesc(
			MetricPrefix+"disk_read_bytes_total",
			"Total bytes read from disk",
			[]string{"device"},
			nil,
		),
		writeBytesDesc: prometheus.NewDesc(
			MetricPrefix+"disk_write_bytes_total",
			"Total bytes written to disk",
			[]string{"device"},
			nil,
		),
		readLatencyDesc: prometheus.NewDesc(
			MetricPrefix+"disk_read_latency_seconds_total",
			"Total time spent reading from disk in seconds",
			[]string{"device"},
			nil,
		),
		writeLatencyDesc: prometheus.NewDesc(
			MetricPrefix+"disk_write_latency_seconds_total",
			"Total time spent writing to disk in seconds",
			[]string{"device"},
			nil,
		),
		readHistDesc: prometheus.NewDesc(
			MetricPrefix+"disk_read_latency_seconds",
			"Histogram of disk read latency in seconds",
			[]string{"device"},
			nil,
		),
		writeHistDesc: prometheus.NewDesc(
			MetricPrefix+"disk_write_latency_seconds",
			"Histogram of disk write latency in seconds",
			[]string{"device"},
			nil,
		),
		collectionErrors: prometheus.NewDesc(
			MetricPrefix+"disk_collection_errors_total",
			"Total number of errors during disk stats collection",
			nil,
			nil,
		),
	}

	return collector, nil
}

// initDeviceCache initializes the device cache by scanning /sys/block
func initDeviceCache() error {
	deviceMutex.Lock()
	defer deviceMutex.Unlock()

	sysBlockPath := "/sys/block"
	entries, err := os.ReadDir(sysBlockPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", sysBlockPath, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		deviceName := entry.Name()
		// Only process virtual disks (vd*)
		if !strings.HasPrefix(deviceName, "vd") {
			continue
		}

		// Read major and minor numbers
		devPath := filepath.Join(sysBlockPath, deviceName, "dev")
		devData, err := os.ReadFile(devPath)
		if err != nil {
			log.Warnf("failed to read %s: %v", devPath, err)
			continue
		}

		var major, minor uint32
		_, err = fmt.Sscanf(string(devData), "%d:%d", &major, &minor)
		if err != nil {
			log.Warnf("failed to parse device numbers for %s: %v", deviceName, err)
			continue
		}

		// Combine major and minor into device ID (same as eBPF)
		deviceID := (major << 8) | (minor & 0xFF)
		deviceCache[deviceID] = deviceName
	}

	log.Infof("Initialized device cache with %d virtual disks", len(deviceCache))
	return nil
}

// getDeviceName returns the device name for a given device ID
func getDeviceName(deviceID uint32) string {
	deviceMutex.RLock()
	defer deviceMutex.RUnlock()

	if name, exists := deviceCache[deviceID]; exists {
		return name
	}

	// If not in cache, try to resolve it dynamically
	major := deviceID >> 8
	minor := deviceID & 0xFF

	// Try to find the device in /sys/block
	sysBlockPath := "/sys/block"
	entries, err := os.ReadDir(sysBlockPath)
	if err != nil {
		return fmt.Sprintf("vd%d:%d", major, minor)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		deviceName := entry.Name()
		if !strings.HasPrefix(deviceName, "vd") {
			continue
		}

		devPath := filepath.Join(sysBlockPath, deviceName, "dev")
		devData, err := os.ReadFile(devPath)
		if err != nil {
			continue
		}

		var devMajor, devMinor uint32
		_, err = fmt.Sscanf(string(devData), "%d:%d", &devMajor, &devMinor)
		if err != nil {
			continue
		}

		if devMajor == major && devMinor == minor {
			// Cache the result
			deviceMutex.Lock()
			deviceCache[deviceID] = deviceName
			deviceMutex.Unlock()
			return deviceName
		}
	}

	return fmt.Sprintf("vd%d:%d", major, minor)
}

// CalculatePercentiles calculates percentiles from histogram data
func CalculateDiskPercentiles(histogram [20]uint64, totalOps uint64) (p50, p90, p99 float64) {
	if totalOps == 0 {
		return 0, 0, 0
	}

	// Disk latency histogram bucket boundaries (in milliseconds)
	// 20 geometric buckets from 10us (0.01ms) to 10ms
	boundaries := [20]float64{
		0.010, 0.014, 0.021, 0.030, 0.043,
		0.062, 0.089, 0.127, 0.183, 0.264,
		0.379, 0.546, 0.785, 1.129, 1.624,
		2.336, 3.360, 4.833, 6.952, 10.000,
	}

	// Calculate cumulative counts
	var cumulative uint64
	for i, count := range histogram {
		cumulative += count

		// Calculate percentile using bucket midpoint
		midpoint := boundaries[i]
		if i > 0 {
			midpoint = (boundaries[i-1] + boundaries[i]) / 2
		}

		// Convert to seconds for Prometheus
		midpointSeconds := midpoint / 1000.0

		// Check if we've reached the percentiles
		if p50 == 0 && cumulative >= totalOps*50/100 {
			p50 = midpointSeconds
		}
		if p90 == 0 && cumulative >= totalOps*90/100 {
			p90 = midpointSeconds
		}
		if p99 == 0 && cumulative >= totalOps*99/100 {
			p99 = midpointSeconds
			break
		}
	}

	// If we didn't find a percentile, use the last bucket
	if p50 == 0 && totalOps > 0 {
		p50 = boundaries[19] / 1000.0
	}
	if p90 == 0 && totalOps > 0 {
		p90 = boundaries[19] / 1000.0
	}
	if p99 == 0 && totalOps > 0 {
		p99 = boundaries[19] / 1000.0
	}

	return p50, p90, p99
}

// Describe implements prometheus.Collector
func (c *DiskLatencyCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.readsDesc
	ch <- c.writesDesc
	ch <- c.readBytesDesc
	ch <- c.writeBytesDesc
	ch <- c.readLatencyDesc
	ch <- c.writeLatencyDesc
	ch <- c.readHistDesc
	ch <- c.writeHistDesc
	ch <- c.collectionErrors
}

// Collect implements prometheus.Collector
func (c *DiskLatencyCollector) Collect(ch chan<- prometheus.Metric) {
	// Get the disk_io_stats map from the eBPF collection
	statsMap := c.objs.Maps["disk_io_stats"]
	if statsMap == nil {
		log.Errorf("disk_io_stats map not found in eBPF collection")
		ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, 1)
		return
	}

	// Iterate over all entries in the map
	var key uint32
	var value struct {
		ReadCount           uint64
		WriteCount          uint64
		ReadBytes           uint64
		WriteBytes          uint64
		TotalReadLatencyNs  uint64
		TotalWriteLatencyNs uint64
		ReadHistogram       [20]uint64
		WriteHistogram      [20]uint64
	}

	totalEntries := 0
	filteredEntries := 0
	iter := statsMap.Iterate()
	for iter.Next(&key, &value) {
		totalEntries++

		// Get device name from device ID
		deviceName := getDeviceName(key)

		// Only process virtual disks (should already be filtered by eBPF, but double-check)
		if !strings.HasPrefix(deviceName, "vd") {
			filteredEntries++
			continue
		}

		// Convert nanoseconds to seconds (Prometheus standard)
		readLatencySeconds := float64(value.TotalReadLatencyNs) / 1e9
		writeLatencySeconds := float64(value.TotalWriteLatencyNs) / 1e9

		// Emit basic metrics
		ch <- prometheus.MustNewConstMetric(
			c.readsDesc,
			prometheus.CounterValue,
			float64(value.ReadCount),
			deviceName,
		)

		ch <- prometheus.MustNewConstMetric(
			c.writesDesc,
			prometheus.CounterValue,
			float64(value.WriteCount),
			deviceName,
		)

		ch <- prometheus.MustNewConstMetric(
			c.readBytesDesc,
			prometheus.CounterValue,
			float64(value.ReadBytes),
			deviceName,
		)

		ch <- prometheus.MustNewConstMetric(
			c.writeBytesDesc,
			prometheus.CounterValue,
			float64(value.WriteBytes),
			deviceName,
		)

		ch <- prometheus.MustNewConstMetric(
			c.readLatencyDesc,
			prometheus.CounterValue,
			readLatencySeconds,
			deviceName,
		)

		ch <- prometheus.MustNewConstMetric(
			c.writeLatencyDesc,
			prometheus.CounterValue,
			writeLatencySeconds,
			deviceName,
		)

		// Emit read histogram
		if value.ReadCount > 0 {
			readBuckets, readCount, readSum := histogramToBuckets(value.ReadHistogram, diskHistogramBucketBoundaries)
			ch <- prometheus.MustNewConstHistogram(
				c.readHistDesc,
				readCount,
				readSum,
				readBuckets,
				deviceName,
			)
		}

		// Emit write histogram
		if value.WriteCount > 0 {
			writeBuckets, writeCount, writeSum := histogramToBuckets(value.WriteHistogram, diskHistogramBucketBoundaries)
			ch <- prometheus.MustNewConstHistogram(
				c.writeHistDesc,
				writeCount,
				writeSum,
				writeBuckets,
				deviceName,
			)
		}
	}

	if err := iter.Err(); err != nil {
		log.Errorf("Error iterating over disk_io_stats map: %v", err)
		ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, 1)
		return
	}

	log.Debugf("Disk metrics collection: %d total entries, %d filtered out, %d emitted",
		totalEntries, filteredEntries, totalEntries-filteredEntries)
}

// Close cleans up the eBPF resources
func (c *DiskLatencyCollector) Close() {
	if c.ioStartLink != nil {
		c.ioStartLink.Close()
	}
	if c.ioDoneLink != nil {
		c.ioDoneLink.Close()
	}
	if c.objs != nil {
		c.objs.Close()
	}
}
