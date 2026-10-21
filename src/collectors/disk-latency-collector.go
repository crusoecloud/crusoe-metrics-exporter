package collectors

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"metrics-exporter/src/log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
)

//go:embed ebpf/disk_latency.o
var diskLatencyBPF []byte

// DiskLatencyCollector monitors disk I/O latency and throughput using one eBPF
// tracepoint at request completion (block_rq_complete). The program reads the
// request's own start timestamp, so there is no in-flight map and nothing runs
// at issue time.
type DiskLatencyCollector struct {
	objs             *ebpf.Collection
	ioDoneLink       link.Link
	readsDesc        *prometheus.Desc
	writesDesc       *prometheus.Desc
	readBytesDesc    *prometheus.Desc
	writeBytesDesc   *prometheus.Desc
	readLatencyDesc  *prometheus.Desc
	writeLatencyDesc *prometheus.Desc
	readHistDesc     *prometheus.Desc
	writeHistDesc    *prometheus.Desc
	readErrorsDesc   *prometheus.Desc
	writeErrorsDesc  *prometheus.Desc
	allocTsDesc      *prometheus.Desc
	collectionErrors *prometheus.Desc
}

// diskLatencyStats mirrors struct disk_latency_stats in ebpf/disk_latency.c.
// disk_io_stats is a per-CPU map, so each lookup returns one of these per CPU.
type diskLatencyStats struct {
	ReadCount           uint64
	WriteCount          uint64
	ReadBytes           uint64
	WriteBytes          uint64
	TotalReadLatencyNs  uint64
	TotalWriteLatencyNs uint64
	ReadHistogram       [20]uint64
	WriteHistogram      [20]uint64
	ReadErrorCount      uint64
	WriteErrorCount     uint64
	AllocTsCount        uint64 // completions timed from request allocation (no dispatch timestamp)
}

// sumDiskStats adds up the per-CPU copies of one device's stats.
func sumDiskStats(perCPU []diskLatencyStats) diskLatencyStats {
	var t diskLatencyStats
	for _, v := range perCPU {
		t.ReadCount += v.ReadCount
		t.WriteCount += v.WriteCount
		t.ReadBytes += v.ReadBytes
		t.WriteBytes += v.WriteBytes
		t.TotalReadLatencyNs += v.TotalReadLatencyNs
		t.TotalWriteLatencyNs += v.TotalWriteLatencyNs
		for i := range v.ReadHistogram {
			t.ReadHistogram[i] += v.ReadHistogram[i]
			t.WriteHistogram[i] += v.WriteHistogram[i]
		}
		t.ReadErrorCount += v.ReadErrorCount
		t.WriteErrorCount += v.WriteErrorCount
		t.AllocTsCount += v.AllocTsCount
	}
	return t
}

// parseVirtioBlkMajor returns the major number of the "virtblk" driver from
// the "Block devices:" section of /proc/devices, or 0 if it isn't listed.
// virtio-blk's major is allocated at boot, so it can't be hardcoded.
func parseVirtioBlkMajor(r io.Reader) uint32 {
	sc := bufio.NewScanner(r)
	inBlock := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "Block devices:") {
			inBlock = true
			continue
		}
		if strings.HasSuffix(line, "devices:") {
			inBlock = false
			continue
		}
		fields := strings.Fields(line)
		if inBlock && len(fields) == 2 && fields[1] == "virtblk" {
			if n, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
				return uint32(n)
			}
		}
	}
	return 0
}

// virtioBlkMajor reads parseVirtioBlkMajor from the host's /proc/devices.
func virtioBlkMajor() uint32 {
	procPath := os.Getenv("HOST_PROC_PATH")
	if procPath == "" {
		procPath = "/proc"
	}
	f, err := os.Open(filepath.Join(procPath, "devices"))
	if err != nil {
		log.Warnf("failed to read %s/devices: %v", procPath, err)
		return 0
	}
	defer f.Close()
	return parseVirtioBlkMajor(f)
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

	// Count only virtio disks in the kernel: the collector reports vd* only, and
	// skipping other devices (local NVMe) keeps them off this program entirely.
	major := virtioBlkMajor()
	if major == 0 {
		log.Warnf("virtblk major not found in /proc/devices; counting all block devices")
	}
	if err := spec.RewriteConstants(map[string]interface{}{"vd_major": major}); err != nil {
		return nil, fmt.Errorf("failed to set vd_major: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	ioDoneProg := coll.Programs["io_done"]
	if ioDoneProg == nil {
		coll.Close()
		return nil, fmt.Errorf("io_done program not found in eBPF collection")
	}
	ioDoneLink, err := link.AttachTracing(link.TracingOptions{Program: ioDoneProg})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to attach tp_btf/block_rq_complete: %w", err)
	}

	log.Infof("Attached disk I/O latency to tracepoint block_rq_complete (virtblk major %d)", major)

	// Initialize device cache
	if err := initDeviceCache(); err != nil {
		log.Warnf("failed to initialize device cache: %v", err)
	}

	collector := &DiskLatencyCollector{
		objs:       coll,
		ioDoneLink: ioDoneLink,
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
		readErrorsDesc: prometheus.NewDesc(
			MetricPrefix+"disk_read_errors_total",
			"Total number of disk read errors",
			[]string{"device"},
			nil,
		),
		writeErrorsDesc: prometheus.NewDesc(
			MetricPrefix+"disk_write_errors_total",
			"Total number of disk write errors",
			[]string{"device"},
			nil,
		),
		allocTsDesc: prometheus.NewDesc(
			MetricPrefix+"disk_latency_alloc_timestamp_total",
			"Completions timed from request allocation because the queue records no dispatch time",
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

// sysClassBlockPath lists every block device and partition (as symlinks).
// /sys/block lists whole disks only, but requests carry the partition's
// device number (e.g. vda1), so partitions must be resolvable too.
var sysClassBlockPath = "/sys/class/block"

// scanVirtioDevices maps device IDs ((major << 8) | (minor & 0xFF), the eBPF
// encoding) to names for every virtio disk and partition (vd*) under root.
// Entries are symlinks, so they are not filtered with IsDir.
func scanVirtioDevices(root string) (map[uint32]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", root, err)
	}
	found := make(map[uint32]string)
	for _, entry := range entries {
		deviceName := entry.Name()
		// Only process virtual disks (vd*) and their partitions
		if !strings.HasPrefix(deviceName, "vd") {
			continue
		}
		devPath := filepath.Join(root, deviceName, "dev")
		devData, err := os.ReadFile(devPath)
		if err != nil {
			log.Warnf("failed to read %s: %v", devPath, err)
			continue
		}
		var major, minor uint32
		if _, err := fmt.Sscanf(string(devData), "%d:%d", &major, &minor); err != nil {
			log.Warnf("failed to parse device numbers for %s: %v", deviceName, err)
			continue
		}
		found[(major<<8)|(minor&0xFF)] = deviceName
	}
	return found, nil
}

// initDeviceCache initializes the device cache from sysClassBlockPath
func initDeviceCache() error {
	found, err := scanVirtioDevices(sysClassBlockPath)
	if err != nil {
		return err
	}
	deviceMutex.Lock()
	defer deviceMutex.Unlock()
	for id, name := range found {
		deviceCache[id] = name
	}
	log.Infof("Initialized device cache with %d virtual disks and partitions", len(deviceCache))
	return nil
}

// getDeviceName returns the device name for a given device ID, rescanning
// sysClassBlockPath on a cache miss (e.g. a disk attached after startup).
func getDeviceName(deviceID uint32) string {
	deviceMutex.RLock()
	name, exists := deviceCache[deviceID]
	deviceMutex.RUnlock()
	if exists {
		return name
	}

	// The read lock is released before taking the write lock: sync.RWMutex
	// cannot be upgraded, and holding both deadlocks.
	if found, err := scanVirtioDevices(sysClassBlockPath); err == nil {
		deviceMutex.Lock()
		for id, n := range found {
			deviceCache[id] = n
		}
		name, exists = deviceCache[deviceID]
		deviceMutex.Unlock()
		if exists {
			return name
		}
	}

	return fmt.Sprintf("vd%d:%d", deviceID>>8, deviceID&0xFF)
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
	ch <- c.readErrorsDesc
	ch <- c.writeErrorsDesc
	ch <- c.allocTsDesc
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

	// Iterate over all entries in the map; each value is one copy per CPU
	var key uint32
	var perCPU []diskLatencyStats

	totalEntries := 0
	filteredEntries := 0
	iter := statsMap.Iterate()
	for iter.Next(&key, &perCPU) {
		totalEntries++
		value := sumDiskStats(perCPU)

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

		// Emit error metrics
		ch <- prometheus.MustNewConstMetric(
			c.readErrorsDesc,
			prometheus.CounterValue,
			float64(value.ReadErrorCount),
			deviceName,
		)

		ch <- prometheus.MustNewConstMetric(
			c.writeErrorsDesc,
			prometheus.CounterValue,
			float64(value.WriteErrorCount),
			deviceName,
		)

		ch <- prometheus.MustNewConstMetric(
			c.allocTsDesc,
			prometheus.CounterValue,
			float64(value.AllocTsCount),
			deviceName,
		)
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
	if c.ioDoneLink != nil {
		c.ioDoneLink.Close()
	}
	if c.objs != nil {
		c.objs.Close()
	}
}
