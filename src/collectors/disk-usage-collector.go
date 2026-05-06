package collectors

import (
	"bufio"
	"metrics-exporter/src/log"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
)

type DiskUsageCollector struct {
	mountsPath       string
	hostRootPath     string
	bytesUsed        *prometheus.Desc
	bytesTotal       *prometheus.Desc
	inodesUsed       *prometheus.Desc
	inodesTotal      *prometheus.Desc
	collectionErrors *prometheus.Desc
}

func NewDiskUsageCollector(mountsPath, hostRootPath string) *DiskUsageCollector {
	return &DiskUsageCollector{
		mountsPath:   mountsPath,
		hostRootPath: hostRootPath,
		bytesUsed: prometheus.NewDesc(
			MetricPrefix+"disk_bytes_used",
			"Bytes currently used on disk filesystem",
			[]string{"device", "mount_point"},
			nil,
		),
		bytesTotal: prometheus.NewDesc(
			MetricPrefix+"disk_bytes_total",
			"Total bytes on disk filesystem",
			[]string{"device", "mount_point"},
			nil,
		),
		inodesUsed: prometheus.NewDesc(
			MetricPrefix+"disk_inodes_used",
			"Inodes currently used on disk filesystem",
			[]string{"device", "mount_point"},
			nil,
		),
		inodesTotal: prometheus.NewDesc(
			MetricPrefix+"disk_inodes_total",
			"Total inodes on disk filesystem",
			[]string{"device", "mount_point"},
			nil,
		),
		collectionErrors: prometheus.NewDesc(
			MetricPrefix+"disk_usage_collection_errors_total",
			"Total number of errors during disk usage collection",
			nil,
			nil,
		),
	}
}

func (c *DiskUsageCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bytesUsed
	ch <- c.bytesTotal
	ch <- c.inodesUsed
	ch <- c.inodesTotal
	ch <- c.collectionErrors
}

func (c *DiskUsageCollector) Collect(ch chan<- prometheus.Metric) {
	file, err := os.Open(c.mountsPath)
	if err != nil {
		log.Errorf("Error opening %s: %v", c.mountsPath, err)
		ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, 1)
		return
	}
	defer file.Close()

	// Match /dev/vda, /dev/vdb, /dev/vda1, /dev/vda2, etc. — capture the full device name.
	diskPattern := regexp.MustCompile(`^/dev/(vd[a-z]\d*)$`)
	errorCount := 0.0
	seen := map[string]bool{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		device := fields[0]
		mountPoint := fields[1]

		matches := diskPattern.FindStringSubmatch(device)
		if matches == nil {
			continue
		}
		deviceName := matches[1] // e.g. "vda", "vda1", "vdb"

		if seen[deviceName] {
			continue
		}
		seen[deviceName] = true

		var stat syscall.Statfs_t
		// hostRootPath is /host/proc/1/root — a kernel magic link to the host's root filesystem
		fullPath := c.hostRootPath + mountPoint
		if err := syscall.Statfs(fullPath, &stat); err != nil {
			log.Warnf("Error calling statfs on %s: %v", fullPath, err)
			errorCount++
			continue
		}

		bytesUsed := float64(stat.Blocks-stat.Bfree) * float64(stat.Bsize)
		bytesTotal := float64(stat.Blocks) * float64(stat.Bsize)
		inodesUsed := float64(stat.Files - stat.Ffree)
		inodesTotal := float64(stat.Files)

		ch <- prometheus.MustNewConstMetric(c.bytesUsed, prometheus.GaugeValue, bytesUsed, deviceName, mountPoint)
		ch <- prometheus.MustNewConstMetric(c.bytesTotal, prometheus.GaugeValue, bytesTotal, deviceName, mountPoint)
		ch <- prometheus.MustNewConstMetric(c.inodesUsed, prometheus.GaugeValue, inodesUsed, deviceName, mountPoint)
		ch <- prometheus.MustNewConstMetric(c.inodesTotal, prometheus.GaugeValue, inodesTotal, deviceName, mountPoint)
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading %s: %v", c.mountsPath, err)
		errorCount++
	}

	ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, errorCount)
}
