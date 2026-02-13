package collectors

import (
	"bufio"
	"metrics-exporter/src/log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type DiskStatsCollector struct {
	diskStatsPath    string
	readsCompleted   *prometheus.Desc
	readTimeMs       *prometheus.Desc
	writesCompleted  *prometheus.Desc
	writeTimeMs      *prometheus.Desc
	collectionErrors *prometheus.Desc
}

func NewDiskStatsCollector(diskStatsPath string) *DiskStatsCollector {
	return &DiskStatsCollector{
		diskStatsPath: diskStatsPath,
		readsCompleted: prometheus.NewDesc(
			MetricPrefix + "disk_reads_completed_total",
			"Total number of reads completed successfully",
			[]string{"device"},
			nil,
		),
		readTimeMs: prometheus.NewDesc(
			MetricPrefix + "disk_read_time_ms_total",
			"Total time spent reading in milliseconds",
			[]string{"device"},
			nil,
		),
		writesCompleted: prometheus.NewDesc(
			MetricPrefix + "disk_writes_completed_total",
			"Total number of writes completed successfully",
			[]string{"device"},
			nil,
		),
		writeTimeMs: prometheus.NewDesc(
			MetricPrefix + "disk_write_time_ms_total",
			"Total time spent writing in milliseconds",
			[]string{"device"},
			nil,
		),
		collectionErrors: prometheus.NewDesc(
			MetricPrefix + "disk_stats_collection_errors_total",
			"Total number of errors during disk stats collection",
			nil,
			nil,
		),
	}
}

func (c *DiskStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.readsCompleted
	ch <- c.readTimeMs
	ch <- c.writesCompleted
	ch <- c.writeTimeMs
	ch <- c.collectionErrors
}

func (c *DiskStatsCollector) Collect(ch chan<- prometheus.Metric) {
	file, err := os.Open(c.diskStatsPath)
	if err != nil {
		log.Errorf("Error opening %s: %v", c.diskStatsPath, err)
		ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, 1)
		return
	}
	defer file.Close()

	// Pattern to match main disk devices (vda, vdb, etc.) but not partitions (vda1, vdb2, etc.)
	diskPattern := regexp.MustCompile(`^vd[a-z]$`)

	scanner := bufio.NewScanner(file)
	errorCount := 0.0

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 14 {
			continue
		}

		// /proc/diskstats format:
		// 0: major, 1: minor, 2: device name, 3: reads completed, 4: reads merged,
		// 5: sectors read, 6: time reading (ms), 7: writes completed, 8: writes merged,
		// 9: sectors written, 10: time writing (ms), 11: ios in progress,
		// 12: time in io, 13: weighted time in io

		device := fields[2]

		// Only process main disk devices
		if !diskPattern.MatchString(device) {
			continue
		}

		readsCompleted, err := strconv.ParseFloat(fields[3], 64)
		if err != nil {
			log.Warnf("Error parsing reads_completed for %s: %v", device, err)
			errorCount++
			continue
		}

		readTimeMs, err := strconv.ParseFloat(fields[6], 64)
		if err != nil {
			log.Warnf("Error parsing read_time_ms for %s: %v", device, err)
			errorCount++
			continue
		}

		writesCompleted, err := strconv.ParseFloat(fields[7], 64)
		if err != nil {
			log.Warnf("Error parsing writes_completed for %s: %v", device, err)
			errorCount++
			continue
		}

		writeTimeMs, err := strconv.ParseFloat(fields[10], 64)
		if err != nil {
			log.Warnf("Error parsing write_time_ms for %s: %v", device, err)
			errorCount++
			continue
		}

		ch <- prometheus.MustNewConstMetric(c.readsCompleted, prometheus.CounterValue, readsCompleted, device)
		ch <- prometheus.MustNewConstMetric(c.readTimeMs, prometheus.CounterValue, readTimeMs, device)
		ch <- prometheus.MustNewConstMetric(c.writesCompleted, prometheus.CounterValue, writesCompleted, device)
		ch <- prometheus.MustNewConstMetric(c.writeTimeMs, prometheus.CounterValue, writeTimeMs, device)
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading %s: %v", c.diskStatsPath, err)
		errorCount++
	}

	ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, errorCount)
}
