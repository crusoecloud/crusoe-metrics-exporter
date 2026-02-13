package collectors

import (
	"bufio"
	"metrics-exporter/src/log"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type NFSStatsCollector struct {
	mountStatsPath   string
	rpcCount         *prometheus.Desc
	rpcRttMs         *prometheus.Desc
	rpcExeMs         *prometheus.Desc
	collectionErrors *prometheus.Desc
}

func NewNFSStatsCollector(mountStatsPath string) *NFSStatsCollector {
	return &NFSStatsCollector{
		mountStatsPath: mountStatsPath,
		rpcCount: prometheus.NewDesc(
			MetricPrefix + "nfs_rpc_count_total",
			"Total number of NFS RPC operations",
			[]string{"nfs_volume_id", "nfs_operation"},
			nil,
		),
		rpcRttMs: prometheus.NewDesc(
			MetricPrefix + "nfs_rpc_rtt_ms_total",
			"Total RTT time for NFS RPC operations in milliseconds",
			[]string{"nfs_volume_id", "nfs_operation"},
			nil,
		),
		rpcExeMs: prometheus.NewDesc(
			MetricPrefix + "nfs_rpc_exe_ms_total",
			"Total execution time for NFS RPC operations in milliseconds",
			[]string{"nfs_volume_id", "nfs_operation"},
			nil,
		),
		collectionErrors: prometheus.NewDesc(
			MetricPrefix + "nfs_stats_collection_errors_total",
			"Total number of errors during NFS stats collection",
			nil,
			nil,
		),
	}
}

func (c *NFSStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rpcCount
	ch <- c.rpcRttMs
	ch <- c.rpcExeMs
	ch <- c.collectionErrors
}

func (c *NFSStatsCollector) Collect(ch chan<- prometheus.Metric) {
	file, err := os.Open(c.mountStatsPath)
	if err != nil {
		log.Errorf("Error opening %s: %v", c.mountStatsPath, err)
		ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, 1)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	errorCount := 0.0
	currentVolumeID := ""

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) == 0 {
			continue
		}

		// Look for device line to extract volume ID
		if fields[0] == "device" && len(fields) >= 2 {
			// Extract volume ID from device field
			// e.g., nfs.crusoecloudcompute.com:/volumes/47d32f7f-1687-42c8-b6fd-67b3a2263c8e
			device := fields[1]
			if idx := strings.Index(device, "/volumes/"); idx != -1 {
				currentVolumeID = device[idx+len("/volumes/"):]
			} else {
				currentVolumeID = ""
			}
			continue
		}

		// Look for READ: or WRITE: lines
		if (fields[0] == "READ:" || fields[0] == "WRITE:") && currentVolumeID != "" {
			if len(fields) < 10 {
				continue
			}

			// Parse operation count (field 1)
			opsCount, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				log.Warnf("Error parsing ops count: %v", err)
				errorCount++
				continue
			}

			// Only output if any IO has happened
			if opsCount == 0 {
				continue
			}

			// Remove colon and lowercase operation name
			opType := strings.ToLower(strings.TrimSuffix(fields[0], ":"))

			// Parse RTT time (field 7, index 7)
			rttTime, err := strconv.ParseFloat(fields[7], 64)
			if err != nil {
				log.Warnf("Error parsing RTT time: %v", err)
				errorCount++
				continue
			}

			// Parse Execute time (field 8, index 8)
			exeTime, err := strconv.ParseFloat(fields[8], 64)
			if err != nil {
				log.Warnf("Error parsing execute time: %v", err)
				errorCount++
				continue
			}

			ch <- prometheus.MustNewConstMetric(c.rpcCount, prometheus.CounterValue, opsCount, currentVolumeID, opType)
			ch <- prometheus.MustNewConstMetric(c.rpcRttMs, prometheus.CounterValue, rttTime, currentVolumeID, opType)
			ch <- prometheus.MustNewConstMetric(c.rpcExeMs, prometheus.CounterValue, exeTime, currentVolumeID, opType)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading %s: %v", c.mountStatsPath, err)
		errorCount++
	}

	ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, errorCount)
}
