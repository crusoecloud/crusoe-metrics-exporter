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
	rpcTimeouts      *prometheus.Desc
	rpcRttMs         *prometheus.Desc
	rpcExeMs         *prometheus.Desc
	bytesSent        *prometheus.Desc
	bytesRecv        *prometheus.Desc
	backlog          *prometheus.Desc
	collectionErrors *prometheus.Desc
}

func NewNFSStatsCollector(mountStatsPath string) *NFSStatsCollector {
	return &NFSStatsCollector{
		mountStatsPath: mountStatsPath,
		rpcCount: prometheus.NewDesc(
			MetricPrefix + "nfs_rpc_count_total",
			"Total number of NFS RPC operations",
			[]string{"volume_id", "nfs_operation"},
			nil,
		),
		rpcRttMs: prometheus.NewDesc(
			MetricPrefix + "nfs_rpc_rtt_ms_total",
			"Total RTT time for NFS RPC operations in milliseconds",
			[]string{"volume_id", "nfs_operation"},
			nil,
		),
		rpcTimeouts: prometheus.NewDesc(
			MetricPrefix+"nfs_rpc_timeouts_total",
			"Total number of NFS RPC timeouts",
			[]string{"volume_id", "nfs_operation"},
			nil,
		),
		rpcExeMs: prometheus.NewDesc(
			MetricPrefix+"nfs_rpc_exe_ms_total",
			"Total execution time for NFS RPC operations in milliseconds",
			[]string{"volume_id", "nfs_operation"},
			nil,
		),
		bytesSent: prometheus.NewDesc(
			MetricPrefix+"nfs_bytes_sent_total",
			"Total bytes sent for NFS RPC operations",
			[]string{"volume_id", "nfs_operation"},
			nil,
		),
		bytesRecv: prometheus.NewDesc(
			MetricPrefix+"nfs_bytes_recv_total",
			"Total bytes received for NFS RPC operations",
			[]string{"volume_id", "nfs_operation"},
			nil,
		),
		backlog: prometheus.NewDesc(
			MetricPrefix + "nfs_rpc_backlog",
			"NFS RPC backlog utilization from xprt stats",
			[]string{"volume_id"},
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
	ch <- c.rpcTimeouts
	ch <- c.rpcRttMs
	ch <- c.rpcExeMs
	ch <- c.bytesSent
	ch <- c.bytesRecv
	ch <- c.backlog
	ch <- c.collectionErrors
}

// rpcKey identifies a unique (volume, operation) pair for deduplication.
type rpcKey struct {
	volumeID  string
	operation string
}

func (c *NFSStatsCollector) Collect(ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("NFSStatsCollector panic recovered: %v", r)
		}
	}()

	file, err := os.Open(c.mountStatsPath)
	if err != nil {
		log.Errorf("Error opening %s: %v", c.mountStatsPath, err)
		ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, 1)
		return
	}
	defer file.Close()

	// Accumulate per volume+operation to handle the same volume appearing
	// in multiple mount blocks (e.g. same PV mounted into several pods).
	type rpcStats struct {
		ops       float64
		timeouts  float64
		rtt       float64
		exe       float64
		bytesSent float64
		bytesRecv float64
	}
	rpcAccum := make(map[rpcKey]*rpcStats)
	backlogAccum := make(map[string]float64) // volume_id -> max bklog_u

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

		// Parse xprt: tcp line for backlog utilization (bklog_u)
		// Format: xprt: tcp <srcport> <bind> <conn> <conn_time> <idle> <sends> <recvs> <bad_xids> <req_u> <bklog_u>
		if fields[0] == "xprt:" && len(fields) >= 12 && fields[1] == "tcp" && currentVolumeID != "" {
			bklogU, err := strconv.ParseFloat(fields[11], 64)
			if err != nil {
				log.Warnf("Error parsing bklog_u: %v", err)
				errorCount++
			} else {
				// Keep the max backlog across duplicate mount blocks
				if bklogU > backlogAccum[currentVolumeID] {
					backlogAccum[currentVolumeID] = bklogU
				}
			}
			continue
		}

		// Look for READ: or WRITE: lines
		if (fields[0] == "READ:" || fields[0] == "WRITE:") && currentVolumeID != "" {
			if len(fields) < 10 {
				continue
			}

			opsCount, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				log.Warnf("Error parsing ops count: %v", err)
				errorCount++
				continue
			}
			if opsCount == 0 {
				continue
			}

			opType := strings.ToLower(strings.TrimSuffix(fields[0], ":"))

			// Parse timeouts (field 3, index 3)
			timeouts, err := strconv.ParseFloat(fields[3], 64)
			if err != nil {
				log.Warnf("Error parsing timeouts: %v", err)
				errorCount++
				continue
			}

			rttTime, err := strconv.ParseFloat(fields[7], 64)
			if err != nil {
				log.Warnf("Error parsing RTT time: %v", err)
				errorCount++
				continue
			}

			exeTime, err := strconv.ParseFloat(fields[8], 64)
			if err != nil {
				log.Warnf("Error parsing execute time: %v", err)
				errorCount++
				continue
			}

			// Per-op line format: OP: ops trans maj_to bytes_sent bytes_recv queue rtt exe errors
			var bytesSent, bytesRecv float64
			if len(fields) >= 6 {
				bytesSent, _ = strconv.ParseFloat(fields[4], 64)
				bytesRecv, _ = strconv.ParseFloat(fields[5], 64)
			}

			key := rpcKey{volumeID: currentVolumeID, operation: opType}
			if existing, ok := rpcAccum[key]; ok {
				// Same volume+op seen again; keep the max values
				if opsCount > existing.ops {
					existing.ops = opsCount
				}
				if timeouts > existing.timeouts {
					existing.timeouts = timeouts
				}
				if rttTime > existing.rtt {
					existing.rtt = rttTime
				}
				if exeTime > existing.exe {
					existing.exe = exeTime
				}
				if bytesSent > existing.bytesSent {
					existing.bytesSent = bytesSent
				}
				if bytesRecv > existing.bytesRecv {
					existing.bytesRecv = bytesRecv
				}
			} else {
				rpcAccum[key] = &rpcStats{ops: opsCount, timeouts: timeouts, rtt: rttTime, exe: exeTime, bytesSent: bytesSent, bytesRecv: bytesRecv}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading %s: %v", c.mountStatsPath, err)
		errorCount++
	}

	// Emit deduplicated metrics
	for key, stats := range rpcAccum {
		ch <- prometheus.MustNewConstMetric(c.rpcCount, prometheus.CounterValue, stats.ops, key.volumeID, key.operation)
		ch <- prometheus.MustNewConstMetric(c.rpcTimeouts, prometheus.CounterValue, stats.timeouts, key.volumeID, key.operation)
		ch <- prometheus.MustNewConstMetric(c.rpcRttMs, prometheus.CounterValue, stats.rtt, key.volumeID, key.operation)
		ch <- prometheus.MustNewConstMetric(c.rpcExeMs, prometheus.CounterValue, stats.exe, key.volumeID, key.operation)
		ch <- prometheus.MustNewConstMetric(c.bytesSent, prometheus.CounterValue, stats.bytesSent, key.volumeID, key.operation)
		ch <- prometheus.MustNewConstMetric(c.bytesRecv, prometheus.CounterValue, stats.bytesRecv, key.volumeID, key.operation)
	}
	for volumeID, bklog := range backlogAccum {
		ch <- prometheus.MustNewConstMetric(c.backlog, prometheus.CounterValue, bklog, volumeID)
	}

	ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, errorCount)
}
