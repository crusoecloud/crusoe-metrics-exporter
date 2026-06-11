package collectors

import (
	"bufio"
	"fmt"
	"metrics-exporter/src/log"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// NFSMountEventsCollector parses the per-mount `events:`, `bytes:`, and
// `age:` lines in /proc/self/mountstats and emits per-(volume_id) metrics.
// This complements NFSStatsCollector (per-volume, per-op RPC stats) and
// NFSXprtCollector (per-nconnect-lane xprt stats) by exposing the *mount-
// level* kernel-side counters: when did the client get delayed, how much
// data did the application actually move, how long has the mount been
// up.
//
// Field layouts (Linux 5.x mountstats v1.1):
//
// `events: <27 numeric fields>` — see fs/nfs/iostat.h NFSIOS_* enum.
//   We expose four counters most diagnostic for perf investigations:
//     index 19: congestion_wait  — kernel waited on RPC congestion
//     index 23: short_read        — read returned fewer bytes than asked
//     index 24: short_write       — write returned fewer bytes than asked
//     index 25: delay             — kernel had to delay a client request
//
// `bytes: <8 numeric fields>`:
//     index 1: normal_read   (via page cache)
//     index 2: normal_write  (via page cache)
//     index 3: direct_read   (O_DIRECT — what fio --direct=1 uses)
//     index 4: direct_write
//     index 5: server_read   (bytes NFS actually transferred, post-cache)
//     index 6: server_write
//     index 7: read_pages    (page count, not byte count)
//     index 8: write_pages
//
// `age: <seconds>` — mount age in seconds since the mount() syscall.
//
// Multi-block dedupe semantics: when the same volume appears in multiple
// mount blocks (e.g. same PV mounted into two pods), per-volume_id values
// are deduplicated by max-merge — matching the convention in
// NFSStatsCollector. For monotonic counter fields (delay_events_total,
// direct_read_bytes_total, ...) this is the correct semantic — the
// larger value wins. For the `age_seconds` gauge, max picks the longer-
// lived mount block, which is opinionated but usually what an alert
// builder wants. In the typical one-mount-per-volume case this dedupe
// never fires.
type NFSMountEventsCollector struct {
	mountStatsPath string

	// events: counters
	congestionWait *prometheus.Desc
	shortRead      *prometheus.Desc
	shortWrite     *prometheus.Desc
	delay          *prometheus.Desc

	// bytes: counters
	normalReadBytes  *prometheus.Desc
	normalWriteBytes *prometheus.Desc
	directReadBytes  *prometheus.Desc
	directWriteBytes *prometheus.Desc
	serverReadBytes  *prometheus.Desc
	serverWriteBytes *prometheus.Desc
	readPages        *prometheus.Desc
	writePages       *prometheus.Desc

	// age: gauge
	ageSeconds *prometheus.Desc

	collectionErrors *prometheus.Desc
}

func NewNFSMountEventsCollector(mountStatsPath string) *NFSMountEventsCollector {
	volLabel := []string{"volume_id"}
	return &NFSMountEventsCollector{
		mountStatsPath: mountStatsPath,
		congestionWait: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_congestion_wait_events_total",
			"Per-mount count of times the NFS client waited on RPC congestion (events: index 19).",
			volLabel, nil,
		),
		shortRead: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_short_read_events_total",
			"Per-mount count of read responses returning fewer bytes than requested (events: index 23).",
			volLabel, nil,
		),
		shortWrite: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_short_write_events_total",
			"Per-mount count of write responses returning fewer bytes than requested (events: index 24).",
			volLabel, nil,
		),
		delay: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_delay_events_total",
			"Per-mount NFSv4 retry-after-DELAY counter — fires only on NFS4ERR_DELAY replies via nfs4_handle_exception (events: index 25). Structurally zero on NFSv3 mounts because v3 has no NFS4ERR_DELAY; v3 server back-pressure surfaces instead as RPC timeouts (nfs_rpc_timeouts_total) and reconnects (nfs_xprt_connect_count_total).",
			volLabel, nil,
		),
		normalReadBytes: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_normal_read_bytes_total",
			"Per-mount bytes returned by page-cached read() syscalls (bytes: index 1).",
			volLabel, nil,
		),
		normalWriteBytes: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_normal_write_bytes_total",
			"Per-mount bytes written by page-cached write() syscalls (bytes: index 2).",
			volLabel, nil,
		),
		directReadBytes: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_direct_read_bytes_total",
			"Per-mount bytes returned by O_DIRECT read() syscalls (bytes: index 3). This is what fio --direct=1 consumes.",
			volLabel, nil,
		),
		directWriteBytes: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_direct_write_bytes_total",
			"Per-mount bytes written by O_DIRECT write() syscalls (bytes: index 4).",
			volLabel, nil,
		),
		serverReadBytes: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_server_read_bytes_total",
			"Per-mount bytes actually fetched from the NFS server (bytes: index 5). Compare with normal_read_bytes to detect page-cache hit ratio.",
			volLabel, nil,
		),
		serverWriteBytes: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_server_write_bytes_total",
			"Per-mount bytes actually written to the NFS server (bytes: index 6).",
			volLabel, nil,
		),
		readPages: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_read_pages_total",
			"Per-mount count of pages read via readpage/readpages NFS ops (bytes: index 7).",
			volLabel, nil,
		),
		writePages: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_write_pages_total",
			"Per-mount count of pages written via writepage/writepages NFS ops (bytes: index 8).",
			volLabel, nil,
		),
		ageSeconds: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_age_seconds",
			"Seconds since the NFS mount was established (mountstats `age:` field). Useful for distinguishing long-lived stuck mounts from freshly-mounted ones, and as a reset signal — drops to a small value indicate the mount was recreated.",
			volLabel, nil,
		),
		collectionErrors: prometheus.NewDesc(
			MetricPrefix+"nfs_mount_events_collection_errors_total",
			"Total errors parsing mount-level events/bytes/age lines from mountstats.",
			nil, nil,
		),
	}
}

func (c *NFSMountEventsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.congestionWait
	ch <- c.shortRead
	ch <- c.shortWrite
	ch <- c.delay
	ch <- c.normalReadBytes
	ch <- c.normalWriteBytes
	ch <- c.directReadBytes
	ch <- c.directWriteBytes
	ch <- c.serverReadBytes
	ch <- c.serverWriteBytes
	ch <- c.readPages
	ch <- c.writePages
	ch <- c.ageSeconds
	ch <- c.collectionErrors
}

// mountAccum collects per-mount values across potentially multiple mount
// blocks for the same volume. Each field tracks the maximum value seen
// (counters only grow; age tracks the longer-lived mount).
type mountAccum struct {
	congestionWait   float64
	shortRead        float64
	shortWrite       float64
	delay            float64
	normalReadBytes  float64
	normalWriteBytes float64
	directReadBytes  float64
	directWriteBytes float64
	serverReadBytes  float64
	serverWriteBytes float64
	readPages        float64
	writePages       float64
	ageSeconds       float64
	// Track which fields were actually observed for this volume so we
	// don't emit zero series for missing lines.
	sawEvents bool
	sawBytes  bool
	sawAge    bool
}

func (m *mountAccum) mergeMax(other *mountAccum) {
	if other.congestionWait > m.congestionWait {
		m.congestionWait = other.congestionWait
	}
	if other.shortRead > m.shortRead {
		m.shortRead = other.shortRead
	}
	if other.shortWrite > m.shortWrite {
		m.shortWrite = other.shortWrite
	}
	if other.delay > m.delay {
		m.delay = other.delay
	}
	if other.normalReadBytes > m.normalReadBytes {
		m.normalReadBytes = other.normalReadBytes
	}
	if other.normalWriteBytes > m.normalWriteBytes {
		m.normalWriteBytes = other.normalWriteBytes
	}
	if other.directReadBytes > m.directReadBytes {
		m.directReadBytes = other.directReadBytes
	}
	if other.directWriteBytes > m.directWriteBytes {
		m.directWriteBytes = other.directWriteBytes
	}
	if other.serverReadBytes > m.serverReadBytes {
		m.serverReadBytes = other.serverReadBytes
	}
	if other.serverWriteBytes > m.serverWriteBytes {
		m.serverWriteBytes = other.serverWriteBytes
	}
	if other.readPages > m.readPages {
		m.readPages = other.readPages
	}
	if other.writePages > m.writePages {
		m.writePages = other.writePages
	}
	if other.ageSeconds > m.ageSeconds {
		m.ageSeconds = other.ageSeconds
	}
	if other.sawEvents {
		m.sawEvents = true
	}
	if other.sawBytes {
		m.sawBytes = true
	}
	if other.sawAge {
		m.sawAge = true
	}
}

func (c *NFSMountEventsCollector) Collect(ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("NFSMountEventsCollector panic recovered: %v", r)
		}
	}()

	errorCount := 0.0

	file, err := os.Open(c.mountStatsPath)
	if err != nil {
		log.Errorf("Error opening %s: %v", c.mountStatsPath, err)
		ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, 1)
		return
	}
	defer file.Close()

	accum := make(map[string]*mountAccum)
	currentVolumeID := ""
	var current *mountAccum

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// New mount block: extract volume_id and reset the per-block
		// accumulator. If the device path doesn't match /volumes/<uuid>,
		// blank the volume so events/bytes/age lines in this block are
		// ignored.
		if fields[0] == "device" && len(fields) >= 2 {
			device := fields[1]
			if idx := strings.Index(device, "/volumes/"); idx != -1 {
				currentVolumeID = device[idx+len("/volumes/"):]
				if _, ok := accum[currentVolumeID]; !ok {
					accum[currentVolumeID] = &mountAccum{}
				}
				current = accum[currentVolumeID]
			} else {
				currentVolumeID = ""
				current = nil
			}
			continue
		}

		if currentVolumeID == "" || current == nil {
			continue
		}

		switch fields[0] {
		case "age:":
			if len(fields) < 2 {
				log.Warnf("malformed age: line (too few fields)")
				errorCount++
				continue
			}
			age, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				log.Warnf("parse age: %v", err)
				errorCount++
				continue
			}
			block := &mountAccum{ageSeconds: age, sawAge: true}
			current.mergeMax(block)

		case "events:":
			// Linux 5.x emits 27 numeric fields after the "events:"
			// header (NFSIOS_* enum in fs/nfs/iostat.h). We need to
			// reach index 25 (delay), so require len(fields) >= 26.
			if len(fields) < 26 {
				log.Warnf("malformed events: line (only %d fields, need >= 26)", len(fields))
				errorCount++
				continue
			}
			// Indices 19/23/24/25 (1-based after "events:" header,
			// i.e. fields[19..25]) — congestion_wait, short_read,
			// short_write, delay. All four are guaranteed to exist
			// given the length gate above.
			block := &mountAccum{sawEvents: true}
			var parseErr error
			parseFloat := func(idx int, dst *float64) bool {
				v, err := strconv.ParseFloat(fields[idx], 64)
				if err != nil {
					parseErr = fmt.Errorf("events: field[%d]: %w", idx, err)
					return false
				}
				*dst = v
				return true
			}
			if !parseFloat(19, &block.congestionWait) ||
				!parseFloat(23, &block.shortRead) ||
				!parseFloat(24, &block.shortWrite) ||
				!parseFloat(25, &block.delay) {
				log.Warnf("%v", parseErr)
				errorCount++
				continue
			}
			current.mergeMax(block)

		case "bytes:":
			// Expect 8 numeric fields after the "bytes:" header.
			if len(fields) < 9 {
				log.Warnf("malformed bytes: line (only %d fields, need >= 9)", len(fields))
				errorCount++
				continue
			}
			block := &mountAccum{sawBytes: true}
			ok := true
			values := [8]float64{}
			for i := 0; i < 8; i++ {
				v, parseErr := strconv.ParseFloat(fields[i+1], 64)
				if parseErr != nil {
					log.Warnf("parse bytes[%d]: %v", i, parseErr)
					errorCount++
					ok = false
					break
				}
				values[i] = v
			}
			if !ok {
				continue
			}
			block.normalReadBytes = values[0]
			block.normalWriteBytes = values[1]
			block.directReadBytes = values[2]
			block.directWriteBytes = values[3]
			block.serverReadBytes = values[4]
			block.serverWriteBytes = values[5]
			block.readPages = values[6]
			block.writePages = values[7]
			current.mergeMax(block)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading %s: %v", c.mountStatsPath, err)
		errorCount++
	}

	for volumeID, m := range accum {
		if m.sawEvents {
			ch <- prometheus.MustNewConstMetric(c.congestionWait, prometheus.CounterValue, m.congestionWait, volumeID)
			ch <- prometheus.MustNewConstMetric(c.shortRead, prometheus.CounterValue, m.shortRead, volumeID)
			ch <- prometheus.MustNewConstMetric(c.shortWrite, prometheus.CounterValue, m.shortWrite, volumeID)
			ch <- prometheus.MustNewConstMetric(c.delay, prometheus.CounterValue, m.delay, volumeID)
		}
		if m.sawBytes {
			ch <- prometheus.MustNewConstMetric(c.normalReadBytes, prometheus.CounterValue, m.normalReadBytes, volumeID)
			ch <- prometheus.MustNewConstMetric(c.normalWriteBytes, prometheus.CounterValue, m.normalWriteBytes, volumeID)
			ch <- prometheus.MustNewConstMetric(c.directReadBytes, prometheus.CounterValue, m.directReadBytes, volumeID)
			ch <- prometheus.MustNewConstMetric(c.directWriteBytes, prometheus.CounterValue, m.directWriteBytes, volumeID)
			ch <- prometheus.MustNewConstMetric(c.serverReadBytes, prometheus.CounterValue, m.serverReadBytes, volumeID)
			ch <- prometheus.MustNewConstMetric(c.serverWriteBytes, prometheus.CounterValue, m.serverWriteBytes, volumeID)
			ch <- prometheus.MustNewConstMetric(c.readPages, prometheus.CounterValue, m.readPages, volumeID)
			ch <- prometheus.MustNewConstMetric(c.writePages, prometheus.CounterValue, m.writePages, volumeID)
		}
		if m.sawAge {
			ch <- prometheus.MustNewConstMetric(c.ageSeconds, prometheus.GaugeValue, m.ageSeconds, volumeID)
		}
	}

	ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, errorCount)
}
