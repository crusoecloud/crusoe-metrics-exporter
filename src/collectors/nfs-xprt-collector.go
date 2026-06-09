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

// NFSXprtCollector parses the per-xprt lines in /proc/self/mountstats and
// emits one series per (volume_id, xprt_idx) for each lane of an
// `nconnect`-mounted NFS volume. This complements the aggregate per-volume
// metrics emitted by NFSStatsCollector — those collapse all nconnect
// transports into a single series, so dead-lane / stuck-lane diagnostics
// require this finer breakdown.
//
// xprt_idx is a 0-based index within the mount block, assigned in scan
// order. It is stable across reconnects (unlike srcport, which the kernel
// regenerates on each socket teardown), so PromQL time-series are
// continuous through normal NFS reconnect activity. The kernel preserves
// xprt ordering in mountstats output — see iteration in
// net/sunrpc/clnt.c's rpc_show_info paths.
//
// Multi-mount-block dedupe: when the same volume appears in multiple
// mount blocks on the same host (e.g. CSI mounts the same PV into two
// pods), per-(volume_id, xprt_idx) values are deduplicated by max-merge.
// For monotonic counter fields (sends_total, connect_count_total, ...)
// this is the correct semantic — the larger value wins. For gauge fields
// (max_slots high-water-mark, idle_seconds current value), max-merge is
// opinionated: a stale or more-idle mount block can shadow an active
// one. In the typical one-mount-per-volume case this never fires; for
// the CSI-edge-case multi-mount, accept the limitation.
//
// Per-xprt deduplication: when the same volume appears in multiple mount
// blocks (e.g. the same PV mounted into two pods on the same node), we
// keep the max value per (volume_id, xprt_idx) — matching the convention
// in NFSStatsCollector for the volume-aggregate metrics.
//
// Field layout for `xprt: tcp ...` on Linux 5.x (mountstats v1.1):
//
//	fields[ 0] = "xprt:"
//	fields[ 1] = "tcp"
//	fields[ 2] = srcport
//	fields[ 3] = bind_count
//	fields[ 4] = connect_count  ← TCP_ESTABLISHED transitions, NOT attempts
//	fields[ 5] = connect_time   (HZ ticks, cumulative)
//	fields[ 6] = idle_time      (seconds since last activity)
//	fields[ 7] = sends
//	fields[ 8] = recvs
//	fields[ 9] = bad_xids
//	fields[10] = req_u          (cumulative request-slot utilization)
//	fields[11] = bklog_u        (cumulative backlog utilization)
//	fields[12] = max_slots      (high-water mark of slot table size)
//	fields[13] = sending_u      (cumulative sending utilization)
//	fields[14] = pending_u      (cumulative pending utilization)
//
// We require len(fields) >= 13 — enough to reach max_slots at index 12.
// Trailing utilization counters are accepted-but-ignored; missing ones
// surface as a parse failure incremented onto the collection-errors
// counter rather than a panic.
type NFSXprtCollector struct {
	mountStatsPath string

	sends            *prometheus.Desc
	recvs            *prometheus.Desc
	connectCount     *prometheus.Desc
	badXids          *prometheus.Desc
	maxSlots         *prometheus.Desc
	idleSeconds      *prometheus.Desc
	backlogU         *prometheus.Desc
	collectionErrors *prometheus.Desc
}

func NewNFSXprtCollector(mountStatsPath string) *NFSXprtCollector {
	labels := []string{"volume_id", "xprt_idx"}
	return &NFSXprtCollector{
		mountStatsPath: mountStatsPath,
		sends: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_sends_total",
			"NFS RPC requests sent on this xprt (lane). rate()==0 with connect_count>0 indicates a dead lane.",
			labels, nil,
		),
		recvs: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_recvs_total",
			"NFS RPC replies received on this xprt (lane).",
			labels, nil,
		),
		connectCount: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_connect_count_total",
			"Number of TCP_ESTABLISHED transitions on this xprt (lane). NOT the number of connect attempts. A high count with sends==0 indicates an ESTABLISH-then-immediate-teardown pattern.",
			labels, nil,
		),
		badXids: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_bad_xids_total",
			"NFS RPC replies with mismatched XIDs on this xprt — out-of-order or corrupted-frame indicator.",
			labels, nil,
		),
		maxSlots: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_max_slots",
			"High-water mark of the slot table size on this xprt. Stuck at 2 (kernel default) with no traffic = lane never used; expect this to rise to the slot-table-entries sysctl value on healthy lanes.",
			labels, nil,
		),
		idleSeconds: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_idle_seconds",
			"Seconds since the last activity on this xprt.",
			labels, nil,
		),
		backlogU: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_backlog_utilization",
			"Cumulative per-xprt backlog utilization. Differentiates lanes — useful when the volume-aggregate backlog metric is climbing and you want to localize which lane is queueing.",
			labels, nil,
		),
		collectionErrors: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_stats_collection_errors_total",
			"Total number of errors encountered while parsing xprt lines from mountstats.",
			nil, nil,
		),
	}
}

func (c *NFSXprtCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.sends
	ch <- c.recvs
	ch <- c.connectCount
	ch <- c.badXids
	ch <- c.maxSlots
	ch <- c.idleSeconds
	ch <- c.backlogU
	ch <- c.collectionErrors
}

// xprtKey identifies a unique (volume, xprt_idx) lane for deduplication.
type xprtKey struct {
	volumeID string
	xprtIdx  int
}

// xprtStats holds the per-lane field values we care about.
type xprtStats struct {
	sends        float64
	recvs        float64
	connectCount float64
	badXids      float64
	maxSlots     float64
	idleSeconds  float64
	backlogU     float64
}

// maxMerge updates `dst` to the max of the existing values and the new
// values. Used when the same (volume, xprt_idx) appears in more than one
// mount block — counters only grow, so max is the right merge.
func (s *xprtStats) maxMerge(other xprtStats) {
	if other.sends > s.sends {
		s.sends = other.sends
	}
	if other.recvs > s.recvs {
		s.recvs = other.recvs
	}
	if other.connectCount > s.connectCount {
		s.connectCount = other.connectCount
	}
	if other.badXids > s.badXids {
		s.badXids = other.badXids
	}
	if other.maxSlots > s.maxSlots {
		s.maxSlots = other.maxSlots
	}
	if other.idleSeconds > s.idleSeconds {
		s.idleSeconds = other.idleSeconds
	}
	if other.backlogU > s.backlogU {
		s.backlogU = other.backlogU
	}
}

func (c *NFSXprtCollector) Collect(ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("NFSXprtCollector panic recovered: %v", r)
		}
	}()

	errorCount := 0.0

	file, err := os.Open(c.mountStatsPath)
	if err != nil {
		log.Errorf("Error opening %s: %v", c.mountStatsPath, err)
		// One error for the file-open failure. Do not emit any xprt
		// series — there's nothing to attribute them to. The
		// collection_errors counter is the single signal a downstream
		// scrape gets in this case.
		ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, 1)
		return
	}
	defer file.Close()

	accum := make(map[xprtKey]*xprtStats)

	scanner := bufio.NewScanner(file)
	currentVolumeID := ""
	currentXprtIdx := 0 // 0-based index of xprts within the current mount block

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// A `device ...` line marks the start of a new mount block.
		// Reset the xprt index counter. If the device path matches
		// our `/volumes/<uuid>` shape, extract the UUID; otherwise
		// blank the volume ID so subsequent xprts in this block are
		// skipped.
		if fields[0] == "device" && len(fields) >= 2 {
			device := fields[1]
			if idx := strings.Index(device, "/volumes/"); idx != -1 {
				currentVolumeID = device[idx+len("/volumes/"):]
			} else {
				currentVolumeID = ""
			}
			currentXprtIdx = 0
			continue
		}

		// Per-xprt line. We only handle TCP xprts; RDMA/UDP land in
		// the same file but with different field counts and are out
		// of scope for the NFS-over-TCP focus of this collector
		// (silent skip — not an error).
		if fields[0] != "xprt:" {
			continue
		}
		if len(fields) < 2 || fields[1] != "tcp" {
			continue
		}

		// From here on the line claims to be a TCP xprt. Advance the
		// index even on malformed lines so the next valid xprt
		// keeps its kernel-emitted ordinal.
		idx := currentXprtIdx
		currentXprtIdx++

		if currentVolumeID == "" {
			// Out of scope for this volume — but we already
			// advanced idx so the order stays right if a later
			// device line resets it.
			continue
		}

		// Malformed TCP xprt line: claims tcp but doesn't carry
		// enough fields to reach max_slots (idx 12). Surface as a
		// collection error rather than silently skipping — silent
		// skip of malformed input is the failure mode that hid
		// kernel-format mismatches across the existing 30-VM error
		// cohort.
		if len(fields) < 13 {
			log.Warnf("malformed xprt: tcp line (too few fields, %d): %q", len(fields), line)
			errorCount++
			continue
		}

		s, err := parseXprtFields(fields)
		if err != nil {
			log.Warnf("error parsing xprt line: %v", err)
			errorCount++
			continue
		}

		key := xprtKey{volumeID: currentVolumeID, xprtIdx: idx}
		if existing, ok := accum[key]; ok {
			existing.maxMerge(s)
		} else {
			accum[key] = &s
		}
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error reading %s: %v", c.mountStatsPath, err)
		errorCount++
	}

	for key, s := range accum {
		idxStr := strconv.Itoa(key.xprtIdx)
		ch <- prometheus.MustNewConstMetric(c.sends, prometheus.CounterValue, s.sends, key.volumeID, idxStr)
		ch <- prometheus.MustNewConstMetric(c.recvs, prometheus.CounterValue, s.recvs, key.volumeID, idxStr)
		ch <- prometheus.MustNewConstMetric(c.connectCount, prometheus.CounterValue, s.connectCount, key.volumeID, idxStr)
		ch <- prometheus.MustNewConstMetric(c.badXids, prometheus.CounterValue, s.badXids, key.volumeID, idxStr)
		ch <- prometheus.MustNewConstMetric(c.maxSlots, prometheus.GaugeValue, s.maxSlots, key.volumeID, idxStr)
		ch <- prometheus.MustNewConstMetric(c.idleSeconds, prometheus.GaugeValue, s.idleSeconds, key.volumeID, idxStr)
		ch <- prometheus.MustNewConstMetric(c.backlogU, prometheus.CounterValue, s.backlogU, key.volumeID, idxStr)
	}

	ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, errorCount)
}

// parseXprtFields converts the 13+ numeric fields of an xprt: tcp line
// into the seven values we expose as metrics. Returns a wrapped error
// identifying which field index failed so debugging a kernel-format drift
// doesn't require diffing the line against the expected layout.
func parseXprtFields(fields []string) (xprtStats, error) {
	parseAt := func(idx int) (float64, error) {
		v, err := strconv.ParseFloat(fields[idx], 64)
		if err != nil {
			return 0, fmt.Errorf("xprt: field[%d]: %w", idx, err)
		}
		return v, nil
	}
	connectCount, err := parseAt(4)
	if err != nil {
		return xprtStats{}, err
	}
	idleSeconds, err := parseAt(6)
	if err != nil {
		return xprtStats{}, err
	}
	sends, err := parseAt(7)
	if err != nil {
		return xprtStats{}, err
	}
	recvs, err := parseAt(8)
	if err != nil {
		return xprtStats{}, err
	}
	badXids, err := parseAt(9)
	if err != nil {
		return xprtStats{}, err
	}
	backlogU, err := parseAt(11)
	if err != nil {
		return xprtStats{}, err
	}
	maxSlots, err := parseAt(12)
	if err != nil {
		return xprtStats{}, err
	}
	return xprtStats{
		sends:        sends,
		recvs:        recvs,
		connectCount: connectCount,
		badXids:      badXids,
		maxSlots:     maxSlots,
		idleSeconds:  idleSeconds,
		backlogU:     backlogU,
	}, nil
}
