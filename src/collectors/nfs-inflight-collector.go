package collectors

import (
	"bufio"
	"bytes"
	"fmt"
	"metrics-exporter/src/log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// NFSInflightCollector exports the number of RPC requests currently
// outstanding per volume, read from the kernel's live per-client task
// list. Unlike the xprt sends/recvs counters, the task list includes
// requests queued but not yet transmitted, and returns to zero the
// moment nothing is waiting — lost replies cannot permanently skew it.
//
// Mapping chain (all vastnfs debugfs text files):
//
//	/proc/1/mountinfo                     mount st_dev ("maj:min") -> volume_id
//	<vastnfs>/nfs_sb/*                    sb_id ("maj:min") -> rpc_id
//	<sunrpc>/rpc_clnt/<rpc_id hex>/tasks  one line per outstanding RPC task
//
// Volumes sharing a superblock (mounted without nosharetransport) share
// one task list and report the same value, consistent with the other
// mountstats-derived metrics.
type NFSInflightCollector struct {
	mountInfoPath    string
	vastnfsDebugPath string
	sunrpcDebugPath  string
	inflight         *prometheus.Desc
	collectionErrors *prometheus.Desc
	warnMissingOnce  sync.Once
}

func NewNFSInflightCollector(mountInfoPath, vastnfsDebugPath, sunrpcDebugPath string) *NFSInflightCollector {
	return &NFSInflightCollector{
		mountInfoPath:    mountInfoPath,
		vastnfsDebugPath: vastnfsDebugPath,
		sunrpcDebugPath:  sunrpcDebugPath,
		inflight: prometheus.NewDesc(
			MetricPrefix+"nfs_rpc_inflight_requests",
			"Number of NFS RPC requests currently outstanding (sunrpc per-client task list). Includes queued-but-untransmitted requests; zero when nothing is waiting.",
			[]string{"volume_id"},
			nil,
		),
		collectionErrors: prometheus.NewDesc(
			MetricPrefix+"nfs_inflight_collection_errors_total",
			"Total number of errors during NFS in-flight collection",
			nil,
			nil,
		),
	}
}

func (c *NFSInflightCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.inflight
	ch <- c.collectionErrors
}

func (c *NFSInflightCollector) Collect(ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("NFSInflightCollector panic recovered: %v", r)
		}
	}()

	if _, err := os.Stat(c.vastnfsDebugPath); err != nil {
		c.warnMissingOnce.Do(func() {
			log.Warnf("NFS in-flight collector idle: %s not readable (%v) - needs vastnfs + debugfs access", c.vastnfsDebugPath, err)
		})
		return
	}

	errorCount := 0.0

	devToVolumes, err := c.volumesByDevice()
	if err != nil {
		log.Errorf("Error reading %s: %v", c.mountInfoPath, err)
		ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, 1)
		return
	}

	// sb_id -> rpc_id from the vastnfs superblock table.
	sbEntries, err := filepath.Glob(filepath.Join(c.vastnfsDebugPath, "nfs_sb", "*"))
	if err != nil {
		log.Errorf("Error listing %s/nfs_sb: %v", c.vastnfsDebugPath, err)
		ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, 1)
		return
	}

	// A volume can appear under several superblocks (e.g. subpath mounts
	// with their own transports); sum their task counts. A superblock read
	// only once cannot double-count.
	inflightByVolume := make(map[string]float64)
	for _, entry := range sbEntries {
		sbID, rpcID, ok := parseNfsSbFile(entry)
		if !ok {
			// Entry vanished mid-read (unmount) or unexpected format.
			continue
		}
		volumes, mounted := devToVolumes[sbID]
		if !mounted {
			continue
		}
		count, err := countTasks(filepath.Join(c.sunrpcDebugPath, "rpc_clnt", strconv.FormatInt(rpcID, 16), "tasks"))
		if err != nil {
			// Client torn down between the sb read and the task read.
			continue
		}
		for volumeID := range volumes {
			inflightByVolume[volumeID] += count
		}
	}

	for volumeID, count := range inflightByVolume {
		ch <- prometheus.MustNewConstMetric(c.inflight, prometheus.GaugeValue, count, volumeID)
	}
	ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, errorCount)
}

// volumesByDevice maps each NFS mount's st_dev ("maj:min", mountinfo
// field 3) to the set of volume IDs mounted from it.
func (c *NFSInflightCollector) volumesByDevice() (map[string]map[string]bool, error) {
	file, err := os.Open(c.mountInfoPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// mountinfo: <id> <parent> <maj:min> <root> <mountpoint> ... - <fstype> <source> <super opts>
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep == -1 || sep+2 >= len(fields) || len(fields) < 5 {
			continue
		}
		fstype := fields[sep+1]
		if fstype != "nfs" && fstype != "nfs4" {
			continue
		}
		// Same volume_id shape as the mountstats collectors: everything
		// after /volumes/ in the source path.
		source := fields[sep+2]
		idx := strings.Index(source, "/volumes/")
		if idx == -1 {
			continue
		}
		volumeID := source[idx+len("/volumes/"):]
		dev := fields[2]
		if result[dev] == nil {
			result[dev] = make(map[string]bool)
		}
		result[dev][volumeID] = true
	}
	return result, scanner.Err()
}

// parseNfsSbFile reads one <vastnfs>/nfs_sb entry ("sb_id: maj:min",
// "rpc_id: N", ...).
func parseNfsSbFile(path string) (sbID string, rpcID int64, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, false
	}
	rpcID = -1
	for _, line := range strings.Split(string(data), "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(name) {
		case "sb_id":
			sbID = strings.TrimSpace(value)
		case "rpc_id":
			rpcID, err = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return "", 0, false
			}
		}
	}
	if sbID == "" || rpcID < 0 {
		return "", 0, false
	}
	return sbID, rpcID, true
}

// countTasks returns the number of outstanding RPC tasks (one per line)
// in a sunrpc rpc_clnt tasks file.
func countTasks(path string) (float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", path, err)
	}
	return float64(bytes.Count(data, []byte("\n"))), nil
}
