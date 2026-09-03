package collectors

import (
	"bufio"
	"metrics-exporter/src/log"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// nfsServerPort is the TCP port every NFS data connection targets. Sockets in
// /proc/net/tcp whose remote port is not this are not NFS and are skipped.
const nfsServerPort = 2049

// NFSSockStateCollector reports the live TCP state of each nconnect transport,
// joined to the NFS lane by source port. It reads two files the exporter
// already has access to (/proc/1/net/tcp and tcp6, same host-proc mount as
// mountstats) and needs no extra privilege.
//
// Why it exists: mountstats gives per-lane activity counters (sends, recvs,
// reconnect count, queue utilisation) but never the transport's current TCP
// state, nor how much data is stuck in the socket's send/receive buffer. A
// mount/umount stall driven by a wedged or reset connection is invisible in
// mountstats, and the eBPF latency probe only counts retransmits per server
// IP, not per connection. This closes that gap at the TCP layer.
//
// The join. The mountstats `xprt: tcp <srcport> ...` line carries the source
// port of that transport's socket (field index 2). /proc/net/tcp lists every
// socket by (local_address:local_port, rem_address:rem_port, state, tx_queue,
// rx_queue, retransmit_timeouts). Match the lane's source port to the socket's
// local port, filtering to remote port 2049, and emit per (volume_id,
// xprt_idx) so the new series line up with the existing per-lane metrics. Both
// files are read in the same scrape, so the join is point-in-time consistent
// even though the kernel regenerates the source port on reconnect.
//
// A lane whose source port has no matching NFS socket (mid-reconnect, or torn
// down) emits tcp_state=0, a sentinel below every real TCP state (1..11), and
// emits no queue series because there is no socket to report bytes for.
type NFSSockStateCollector struct {
	mountStatsPath string
	tcpPath        string
	tcp6Path       string

	tcpState         *prometheus.Desc
	txQueueBytes     *prometheus.Desc
	rxQueueBytes     *prometheus.Desc
	retransTimeouts  *prometheus.Desc
	collectionErrors *prometheus.Desc
}

func NewNFSSockStateCollector(mountStatsPath, tcpPath, tcp6Path string) *NFSSockStateCollector {
	labels := []string{"volume_id", "xprt_idx"}
	return &NFSSockStateCollector{
		mountStatsPath: mountStatsPath,
		tcpPath:        tcpPath,
		tcp6Path:       tcp6Path,
		tcpState: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_tcp_state",
			"TCP state of this xprt (lane) socket, from /proc/net/tcp. Kernel state codes: 1=ESTABLISHED, 2=SYN_SENT, 3=SYN_RECV, 4=FIN_WAIT1, 5=FIN_WAIT2, 6=TIME_WAIT, 7=CLOSE, 8=CLOSE_WAIT, 9=LAST_ACK, 10=LISTEN, 11=CLOSING, 12=NEW_SYN_RECV. 0 is a sentinel: the lane's source port has no unambiguous NFS socket right now (mid-reconnect, torn down, or a source-port collision across lanes). Note a lane can wedge while staying ESTABLISHED, so watch nfs_xprt_tx_queue_bytes for a stuck lane; state != 1 catches reset or half-closed lanes.",
			labels, nil,
		),
		txQueueBytes: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_tx_queue_bytes",
			"Bytes queued in this xprt socket's send buffer, not yet acknowledged by the server (/proc/net/tcp tx_queue). A sustained rise is data backing up because the connection is not draining, the direct wedged-lane signal.",
			labels, nil,
		),
		rxQueueBytes: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_rx_queue_bytes",
			"Bytes received into this xprt socket's receive buffer, not yet read by the NFS client (/proc/net/tcp rx_queue).",
			labels, nil,
		),
		retransTimeouts: prometheus.NewDesc(
			MetricPrefix+"nfs_xprt_retransmit_timeouts",
			"Unrecovered retransmit timeouts on this xprt socket (/proc/net/tcp retrnsmt field). A gauge, not a counter: it tracks the current socket and resets on TCP recovery (forward progress), not only on reconnect.",
			labels, nil,
		),
		collectionErrors: prometheus.NewDesc(
			MetricPrefix+"nfs_sock_state_collection_errors_total",
			"Total errors encountered while joining mountstats xprt source ports to /proc/net/tcp sockets.",
			nil, nil,
		),
	}
}

func (c *NFSSockStateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.tcpState
	ch <- c.txQueueBytes
	ch <- c.rxQueueBytes
	ch <- c.retransTimeouts
	ch <- c.collectionErrors
}

// laneKey identifies one transport lane, matching the existing xprt collector.
type laneKey struct {
	volumeID string
	xprtIdx  int
}

// sockInfo holds the fields we take from one /proc/net/tcp socket line.
// remoteAddr is the raw "addr:port" hex token, kept only to detect two NFS
// sockets sharing a local port (different remotes), which makes that port
// ambiguous.
type sockInfo struct {
	state      float64
	txQueue    float64
	rxQueue    float64
	retransmt  float64
	remoteAddr string
}

func (c *NFSSockStateCollector) Collect(ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("NFSSockStateCollector panic recovered: %v", r)
		}
	}()

	errorCount := 0.0

	// Map every lane (volume_id, xprt_idx) to its source port. A nil map means
	// the file could not be opened (fatal, like the sibling collectors); a
	// non-nil map with a non-nil error is a partial read from a mid-file scan
	// error, which we count but still emit.
	laneSrcPort, msErr := c.parseMountstatsSrcPorts()
	if laneSrcPort == nil {
		log.Errorf("Error opening %s: %v", c.mountStatsPath, msErr)
		ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, 1)
		return
	}
	if msErr != nil {
		log.Warnf("sock-state: reading %s: %v", c.mountStatsPath, msErr)
		errorCount++
	}

	// A source port shared by more than one lane cannot be attributed to a
	// single socket: the lanes reach different VIPs, and mountstats never
	// records which VIP a lane uses, so there is nothing to disambiguate them
	// by. Mark those ports ambiguous and report the sentinel for them rather
	// than guess, the same discipline the volume-ID mapping uses for an IP
	// that serves multiple exports (nfs-latency-collector.go).
	ambiguous := make(map[uint64]bool)
	laneCount := make(map[uint64]int)
	for _, srcPort := range laneSrcPort {
		laneCount[srcPort]++
	}
	for srcPort, n := range laneCount {
		if n > 1 {
			ambiguous[srcPort] = true
		}
	}

	// Snapshot NFS sockets by local port. A missing tcp6 file (IPv6 disabled)
	// is benign and not counted; a genuine read error is. parseProcNetTCP also
	// flags a local port carrying two different NFS remotes as ambiguous.
	sockets := make(map[uint64]sockInfo)
	for _, p := range []string{c.tcpPath, c.tcp6Path} {
		if err := parseProcNetTCP(p, sockets, ambiguous); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			log.Warnf("sock-state: reading %s: %v", p, err)
			errorCount++
		}
	}

	for key, srcPort := range laneSrcPort {
		idxStr := strconv.Itoa(key.xprtIdx)
		s, ok := sockets[srcPort]
		if !ok || ambiguous[srcPort] {
			// No socket on this lane's source port, or the source port cannot
			// be attributed to one socket. Emit the sentinel state only.
			ch <- prometheus.MustNewConstMetric(c.tcpState, prometheus.GaugeValue, 0, key.volumeID, idxStr)
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.tcpState, prometheus.GaugeValue, s.state, key.volumeID, idxStr)
		ch <- prometheus.MustNewConstMetric(c.txQueueBytes, prometheus.GaugeValue, s.txQueue, key.volumeID, idxStr)
		ch <- prometheus.MustNewConstMetric(c.rxQueueBytes, prometheus.GaugeValue, s.rxQueue, key.volumeID, idxStr)
		ch <- prometheus.MustNewConstMetric(c.retransTimeouts, prometheus.GaugeValue, s.retransmt, key.volumeID, idxStr)
	}

	ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, errorCount)
}

// parseMountstatsSrcPorts walks /proc/self/mountstats and returns, for every
// TCP xprt line, the source port of that lane keyed by (volume_id, xprt_idx).
// xprt_idx is the 0-based scan order within the mount block, identical to the
// NFSXprtCollector so the series align. Returns an error only if the file
// cannot be opened; malformed lines are skipped.
func (c *NFSSockStateCollector) parseMountstatsSrcPorts() (map[laneKey]uint64, error) {
	file, err := os.Open(c.mountStatsPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	out := make(map[laneKey]uint64)
	scanner := bufio.NewScanner(file)
	currentVolumeID := ""
	currentXprtIdx := 0

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}

		if fields[0] == "device" && len(fields) >= 2 {
			if idx := strings.Index(fields[1], "/volumes/"); idx != -1 {
				currentVolumeID = fields[1][idx+len("/volumes/"):]
			} else {
				currentVolumeID = ""
			}
			currentXprtIdx = 0
			continue
		}

		if fields[0] != "xprt:" {
			continue
		}
		if len(fields) < 3 || fields[1] != "tcp" {
			continue
		}
		// This is a TCP xprt line. Advance the ordinal even if the source
		// port fails to parse, so later lanes keep their kernel-order index.
		idx := currentXprtIdx
		currentXprtIdx++
		if currentVolumeID == "" {
			continue
		}
		srcPort, perr := strconv.ParseUint(fields[2], 10, 32)
		if perr != nil {
			continue
		}
		out[laneKey{volumeID: currentVolumeID, xprtIdx: idx}] = srcPort
	}
	return out, scanner.Err()
}

// parseProcNetTCP reads a /proc/net/tcp or tcp6 file and inserts one entry per
// NFS socket (remote port 2049) into `sockets`, keyed by local (source) port.
// If two NFS sockets share a local port (different remotes), the port is added
// to `ambiguous` so the caller reports the sentinel rather than pick one. The
// two files share a column layout; the only difference is the address width,
// and we take the port after the last ':' so both parse identically.
func parseProcNetTCP(path string, sockets map[uint64]sockInfo, ambiguous map[uint64]bool) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// A socket row needs at least through the retransmit-timeout field
		// (index 6). The header row ("sl local_address ...") and any short
		// line falls below this and is skipped.
		if len(fields) < 10 || fields[1] == "local_address" {
			continue
		}

		remPort, ok := portAfterColon(fields[2])
		if !ok || remPort != nfsServerPort {
			continue
		}
		localPort, ok := portAfterColon(fields[1])
		if !ok {
			continue
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}
		tx, rx, ok := parseTxRxQueue(fields[4])
		if !ok {
			continue
		}
		retrans, err := strconv.ParseUint(fields[6], 16, 32)
		if err != nil {
			continue
		}
		if existing, ok := sockets[localPort]; ok && existing.remoteAddr != fields[2] {
			// Two NFS sockets on the same local port to different remotes.
			// The lane's source port can no longer name one socket.
			ambiguous[localPort] = true
		}
		sockets[localPort] = sockInfo{
			state:      float64(state),
			txQueue:    float64(tx),
			rxQueue:    float64(rx),
			retransmt:  float64(retrans),
			remoteAddr: fields[2],
		}
	}
	return scanner.Err()
}

// portAfterColon parses the hex port that follows the last ':' of an
// "address:port" field. Robust for both the 8-hex IPv4 and 32-hex IPv6 address
// forms, neither of which contains an internal ':'.
func portAfterColon(field string) (uint64, bool) {
	i := strings.LastIndexByte(field, ':')
	if i < 0 || i+1 >= len(field) {
		return 0, false
	}
	p, err := strconv.ParseUint(field[i+1:], 16, 32)
	if err != nil {
		return 0, false
	}
	return p, true
}

// parseTxRxQueue splits the "tx_queue:rx_queue" field (both hex) into bytes.
func parseTxRxQueue(field string) (tx, rx uint64, ok bool) {
	i := strings.IndexByte(field, ':')
	if i < 0 {
		return 0, 0, false
	}
	t, err := strconv.ParseUint(field[:i], 16, 64)
	if err != nil {
		return 0, 0, false
	}
	r, err := strconv.ParseUint(field[i+1:], 16, 64)
	if err != nil {
		return 0, 0, false
	}
	return t, r, true
}
