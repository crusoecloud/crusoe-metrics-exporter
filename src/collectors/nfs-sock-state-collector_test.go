package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// writeProcFile writes content to a temp file and returns its path. Used for
// /proc/net/tcp{,6} fixtures.
func writeProcFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// A realistic /proc/net/tcp header line, verbatim from a Linux 5.x host. The
// collector must skip it without counting a parse error.
const procTCPHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func TestNFSSockStateCollector_Describe(t *testing.T) {
	c := NewNFSSockStateCollector("/nonexistent", "/nonexistent", "/nonexistent")
	ch := make(chan *prometheus.Desc, 16)
	c.Describe(ch)
	close(ch)
	got := 0
	for range ch {
		got++
	}
	// tcp_state, tx_queue_bytes, rx_queue_bytes, retransmit_timeouts,
	// collection_errors = 5
	want := 5
	if got != want {
		t.Errorf("Describe emitted %d descriptors, want %d", got, want)
	}
}

// TestNFSSockStateCollector_JoinAndEmit is the core test: two nconnect lanes
// (srcport 729 -> xprt_idx 0, srcport 730 -> xprt_idx 1) joined by source port
// to their /proc/net/tcp sockets, with a non-NFS socket (dst :443) that must be
// ignored. Values are distinct and hex so a field-index or base mistake shows
// as a wrong number, not a coincidental zero.
func TestNFSSockStateCollector_JoinAndEmit(t *testing.T) {
	// srcport 729=0x02D9, 730=0x02DA; NFS dst port 2049=0x0801; 443=0x01BB.
	mountstats := "" +
		"device nfs.example.com:/volumes/aaaaaaaa-1111-2222-3333-444444444444 mounted on /mnt/a with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 729 1 1 0 0 100 100 0 0 0 128 64 27\n" +
		"\txprt:\ttcp 730 1 1 0 0 200 200 0 0 0 128 64 27\n" +
		"\tper-op statistics\n"
	// tx_queue/rx_queue/retrnsmt are hex. Lane 0: ESTABLISHED(01), tx=0x64(100),
	// rx=0, retr=0. Lane 1: CLOSE_WAIT(08), tx=0x1388(5000), rx=0xC8(200), retr=3.
	// Third row is a non-NFS socket (dst :443) and must be dropped.
	tcp := procTCPHeader +
		"   0: 0100007F:02D9 0A00007F:0801 01 00000064:00000000 00:00000000 00000000  1000  0 12345 1 0000 0\n" +
		"   1: 0100007F:02DA 0A00007F:0801 08 00001388:000000C8 01:00000000 00000003  1000  0 12346 1 0000 0\n" +
		"   2: 0100007F:0320 0A00007F:01BB 01 00000000:00000000 00:00000000 00000000  1000  0 12347 1 0000 0\n"

	msPath := writeMountstats(t, mountstats)
	tcpPath := writeProcFile(t, "tcp", tcp)
	metrics := collectMetrics(t, NewNFSSockStateCollector(msPath, tcpPath, "/nonexistent-tcp6"))

	type key struct{ name, idx string }
	got := map[key]float64{}
	for _, m := range metrics {
		l := metricLabels(m)
		if l["volume_id"] != "aaaaaaaa-1111-2222-3333-444444444444" {
			continue
		}
		got[key{fqName(m), l["xprt_idx"]}] = metricValue(m)
	}

	cases := []struct {
		name, idx string
		want      float64
	}{
		{"crusoe_vm_nfs_xprt_tcp_state", "0", 1}, // ESTABLISHED
		{"crusoe_vm_nfs_xprt_tx_queue_bytes", "0", 100},
		{"crusoe_vm_nfs_xprt_rx_queue_bytes", "0", 0},
		{"crusoe_vm_nfs_xprt_retransmit_timeouts", "0", 0},
		{"crusoe_vm_nfs_xprt_tcp_state", "1", 8}, // CLOSE_WAIT
		{"crusoe_vm_nfs_xprt_tx_queue_bytes", "1", 5000},
		{"crusoe_vm_nfs_xprt_rx_queue_bytes", "1", 200},
		{"crusoe_vm_nfs_xprt_retransmit_timeouts", "1", 3},
	}
	for _, tc := range cases {
		v, ok := got[key{tc.name, tc.idx}]
		if !ok {
			t.Errorf("%s{xprt_idx=%s} not emitted", tc.name, tc.idx)
			continue
		}
		if v != tc.want {
			t.Errorf("%s{xprt_idx=%s} = %v, want %v", tc.name, tc.idx, v, tc.want)
		}
	}
}

// TestNFSSockStateCollector_LaneWithNoSocket: mountstats lists a lane whose
// source port has no matching NFS socket in /proc/net/tcp (mid-reconnect /
// torn down). The lane must still emit tcp_state=0 (the "no live socket"
// sentinel; real TCP states are 1..11), and must NOT emit a tx_queue series
// (there is no socket to report bytes for).
func TestNFSSockStateCollector_LaneWithNoSocket(t *testing.T) {
	mountstats := "" +
		"device nfs.example.com:/volumes/bbbbbbbb-1111-2222-3333-444444444444 mounted on /mnt/b with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 999 1 1 0 0 0 0 0 0 0 128 2 0\n" +
		"\tper-op statistics\n"
	// tcp table has an NFS socket, but on a different source port (0x0001).
	tcp := procTCPHeader +
		"   0: 0100007F:0001 0A00007F:0801 01 00000000:00000000 00:00000000 00000000  1000  0 22222 1 0000 0\n"

	msPath := writeMountstats(t, mountstats)
	tcpPath := writeProcFile(t, "tcp", tcp)
	metrics := collectMetrics(t, NewNFSSockStateCollector(msPath, tcpPath, "/nonexistent-tcp6"))

	var stateSeen, stateVal float64
	stateFound := false
	txFound := false
	for _, m := range metrics {
		l := metricLabels(m)
		if l["volume_id"] != "bbbbbbbb-1111-2222-3333-444444444444" {
			continue
		}
		switch fqName(m) {
		case "crusoe_vm_nfs_xprt_tcp_state":
			stateFound = true
			stateVal = metricValue(m)
			stateSeen++
		case "crusoe_vm_nfs_xprt_tx_queue_bytes":
			txFound = true
		}
	}
	if !stateFound {
		t.Fatalf("lane with no socket must still emit tcp_state (as 0)")
	}
	if stateVal != 0 {
		t.Errorf("tcp_state for a lane with no matching socket = %v, want 0", stateVal)
	}
	if txFound {
		t.Errorf("tx_queue_bytes must not be emitted for a lane with no socket")
	}
}

// TestNFSSockStateCollector_TCP6 verifies the IPv6 table parses (longer hex
// local address, same port/queue field positions), joined by source port.
func TestNFSSockStateCollector_TCP6(t *testing.T) {
	mountstats := "" +
		"device nfs.example.com:/volumes/cccccccc-1111-2222-3333-444444444444 mounted on /mnt/c with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 1234 1 1 0 0 0 0 0 0 0 128 4 0\n" +
		"\tper-op statistics\n"
	// srcport 1234=0x04D2, dst port 2049=0x0801, state ESTABLISHED, tx=0x2A(42).
	tcp6 := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000001000000:04D2 00000000000000000000000001000000:0801 01 0000002A:00000000 00:00000000 00000000  1000  0 33333 1 0000 0\n"

	msPath := writeMountstats(t, mountstats)
	tcp6Path := writeProcFile(t, "tcp6", tcp6)
	metrics := collectMetrics(t, NewNFSSockStateCollector(msPath, "/nonexistent-tcp4", tcp6Path))

	var state, tx float64
	for _, m := range metrics {
		if metricLabels(m)["volume_id"] != "cccccccc-1111-2222-3333-444444444444" {
			continue
		}
		switch fqName(m) {
		case "crusoe_vm_nfs_xprt_tcp_state":
			state = metricValue(m)
		case "crusoe_vm_nfs_xprt_tx_queue_bytes":
			tx = metricValue(m)
		}
	}
	if state != 1 {
		t.Errorf("tcp6 lane tcp_state = %v, want 1 (ESTABLISHED)", state)
	}
	if tx != 42 {
		t.Errorf("tcp6 lane tx_queue_bytes = %v, want 42", tx)
	}
}

func TestNFSSockStateCollector_MissingFiles(t *testing.T) {
	c := NewNFSSockStateCollector("/no/mountstats", "/no/tcp", "/no/tcp6")
	metrics := collectMetrics(t, c)

	var collErrors float64
	laneSeries := 0
	for _, m := range metrics {
		name := fqName(m)
		if name == "crusoe_vm_nfs_sock_state_collection_errors_total" {
			collErrors = metricValue(m)
			continue
		}
		if name == "crusoe_vm_nfs_xprt_tcp_state" {
			laneSeries++
		}
	}
	if collErrors == 0 {
		t.Errorf("expected collection_errors > 0 when mountstats is missing")
	}
	if laneSeries != 0 {
		t.Errorf("expected 0 lane series when files are missing, got %d", laneSeries)
	}
}

// TestNFSSockStateCollector_AmbiguousLane: two lanes report the same source
// port (they reach different VIPs; the kernel reused the port). mountstats
// cannot say which socket is which, so both lanes must get the sentinel, while
// a third lane on its own port still reports normally.
func TestNFSSockStateCollector_AmbiguousLane(t *testing.T) {
	// Lanes 0 and 1 both on srcport 729 (0x02D9); lane 2 on srcport 800 (0x0320).
	mountstats := "" +
		"device nfs.example.com:/volumes/dddddddd-1111-2222-3333-444444444444 mounted on /mnt/d with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 729 1 1 0 0 0 0 0 0 0 128 1 0\n" +
		"\txprt:\ttcp 729 1 1 0 0 0 0 0 0 0 128 1 0\n" +
		"\txprt:\ttcp 800 1 1 0 0 0 0 0 0 0 128 1 0\n" +
		"\tper-op statistics\n"
	tcp := procTCPHeader +
		"   0: 0100007F:02D9 0A00007F:0801 01 00000000:00000000 00:00000000 00000000  1000  0 40001 1 0000 0\n" +
		"   1: 0100007F:0320 0A00007F:0801 01 00000064:00000000 00:00000000 00000000  1000  0 40002 1 0000 0\n"

	msPath := writeMountstats(t, mountstats)
	tcpPath := writeProcFile(t, "tcp", tcp)
	metrics := collectMetrics(t, NewNFSSockStateCollector(msPath, tcpPath, "/nonexistent-tcp6"))

	state := map[string]float64{}
	tx := map[string]bool{}
	for _, m := range metrics {
		l := metricLabels(m)
		if l["volume_id"] != "dddddddd-1111-2222-3333-444444444444" {
			continue
		}
		switch fqName(m) {
		case "crusoe_vm_nfs_xprt_tcp_state":
			state[l["xprt_idx"]] = metricValue(m)
		case "crusoe_vm_nfs_xprt_tx_queue_bytes":
			tx[l["xprt_idx"]] = true
		}
	}
	if state["0"] != 0 || state["1"] != 0 {
		t.Errorf("ambiguous lanes must report sentinel 0, got idx0=%v idx1=%v", state["0"], state["1"])
	}
	if tx["0"] || tx["1"] {
		t.Errorf("ambiguous lanes must not emit tx_queue_bytes")
	}
	if state["2"] != 1 {
		t.Errorf("the unambiguous lane (idx 2) must still report state=1, got %v", state["2"])
	}
	if !tx["2"] {
		t.Errorf("the unambiguous lane (idx 2) must emit tx_queue_bytes")
	}
}

// TestNFSSockStateCollector_AmbiguousSocket: one lane, but two NFS sockets
// share its local port (to different remotes). The port cannot name one
// socket, so the lane gets the sentinel.
func TestNFSSockStateCollector_AmbiguousSocket(t *testing.T) {
	mountstats := "" +
		"device nfs.example.com:/volumes/eeeeeeee-1111-2222-3333-444444444444 mounted on /mnt/e with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 729 1 1 0 0 0 0 0 0 0 128 1 0\n" +
		"\tper-op statistics\n"
	// Two NFS sockets on local port 0x02D9, remotes 0A00007F and 0B00007F.
	tcp := procTCPHeader +
		"   0: 0100007F:02D9 0A00007F:0801 01 00000064:00000000 00:00000000 00000000  1000  0 50001 1 0000 0\n" +
		"   1: 0100007F:02D9 0B00007F:0801 08 00001388:00000000 00:00000000 00000000  1000  0 50002 1 0000 0\n"

	msPath := writeMountstats(t, mountstats)
	tcpPath := writeProcFile(t, "tcp", tcp)
	metrics := collectMetrics(t, NewNFSSockStateCollector(msPath, tcpPath, "/nonexistent-tcp6"))

	var state float64
	txFound := false
	for _, m := range metrics {
		if metricLabels(m)["volume_id"] != "eeeeeeee-1111-2222-3333-444444444444" {
			continue
		}
		switch fqName(m) {
		case "crusoe_vm_nfs_xprt_tcp_state":
			state = metricValue(m)
		case "crusoe_vm_nfs_xprt_tx_queue_bytes":
			txFound = true
		}
	}
	if state != 0 {
		t.Errorf("lane whose source port carries two NFS sockets must report sentinel 0, got %v", state)
	}
	if txFound {
		t.Errorf("ambiguous-socket lane must not emit tx_queue_bytes")
	}
}

// TestNFSSockStateCollector_TCP6MissingNotCounted: a missing tcp6 file (IPv6
// disabled) is benign and must not increment collection_errors, which would
// otherwise fire the apparatus-health alert on every scrape.
func TestNFSSockStateCollector_TCP6MissingNotCounted(t *testing.T) {
	mountstats := "" +
		"device nfs.example.com:/volumes/ffffffff-1111-2222-3333-444444444444 mounted on /mnt/f with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 729 1 1 0 0 0 0 0 0 0 128 1 0\n" +
		"\tper-op statistics\n"
	tcp := procTCPHeader +
		"   0: 0100007F:02D9 0A00007F:0801 01 00000000:00000000 00:00000000 00000000  1000  0 60001 1 0000 0\n"

	msPath := writeMountstats(t, mountstats)
	tcpPath := writeProcFile(t, "tcp", tcp)
	metrics := collectMetrics(t, NewNFSSockStateCollector(msPath, tcpPath, "/nonexistent-tcp6"))

	var collErrors, state float64
	for _, m := range metrics {
		switch fqName(m) {
		case "crusoe_vm_nfs_sock_state_collection_errors_total":
			collErrors = metricValue(m)
		case "crusoe_vm_nfs_xprt_tcp_state":
			state = metricValue(m)
		}
	}
	if collErrors != 0 {
		t.Errorf("a missing tcp6 file must not be counted; collection_errors = %v, want 0", collErrors)
	}
	if state != 1 {
		t.Errorf("the tcp lane should still report state=1, got %v", state)
	}
}
