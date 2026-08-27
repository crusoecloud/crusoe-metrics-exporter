package collectors

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNFSStatsCollectorDescribe(t *testing.T) {
	c := NewNFSStatsCollector("/nonexistent")
	ch := make(chan *prometheus.Desc, 32)
	c.Describe(ch)
	close(ch)

	got := 0
	for range ch {
		got++
	}
	// rpcCount, rpcTimeouts, rpcRetrans, rpcErrors, rpcRttMs, rpcExeMs,
	// rpcQueueMs, bytesSent, bytesRecv, backlog, collectionErrors = 11
	want := 11
	if got != want {
		t.Errorf("Describe emitted %d descriptors, want %d", got, want)
	}
}

// TestNFSStatsCollector_AllTrackedOps exercises every op in trackedOps with
// distinct values per field, plus one untracked op (SETATTR) that must not
// appear in the output. Distinct values so a field-index mistake surfaces as
// a wrong number rather than a coincidental zero.
func TestNFSStatsCollector_AllTrackedOps(t *testing.T) {
	// Per-op line format: OP: ops trans maj_to bytes_sent bytes_recv queue rtt exe errors
	fixture := "" +
		"device nfs.example.com:/volumes/aaaaaaaa-1111-2222-3333-444444444444 mounted on /mnt/sharedfs with fstype nfs statvers=1.1\n" +
		"\tper-op statistics\n" +
		"\t       READ: 101 101 1 111 121 131 141 151 1\n" +
		"\t      WRITE: 102 102 2 112 122 132 142 152 2\n" +
		"\t    GETATTR: 103 103 3 113 123 133 143 153 3\n" +
		"\t     LOOKUP: 104 104 4 114 124 134 144 154 4\n" +
		"\t     ACCESS: 105 105 5 115 125 135 145 155 5\n" +
		"\t     CREATE: 106 106 6 116 126 136 146 156 6\n" +
		"\t     REMOVE: 107 107 7 117 127 137 147 157 7\n" +
		"\t     RENAME: 108 108 8 118 128 138 148 158 8\n" +
		"\t     COMMIT: 109 109 9 119 129 139 149 159 9\n" +
		"\t    READDIR: 110 110 10 120 130 140 150 160 10\n" +
		"\tREADDIRPLUS: 111 111 11 121 131 141 151 161 11\n" +
		"\t       NULL: 112 112 12 122 132 142 152 162 12\n" +
		"\t     FSSTAT: 113 113 13 123 133 143 153 163 13\n" +
		"\t     FSINFO: 114 114 14 124 134 144 154 164 14\n" +
		"\t   PATHCONF: 115 115 15 125 135 145 155 165 15\n" +
		"\t    SETATTR: 999 999 99 999 999 999 999 999 99\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSStatsCollector(path))

	gotOps := map[string]float64{}
	seenOperations := map[string]bool{}
	for _, m := range metrics {
		if fqName(m) != "crusoe_vm_nfs_rpc_count_total" {
			continue
		}
		l := metricLabels(m)
		seenOperations[l["nfs_operation"]] = true
		gotOps[l["nfs_operation"]] = metricValue(m)
	}

	wantOps := map[string]float64{
		"read": 101, "write": 102, "getattr": 103, "lookup": 104,
		"access": 105, "create": 106, "remove": 107, "rename": 108,
		"commit": 109, "readdir": 110, "readdirplus": 111,
		"null": 112, "fsstat": 113, "fsinfo": 114, "pathconf": 115,
	}
	for op, want := range wantOps {
		if got, ok := gotOps[op]; !ok || got != want {
			t.Errorf("nfs_rpc_count_total{nfs_operation=%q} = %v (present=%v), want %v", op, got, ok, want)
		}
	}
	if seenOperations["setattr"] {
		t.Errorf("untracked op %q must not appear in output", "setattr")
	}
	if len(seenOperations) != len(wantOps) {
		t.Errorf("got %d distinct nfs_operation values, want %d (exactly the tracked set)", len(seenOperations), len(wantOps))
	}
}

func TestNFSStatsCollector_MultipleMountBlocks_MaxAggregation(t *testing.T) {
	// Same volume mounted in two blocks (e.g. same PV into two pods on
	// the same node) — counters dedupe by max across blocks.
	fixture := "" +
		"device nfs.example.com:/volumes/cccccccc-1111-2222-3333-444444444444 mounted on /mnt/a with fstype nfs statvers=1.1\n" +
		"\tper-op statistics\n" +
		"\tGETATTR: 50 50 0 500 500 0 50 50 0\n" +
		"device nfs.example.com:/volumes/cccccccc-1111-2222-3333-444444444444 mounted on /mnt/b with fstype nfs statvers=1.1\n" +
		"\tper-op statistics\n" +
		"\tGETATTR: 80 80 0 800 800 0 80 80 0\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSStatsCollector(path))

	count := 0
	var ops float64
	for _, m := range metrics {
		if fqName(m) != "crusoe_vm_nfs_rpc_count_total" {
			continue
		}
		l := metricLabels(m)
		if l["volume_id"] != "cccccccc-1111-2222-3333-444444444444" || l["nfs_operation"] != "getattr" {
			continue
		}
		count++
		ops = metricValue(m)
	}

	if count != 1 {
		t.Errorf("expected 1 getattr series after dedupe, got %d", count)
	}
	if ops != 80 {
		t.Errorf("getattr ops after dedupe = %v, want 80 (max across blocks)", ops)
	}
}

func TestNFSStatsCollector_MalformedLineSkipped(t *testing.T) {
	// A tracked-op line with a non-numeric ops count should not panic and
	// should surface in collection_errors. Other valid ops in the same
	// file emit normally. (A too-short line is silently skipped by the
	// existing len(fields) < 10 guard with no error counted — that's the
	// pre-existing behavior for this collector, not exercised here.)
	fixture := "" +
		"device nfs.example.com:/volumes/dddddddd-1111-2222-3333-444444444444 mounted on /mnt/sharedfs with fstype nfs statvers=1.1\n" +
		"\tper-op statistics\n" +
		"\tGETATTR: not-a-number 1 2 3 4 5 6 7 8\n" +
		"\tLOOKUP: 40 40 0 400 400 0 40 40 0\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSStatsCollector(path))

	var lookupOps, collectionErrors float64
	for _, m := range metrics {
		switch fqName(m) {
		case "crusoe_vm_nfs_rpc_count_total":
			if metricLabels(m)["nfs_operation"] == "lookup" {
				lookupOps = metricValue(m)
			}
		case "crusoe_vm_nfs_stats_collection_errors_total":
			collectionErrors = metricValue(m)
		}
	}

	if lookupOps != 40 {
		t.Errorf("valid op after malformed line should still emit ops=40, got %v", lookupOps)
	}
	if collectionErrors == 0 {
		t.Errorf("expected collection_errors > 0 for malformed op line")
	}
}

// TestNFSStatsCollector_QueueTime pins the per-op queue field (mountstats
// index 6) to its own metric, and pins the field ordering: queue, rtt, exe are
// fields 6, 7, 8, so a shifted read would silently report the wrong number.
func TestNFSStatsCollector_QueueTime(t *testing.T) {
	// Per-op line format: OP: ops trans maj_to bytes_sent bytes_recv queue rtt exe errors
	// queue=600, rtt=70, exe=800 -> deliberately distinct so a field shift fails.
	fixture := "device 10.0.0.1:/volumes/vol-queue mounted on /mnt/q with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 0 0 1 0 0 100 100 0 0 0 2 0 0\n" +
		"\tper-op statistics\n" +
		"\tWRITE: 10 10 0 1000 1000 600 70 800 0\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSStatsCollector(path))

	want := map[string]float64{
		"crusoe_vm_nfs_rpc_queue_ms_total": 600,
		"crusoe_vm_nfs_rpc_rtt_ms_total":   70,
		"crusoe_vm_nfs_rpc_exe_ms_total":   800,
	}
	got := map[string]float64{}
	for _, m := range metrics {
		if _, tracked := want[fqName(m)]; tracked && metricLabels(m)["nfs_operation"] == "write" {
			got[fqName(m)] = metricValue(m)
		}
	}
	for name, w := range want {
		v, ok := got[name]
		if !ok {
			t.Errorf("%s{nfs_operation=\"write\"} not emitted", name)
			continue
		}
		if v != w {
			t.Errorf("%s = %v, want %v (field-order regression?)", name, v, w)
		}
	}
}

func TestNFSStatsCollector_MissingFile_GracefulError(t *testing.T) {
	c := NewNFSStatsCollector("/nonexistent/path/that/does/not/exist")
	metrics := collectMetrics(t, c)

	var collectionErrors float64
	rpcSeries := 0
	for _, m := range metrics {
		name := fqName(m)
		if name == "crusoe_vm_nfs_stats_collection_errors_total" {
			collectionErrors = metricValue(m)
			continue
		}
		if name == "crusoe_vm_nfs_rpc_count_total" {
			rpcSeries++
		}
	}

	if collectionErrors == 0 {
		t.Errorf("expected collection_errors > 0 for missing mountstats file")
	}
	if rpcSeries != 0 {
		t.Errorf("expected 0 rpc_count series for missing file, got %d", rpcSeries)
	}
}

// TestNFSStatsCollector_GoldenFixture_NconnectMount runs the collector
// against the same real /proc/self/mountstats capture used by the xprt and
// mount-events collectors' golden tests, verifying the newly-tracked
// metadata/write-churn ops parse correctly from real kernel output, not just
// synthetic fixtures.
func TestNFSStatsCollector_GoldenFixture_NconnectMount(t *testing.T) {
	metrics := collectMetrics(t, NewNFSStatsCollector("testdata/mountstats_real_nconnect16.txt"))

	vol := "00000000-0000-0000-0000-000000000001"
	gotOps := map[string]float64{}
	for _, m := range metrics {
		if fqName(m) != "crusoe_vm_nfs_rpc_count_total" {
			continue
		}
		l := metricLabels(m)
		if l["volume_id"] != vol {
			continue
		}
		gotOps[l["nfs_operation"]] = metricValue(m)
	}

	// Known values read directly from testdata/mountstats_real_nconnect16.txt.
	wantPresent := map[string]float64{
		"read": 637414, "write": 1410, "getattr": 35, "lookup": 21,
		"access": 11, "create": 12,
		// Mount-time RPCs: the ops a mount() issues before any I/O.
		"null": 16, "fsstat": 3, "fsinfo": 2, "pathconf": 1,
	}
	for op, want := range wantPresent {
		if got, ok := gotOps[op]; !ok || got != want {
			t.Errorf("nfs_rpc_count_total{nfs_operation=%q} = %v (present=%v), want %v", op, got, ok, want)
		}
	}

	// Tracked ops with ops=0 are still exported, as zero. An absent counter
	// cannot be distinguished from an uninstrumented one, breaks rate(), and
	// makes "idle" and "not collected" look identical to an alert.
	for _, op := range []string{"remove", "rename", "commit", "readdir", "readdirplus"} {
		got, ok := gotOps[op]
		if !ok {
			t.Errorf("op %q has ops=0 in the fixture and must still be exported as 0, but no series was emitted", op)
			continue
		}
		if got != 0 {
			t.Errorf("nfs_rpc_count_total{nfs_operation=%q} = %v, want 0", op, got)
		}
	}

	// setattr is present in the fixture with nonzero ops (3) but is
	// deliberately untracked.
	if _, ok := gotOps["setattr"]; ok {
		t.Errorf("untracked op %q must not appear in output even with nonzero ops in the fixture", "setattr")
	}
}

// TestNFSStatsCollector_GoldenFixture_SharedVolumeManyMounts runs the
// collector against a real capture of the same NFS volume mounted 463 times
// on one host (a batch-job scale-out sharing one read-mostly dataset across
// many pods). All 463 mount blocks report the same volume_id, so this is a
// real-world, large-N instance of the multi-mount-block max-merge dedup path
// that the existing synthetic tests only exercise at N=2 -- it confirms
// dedup collapses to one series per (volume_id, operation) rather than
// double-counting (or timing out) at scale.
func TestNFSStatsCollector_GoldenFixture_SharedVolumeManyMounts(t *testing.T) {
	metrics := collectMetrics(t, NewNFSStatsCollector("testdata/mountstats_real_shared_volume_463mounts.txt"))

	vol := "00000000-0000-0000-0000-000000000001"
	gotOps := map[string]float64{}
	seriesCount := map[string]int{}
	for _, m := range metrics {
		if fqName(m) != "crusoe_vm_nfs_rpc_count_total" {
			continue
		}
		l := metricLabels(m)
		if l["volume_id"] != vol {
			continue
		}
		gotOps[l["nfs_operation"]] = metricValue(m)
		seriesCount[l["nfs_operation"]]++
	}

	// Known max-across-463-blocks values, computed directly from the
	// fixture (ops counts vary slightly per block since each pod mount
	// accumulated its own independent metadata traffic during startup).
	wantMax := map[string]float64{
		"lookup": 13906,
		"access": 13907,
	}
	for op, want := range wantMax {
		if got, ok := gotOps[op]; !ok || got != want {
			t.Errorf("nfs_rpc_count_total{nfs_operation=%q} = %v (present=%v), want %v (max across 463 blocks)", op, got, ok, want)
		}
		if seriesCount[op] != 1 {
			t.Errorf("nfs_operation=%q: got %d series across 463 mount blocks, want exactly 1 (dedup should collapse them)", op, seriesCount[op])
		}
	}

	// read/getattr are zero across all 463 blocks in this fixture (the
	// batch job hadn't started actual data access at capture time) and must
	// still be exported as 0, deduped to one series like any other op.
	for _, op := range []string{"read", "getattr"} {
		got, ok := gotOps[op]
		if !ok {
			t.Errorf("op %q is zero across all 463 blocks and must still be exported as 0, but no series was emitted", op)
			continue
		}
		if got != 0 {
			t.Errorf("nfs_rpc_count_total{nfs_operation=%q} = %v, want 0", op, got)
		}
		if seriesCount[op] != 1 {
			t.Errorf("nfs_operation=%q: got %d series across 463 mount blocks, want exactly 1", op, seriesCount[op])
		}
	}

	// setattr has nonzero ops in this fixture too but remains untracked.
	if _, ok := gotOps["setattr"]; ok {
		t.Errorf("untracked op %q must not appear in output even with nonzero ops across many blocks", "setattr")
	}
}

// TestNFSStatsCollector_RetransAndErrors pins the trans (field 2) and errors
// (field 9) per-op fields. trans counts transmissions where ops counts
// operations, so trans - ops is the retransmit count; errors counts ops whose
// RPC completed with an error status from the server. Values are distinct
// from every other field on the line so a field shift causes a test failure.
func TestNFSStatsCollector_RetransAndErrors(t *testing.T) {
	// Per-op line format: OP: ops trans maj_to bytes_sent bytes_recv queue rtt exe errors
	// WRITE: ops=10, trans=25 → retransmits=15; errors=4.
	// GETATTR: ops==trans → retransmits=0; errors=0.
	fixture := "" +
		"device nfs.example.com:/volumes/eeeeeeee-5555-6666-7777-888888888888 mounted on /mnt/r with fstype nfs statvers=1.1\n" +
		"\tper-op statistics\n" +
		"\t  WRITE: 10 25 3 1000 2000 600 70 800 4\n" +
		"\tGETATTR: 7 7 0 100 100 0 5 5 0\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSStatsCollector(path))

	type key struct{ name, op string }
	got := map[key]float64{}
	for _, m := range metrics {
		l := metricLabels(m)
		if l["volume_id"] != "eeeeeeee-5555-6666-7777-888888888888" {
			continue
		}
		got[key{fqName(m), l["nfs_operation"]}] = metricValue(m)
	}

	cases := []struct {
		name, op string
		want     float64
	}{
		{"crusoe_vm_nfs_rpc_retransmits_total", "write", 15},
		{"crusoe_vm_nfs_rpc_errors_total", "write", 4},
		{"crusoe_vm_nfs_rpc_timeouts_total", "write", 3},
		{"crusoe_vm_nfs_rpc_retransmits_total", "getattr", 0},
		{"crusoe_vm_nfs_rpc_errors_total", "getattr", 0},
	}
	for _, tc := range cases {
		v, ok := got[key{tc.name, tc.op}]
		if !ok {
			t.Errorf("%s{nfs_operation=%q} not emitted", tc.name, tc.op)
			continue
		}
		if v != tc.want {
			t.Errorf("%s{nfs_operation=%q} = %v, want %v", tc.name, tc.op, v, tc.want)
		}
	}
}
