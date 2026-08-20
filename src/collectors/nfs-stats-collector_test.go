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
	// rpcCount, rpcTimeouts, rpcRttMs, rpcExeMs, bytesSent, bytesRecv,
	// backlog, collectionErrors = 8
	want := 8
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
	}
	for op, want := range wantPresent {
		if got, ok := gotOps[op]; !ok || got != want {
			t.Errorf("nfs_rpc_count_total{nfs_operation=%q} = %v (present=%v), want %v", op, got, ok, want)
		}
	}

	// Zero-ops tracked ops (remove, rename, commit, readdir, readdirplus)
	// are skipped, matching the existing zero-ops-skip behavior for
	// read/write (nfs-stats-collector.go).
	for _, op := range []string{"remove", "rename", "commit", "readdir", "readdirplus"} {
		if _, ok := gotOps[op]; ok {
			t.Errorf("op %q has ops=0 in the fixture and should be skipped, but a series was emitted", op)
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
	// batch job hadn't started actual data access at capture time) and
	// should be skipped like any other zero-ops line.
	for _, op := range []string{"read", "getattr"} {
		if _, ok := gotOps[op]; ok {
			t.Errorf("op %q has ops=0 across all 463 blocks in the fixture and should be skipped, but a series was emitted", op)
		}
	}

	// setattr has nonzero ops in this fixture too but remains untracked.
	if _, ok := gotOps["setattr"]; ok {
		t.Errorf("untracked op %q must not appear in output even with nonzero ops across many blocks", "setattr")
	}
}
