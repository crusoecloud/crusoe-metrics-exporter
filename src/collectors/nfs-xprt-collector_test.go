package collectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Field index reference for the `xprt: tcp <N fields>` line in
// /proc/self/mountstats on Linux 5.x (statvers 1.1). The kernel emits these
// in this order; we only consume the ones we expose as metrics.
//
//	fields[ 0] = "xprt:"
//	fields[ 1] = "tcp"
//	fields[ 2] = srcport         (varies on reconnect; not labelled)
//	fields[ 3] = bind_count
//	fields[ 4] = connect_count   ← SUCCESS counter (TCP_ESTABLISHED transitions)
//	fields[ 5] = connect_time    (HZ ticks, cumulative)
//	fields[ 6] = idle_time       ← seconds since last activity (gauge)
//	fields[ 7] = sends           ← counter
//	fields[ 8] = recvs           ← counter
//	fields[ 9] = bad_xids        ← counter
//	fields[10] = req_u           (cumulative request-slot utilization)
//	fields[11] = bklog_u         ← counter (backlog utilization, cumulative)
//	fields[12] = max_slots       ← gauge (high-water mark of slot table size)
//	fields[13] = sending_u       (cumulative sending utilization)
//	fields[14] = pending_u       (cumulative pending utilization)
//
// Minimum length for a usable line is 13 (so we can reach max_slots at
// index 12). Shorter lines are treated as malformed.

func writeMountstats(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "mountstats")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func collectMetrics(t *testing.T, c prometheus.Collector) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 1024)
	c.Collect(ch)
	close(ch)
	out := make([]prometheus.Metric, 0, 64)
	for m := range ch {
		out = append(out, m)
	}
	return out
}

func metricLabels(m prometheus.Metric) map[string]string {
	dm := &dto.Metric{}
	_ = m.Write(dm)
	out := map[string]string{}
	for _, lp := range dm.Label {
		out[lp.GetName()] = lp.GetValue()
	}
	return out
}

func metricValue(m prometheus.Metric) float64 {
	dm := &dto.Metric{}
	_ = m.Write(dm)
	if dm.Counter != nil {
		return dm.Counter.GetValue()
	}
	if dm.Gauge != nil {
		return dm.Gauge.GetValue()
	}
	return 0
}

func fqName(m prometheus.Metric) string {
	s := m.Desc().String()
	const key = `fqName: "`
	i := strings.Index(s, key)
	if i < 0 {
		return ""
	}
	rest := s[i+len(key):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func TestNFSXprtCollectorDescribe(t *testing.T) {
	c := NewNFSXprtCollector("/nonexistent")
	ch := make(chan *prometheus.Desc, 16)
	c.Describe(ch)
	close(ch)

	got := 0
	for range ch {
		got++
	}
	// 7 per-xprt metrics: sends, recvs, connect_count, bad_xids,
	// max_slots, idle_seconds, backlog_utilization.
	// + 1 collection_errors metric. Total 8.
	want := 8
	if got != want {
		t.Errorf("Describe emitted %d descriptors, want %d", got, want)
	}
}

func TestNFSXprtCollector_SingleXprt(t *testing.T) {
	// One mount, one xprt — happy path. 13 numeric fields after "tcp",
	// matching the Linux 5.x mountstats v1.1 layout documented at top of
	// this file. Tabs between fields just like the kernel emits.
	fixture := "" +
		"device nfs.example.com:/volumes/aaaaaaaa-1111-2222-3333-444444444444 mounted on /mnt/sharedfs with fstype nfs statvers=1.1\n" +
		"\tage:\t100\n" +
		"\txprt:\ttcp 729 1 22 0 7 200830 200829 5 999 3 128 64 27\n" +
		"\tper-op statistics\n" +
		"\t        NULL: 0 0 0 0 0 0 0 0\n"

	path := writeMountstats(t, fixture)
	c := NewNFSXprtCollector(path)

	metrics := collectMetrics(t, c)

	// Expected: 7 per-xprt + 1 collection_errors = 8.
	if len(metrics) != 8 {
		t.Fatalf("got %d metrics, want 8", len(metrics))
	}

	type key struct{ name, vol, idx string }
	values := map[key]float64{}
	for _, m := range metrics {
		l := metricLabels(m)
		values[key{name: fqName(m), vol: l["volume_id"], idx: l["xprt_idx"]}] = metricValue(m)
	}

	vol := "aaaaaaaa-1111-2222-3333-444444444444"
	cases := []struct {
		name string
		want float64
	}{
		// xprt: tcp 729 1 22 0 7 200830 200829 5 999 3 128 64 27
		// idx:       2  3  4 5 6 7      8      9 10  11 12  13 14
		{"crusoe_vm_nfs_xprt_connect_count_total", 22},
		{"crusoe_vm_nfs_xprt_idle_seconds", 7},
		{"crusoe_vm_nfs_xprt_sends_total", 200830},
		{"crusoe_vm_nfs_xprt_recvs_total", 200829},
		{"crusoe_vm_nfs_xprt_bad_xids_total", 5},
		{"crusoe_vm_nfs_xprt_backlog_utilization", 3},
		{"crusoe_vm_nfs_xprt_max_slots", 128},
	}
	for _, tc := range cases {
		got, ok := values[key{name: tc.name, vol: vol, idx: "0"}]
		if !ok {
			t.Errorf("missing series %s{volume_id=%s, xprt_idx=0}", tc.name, vol)
			continue
		}
		if got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNFSXprtCollector_NconnectMount(t *testing.T) {
	// Four xprts in one mount block — verify each gets a distinct
	// xprt_idx (0..3). The dead-lane case (sends=0 with connect_count
	// high) still emits a series so PromQL `count(rate(...) > 0)` can
	// see it as not-firing.
	fixture := "" +
		"device nfs.example.com:/volumes/bbbbbbbb-1111-2222-3333-444444444444 mounted on /mnt/sharedfs with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 701 1 1 0 0 100 100 0 0 0 128 1 0\n" +
		"\txprt:\ttcp 702 1 1 0 0 200 200 0 0 0 128 1 0\n" +
		"\txprt:\ttcp 703 1 1 0 0 300 300 0 0 0 128 1 0\n" +
		"\txprt:\ttcp 704 1 19785 0 999 0 0 0 0 0 2 1 0\n" +
		"\tper-op statistics\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSXprtCollector(path))

	seenSends := map[string]float64{}
	seenIdle := map[string]float64{}
	seenConnect := map[string]float64{}
	seenMaxSlots := map[string]float64{}
	for _, m := range metrics {
		idx := metricLabels(m)["xprt_idx"]
		switch fqName(m) {
		case "crusoe_vm_nfs_xprt_sends_total":
			seenSends[idx] = metricValue(m)
		case "crusoe_vm_nfs_xprt_idle_seconds":
			seenIdle[idx] = metricValue(m)
		case "crusoe_vm_nfs_xprt_connect_count_total":
			seenConnect[idx] = metricValue(m)
		case "crusoe_vm_nfs_xprt_max_slots":
			seenMaxSlots[idx] = metricValue(m)
		}
	}

	for i, want := range map[string]float64{"0": 100, "1": 200, "2": 300, "3": 0} {
		if got, ok := seenSends[i]; !ok || got != want {
			t.Errorf("xprt_idx=%s sends_total = %v (ok=%v), want %v", i, got, ok, want)
		}
	}
	// Dead-lane diagnostic shape: connect_count >> 1, sends == 0,
	// max_slots stuck at 2 (default, never grew). PromQL on those three
	// is the per-lane health test.
	if seenSends["3"] != 0 {
		t.Errorf("dead lane (idx=3) expected sends=0, got %v", seenSends["3"])
	}
	if seenConnect["3"] != 19785 {
		t.Errorf("dead lane connect_count = %v, want 19785", seenConnect["3"])
	}
	if seenMaxSlots["3"] != 2 {
		t.Errorf("dead lane max_slots = %v, want 2 (never grew)", seenMaxSlots["3"])
	}
	if seenIdle["3"] != 999 {
		t.Errorf("dead lane idle_seconds = %v, want 999", seenIdle["3"])
	}
}

func TestNFSXprtCollector_MultipleMountBlocks_MaxAggregation(t *testing.T) {
	// Same volume mounted in two blocks (e.g. same PV into two pods on
	// the same node). Existing nfs-stats-collector dedupes by max
	// across blocks; we do the same here so counters don't double-count
	// the same kernel state.
	fixture := "" +
		"device nfs.example.com:/volumes/cccccccc-1111-2222-3333-444444444444 mounted on /mnt/a with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 800 1 1 0 0 100 100 0 0 0 128 1 0\n" +
		"\tper-op statistics\n" +
		"device nfs.example.com:/volumes/cccccccc-1111-2222-3333-444444444444 mounted on /mnt/b with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 801 1 2 0 0 250 250 0 0 0 128 1 0\n" +
		"\tper-op statistics\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSXprtCollector(path))

	count := 0
	var sends float64
	for _, m := range metrics {
		if fqName(m) != "crusoe_vm_nfs_xprt_sends_total" {
			continue
		}
		l := metricLabels(m)
		if l["volume_id"] != "cccccccc-1111-2222-3333-444444444444" {
			continue
		}
		count++
		sends = metricValue(m)
	}

	if count != 1 {
		t.Errorf("expected 1 sends_total series after dedupe (volume seen in 2 blocks, both xprt_idx=0), got %d", count)
	}
	if sends != 250 {
		t.Errorf("sends_total after dedupe = %v, want 250 (max across blocks)", sends)
	}
}

func TestNFSXprtCollector_MalformedXprtSkipped(t *testing.T) {
	// A truncated xprt line should not panic and should surface in
	// collection_errors. Other valid xprts in the same file emit
	// normally.
	fixture := "" +
		"device nfs.example.com:/volumes/dddddddd-1111-2222-3333-444444444444 mounted on /mnt/sharedfs with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 900 1 1 0 0 999 999 0 0 0 128 1 0\n" +
		"\txprt:\ttcp not-a-number garbage\n" +
		"\tper-op statistics\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSXprtCollector(path))

	var validSends, collectionErrors float64
	for _, m := range metrics {
		switch fqName(m) {
		case "crusoe_vm_nfs_xprt_sends_total":
			if metricLabels(m)["xprt_idx"] == "0" {
				validSends = metricValue(m)
			}
		case "crusoe_vm_nfs_xprt_stats_collection_errors_total":
			collectionErrors = metricValue(m)
		}
	}

	if validSends != 999 {
		t.Errorf("valid xprt before malformed line should still emit sends=999, got %v", validSends)
	}
	if collectionErrors == 0 {
		t.Errorf("expected collection_errors > 0 for malformed xprt line")
	}
}

func TestNFSXprtCollector_MissingFile_GracefulError(t *testing.T) {
	// Missing mountstats file (e.g. host-PID-namespace volume-mount
	// misconfig, the same failure mode that produces collection_errors
	// across 30+ fleet VMs today). Should emit collection_errors and
	// no phantom xprt series.
	c := NewNFSXprtCollector("/nonexistent/path/that/does/not/exist")
	metrics := collectMetrics(t, c)

	var collectionErrors float64
	xprtSeries := 0
	for _, m := range metrics {
		name := fqName(m)
		if name == "crusoe_vm_nfs_xprt_stats_collection_errors_total" {
			collectionErrors = metricValue(m)
			continue
		}
		if strings.HasPrefix(name, "crusoe_vm_nfs_xprt_") {
			xprtSeries++
		}
	}

	if collectionErrors == 0 {
		t.Errorf("expected collection_errors > 0 for missing mountstats file")
	}
	if xprtSeries != 0 {
		t.Errorf("expected 0 xprt series for missing file, got %d", xprtSeries)
	}
}

func TestNFSXprtCollector_VolumeIDExtraction(t *testing.T) {
	// Volume ID comes from the `/volumes/<uuid>` segment of the device
	// path. Mounts that don't match that shape are skipped (no
	// volume_id to attribute the xprt to) — they don't emit
	// empty-volume-id series.
	fixture := "" +
		"device some.nfs.server:/exports/random mounted on /mnt/foo with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 600 1 1 0 0 50 50 0 0 0 128 1 0\n" +
		"\tper-op statistics\n" +
		"device nfs.example.com:/volumes/eeeeeeee-1111-2222-3333-444444444444 mounted on /mnt/bar with fstype nfs statvers=1.1\n" +
		"\txprt:\ttcp 601 1 1 0 0 75 75 0 0 0 128 1 0\n" +
		"\tper-op statistics\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSXprtCollector(path))

	emitted := map[string]float64{}
	for _, m := range metrics {
		if fqName(m) != "crusoe_vm_nfs_xprt_sends_total" {
			continue
		}
		emitted[metricLabels(m)["volume_id"]] = metricValue(m)
	}

	if _, ok := emitted[""]; ok {
		t.Errorf("xprt series emitted with empty volume_id label; non-/volumes/ mount should be skipped entirely")
	}
	if got := emitted["eeeeeeee-1111-2222-3333-444444444444"]; got != 75 {
		t.Errorf("series for /volumes/ mount missing or wrong: got %v want 75", got)
	}
}

// TestNFSXprtCollector_GoldenFixture_NconnectMount runs the collector against
// an anonymised snapshot of a real /proc/self/mountstats from a Linux 5.15
// NFSv3 + nconnect=16 client. Catches kernel-emitted formatting quirks that
// synthetic fixtures might miss — exact tab spacing, field counts, the
// trailing pending_u field.
//
// Identifying details (UUID, internal IP, DNS name) have been replaced with
// placeholders; field counter values are intact from the original capture.
func TestNFSXprtCollector_GoldenFixture_NconnectMount(t *testing.T) {
	metrics := collectMetrics(t, NewNFSXprtCollector("testdata/mountstats_real_nconnect16.txt"))

	// Verify all 16 nconnect lanes were parsed — this is the high-value
	// real-world assertion: a single mount, nconnect=16, every xprt
	// active. If we mis-handle the kernel's tab spacing or the trailing
	// pending_u field this test catches it.
	vol := "00000000-0000-0000-0000-000000000001"
	indices := map[string]bool{}
	for _, m := range metrics {
		if fqName(m) != "crusoe_vm_nfs_xprt_sends_total" {
			continue
		}
		l := metricLabels(m)
		if l["volume_id"] != vol {
			continue
		}
		indices[l["xprt_idx"]] = true
	}

	if len(indices) != 16 {
		t.Errorf("nconnect=16 mount: expected 16 distinct xprt_idx, got %d", len(indices))
	}
	for i := 0; i < 16; i++ {
		key := ""
		switch i {
		case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9:
			key = string(rune('0' + i))
		default:
			key = string(rune('1')) + string(rune('0'+i-10))
		}
		if !indices[key] {
			t.Errorf("missing xprt_idx=%s on real-world nconnect=16 mount", key)
		}
	}

	// Spot-check: first xprt's sends value from the captured file is
	// 40611. If parsing went wrong this comes back wrong.
	for _, m := range metrics {
		if fqName(m) != "crusoe_vm_nfs_xprt_sends_total" {
			continue
		}
		l := metricLabels(m)
		if l["volume_id"] == vol && l["xprt_idx"] == "0" {
			if got := metricValue(m); got != 40611 {
				t.Errorf("first xprt sends_total = %v, want 40611 (from captured data)", got)
			}
			return
		}
	}
	t.Errorf("never found xprt_idx=0 series in golden fixture output")
}
