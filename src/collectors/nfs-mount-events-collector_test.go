package collectors

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNFSMountEventsCollectorDescribe(t *testing.T) {
	c := NewNFSMountEventsCollector("/nonexistent")
	ch := make(chan *prometheus.Desc, 32)
	c.Describe(ch)
	close(ch)

	got := 0
	for range ch {
		got++
	}
	// 4 events counters + 8 bytes counters + 1 age gauge + 1 collection_errors = 14
	want := 14
	if got != want {
		t.Errorf("Describe emitted %d descriptors, want %d", got, want)
	}
}

func TestNFSMountEventsCollector_AllLines(t *testing.T) {
	// Synthetic mountstats with realistic events:/bytes:/age: lines.
	// Values chosen to be distinct so a field-index error in parsing
	// surfaces as a wrong value rather than coincidental zeros.
	//
	// events: indices we consume: 19 (congestion_wait), 23 (short_read),
	// 24 (short_write), 25 (delay). Pad the line with 27 fields total.
	fixture := "" +
		"device nfs.example.com:/volumes/aaaaaaaa-1111-2222-3333-444444444444 mounted on /mnt/sharedfs with fstype nfs statvers=1.1\n" +
		"\tage:\t12345\n" +
		// 27 event counters; positions 19/23/24/25 set to 191/231/241/251.
		// (1-indexed after "events:" header.)
		"\tevents:\t1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 191 20 21 22 231 241 251 26 27\n" +
		// 8 byte counters with distinct values.
		"\tbytes:\t100 200 300 400 500 600 700 800\n" +
		"\tper-op statistics\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSMountEventsCollector(path))

	values := map[string]float64{}
	for _, m := range metrics {
		l := metricLabels(m)
		if l["volume_id"] == "aaaaaaaa-1111-2222-3333-444444444444" {
			values[fqName(m)] = metricValue(m)
		}
	}

	cases := []struct {
		name string
		want float64
	}{
		{"crusoe_vm_nfs_mount_age_seconds", 12345},
		{"crusoe_vm_nfs_mount_congestion_wait_events_total", 191},
		{"crusoe_vm_nfs_mount_short_read_events_total", 231},
		{"crusoe_vm_nfs_mount_short_write_events_total", 241},
		{"crusoe_vm_nfs_mount_delay_events_total", 251},
		{"crusoe_vm_nfs_mount_normal_read_bytes_total", 100},
		{"crusoe_vm_nfs_mount_normal_write_bytes_total", 200},
		{"crusoe_vm_nfs_mount_direct_read_bytes_total", 300},
		{"crusoe_vm_nfs_mount_direct_write_bytes_total", 400},
		{"crusoe_vm_nfs_mount_server_read_bytes_total", 500},
		{"crusoe_vm_nfs_mount_server_write_bytes_total", 600},
		{"crusoe_vm_nfs_mount_read_pages_total", 700},
		{"crusoe_vm_nfs_mount_write_pages_total", 800},
	}
	for _, tc := range cases {
		got, ok := values[tc.name]
		if !ok {
			t.Errorf("missing series %s", tc.name)
			continue
		}
		if got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNFSMountEventsCollector_MultiBlockMaxAggregation(t *testing.T) {
	// Same volume in two mount blocks — counters keep the max across
	// blocks. Age also tracks the older mount (since age is a counter
	// of mount-lifetime; the longer mount represents more activity).
	fixture := "" +
		"device nfs.example.com:/volumes/cccccccc-1111-2222-3333-444444444444 mounted on /mnt/a with fstype nfs statvers=1.1\n" +
		"\tage:\t100\n" +
		"\tevents:\t1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 50 20 21 22 60 70 80 26 27\n" +
		"\tbytes:\t1000 2000 3000 4000 5000 6000 7000 8000\n" +
		"\tper-op statistics\n" +
		"device nfs.example.com:/volumes/cccccccc-1111-2222-3333-444444444444 mounted on /mnt/b with fstype nfs statvers=1.1\n" +
		"\tage:\t250\n" +
		"\tevents:\t1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 70 20 21 22 90 100 200 26 27\n" +
		"\tbytes:\t2000 4000 6000 8000 10000 12000 14000 16000\n" +
		"\tper-op statistics\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSMountEventsCollector(path))

	values := map[string]float64{}
	count := map[string]int{}
	for _, m := range metrics {
		l := metricLabels(m)
		if l["volume_id"] != "cccccccc-1111-2222-3333-444444444444" {
			continue
		}
		name := fqName(m)
		values[name] = metricValue(m)
		count[name]++
	}

	// Expect exactly 1 series per metric (not 2 — dedupe by max).
	for name, n := range count {
		if n != 1 {
			t.Errorf("%s emitted %d series, want 1 (multi-block dedupe failed)", name, n)
		}
	}

	if got := values["crusoe_vm_nfs_mount_age_seconds"]; got != 250 {
		t.Errorf("age_seconds = %v, want 250 (max across blocks)", got)
	}
	if got := values["crusoe_vm_nfs_mount_delay_events_total"]; got != 200 {
		t.Errorf("delay = %v, want 200 (max across blocks)", got)
	}
	if got := values["crusoe_vm_nfs_mount_direct_read_bytes_total"]; got != 6000 {
		t.Errorf("direct_read_bytes = %v, want 6000 (max across blocks)", got)
	}
}

func TestNFSMountEventsCollector_MalformedSkipped(t *testing.T) {
	// Malformed events: line (too few fields) and malformed bytes: line
	// (non-numeric) — both should count as collection errors but not
	// panic. age: line should still emit normally.
	fixture := "" +
		"device nfs.example.com:/volumes/dddddddd-1111-2222-3333-444444444444 mounted on /mnt/sharedfs with fstype nfs statvers=1.1\n" +
		"\tage:\t42\n" +
		"\tevents:\t1 2 3\n" +
		"\tbytes:\tnot-a-number 200 300 400 500 600 700 800\n" +
		"\tper-op statistics\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSMountEventsCollector(path))

	var age, collectionErrors float64
	eventsSeen, bytesSeen := false, false
	for _, m := range metrics {
		name := fqName(m)
		l := metricLabels(m)
		if l["volume_id"] == "dddddddd-1111-2222-3333-444444444444" {
			if name == "crusoe_vm_nfs_mount_age_seconds" {
				age = metricValue(m)
			}
			if strings.Contains(name, "events_total") {
				eventsSeen = true
			}
			if strings.Contains(name, "bytes_total") {
				bytesSeen = true
			}
		}
		if name == "crusoe_vm_nfs_mount_events_collection_errors_total" {
			collectionErrors = metricValue(m)
		}
	}

	if age != 42 {
		t.Errorf("age should still emit despite other line errors; got %v, want 42", age)
	}
	if eventsSeen {
		t.Errorf("events series emitted despite malformed events: line — should have been skipped")
	}
	if bytesSeen {
		t.Errorf("bytes series emitted despite malformed bytes: line — should have been skipped")
	}
	if collectionErrors < 2 {
		t.Errorf("expected collection_errors >= 2 (one per malformed line), got %v", collectionErrors)
	}
}

func TestNFSMountEventsCollector_NonVolumeMountSkipped(t *testing.T) {
	// Mount that doesn't match /volumes/<uuid> shape — should be skipped
	// entirely (no empty-volume_id series).
	fixture := "" +
		"device some.nfs.server:/exports/other mounted on /mnt/other with fstype nfs statvers=1.1\n" +
		"\tage:\t999\n" +
		"\tevents:\t1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27\n" +
		"\tbytes:\t100 200 300 400 500 600 700 800\n" +
		"\tper-op statistics\n"

	path := writeMountstats(t, fixture)
	metrics := collectMetrics(t, NewNFSMountEventsCollector(path))

	for _, m := range metrics {
		l := metricLabels(m)
		// volume_id="" only appears on the collection_errors metric (no
		// volume label). Any other metric with empty volume_id is wrong.
		if v, ok := l["volume_id"]; ok && v == "" {
			t.Errorf("metric %s emitted with empty volume_id label", fqName(m))
		}
	}
}

func TestNFSMountEventsCollector_MissingFile(t *testing.T) {
	c := NewNFSMountEventsCollector("/no/such/path")
	metrics := collectMetrics(t, c)

	var errors float64
	other := 0
	for _, m := range metrics {
		name := fqName(m)
		if name == "crusoe_vm_nfs_mount_events_collection_errors_total" {
			errors = metricValue(m)
			continue
		}
		other++
	}
	if errors == 0 {
		t.Errorf("expected collection_errors > 0 for missing file")
	}
	if other != 0 {
		t.Errorf("expected 0 non-error series for missing file, got %d", other)
	}
}

func TestNFSMountEventsCollector_GoldenFixture_NconnectMount(t *testing.T) {
	// Parse the same real-customer mountstats fixture used by the xprt
	// collector test. Verifies we extract the real-shaped age/events/bytes
	// values from a captured nconnect=16 mount.
	//
	// From the captured file:
	//   age: 245
	//   events: 35 209 0 0 33 23 271 397086 0 0 0 47 0 1 49 0 0 29 0 0 397086 0 0 0 0 0 0
	//     → index 19 (congestion_wait) = 0
	//     → index 23 (short_read)      = 0
	//     → index 24 (short_write)     = 0
	//     → index 25 (delay)           = 0
	//   bytes: 0 1626377887 668377022464 0 668377022464 1465170212 0 357718
	metrics := collectMetrics(t, NewNFSMountEventsCollector("testdata/mountstats_real_nconnect16.txt"))

	vol := "00000000-0000-0000-0000-000000000001"
	values := map[string]float64{}
	for _, m := range metrics {
		l := metricLabels(m)
		if l["volume_id"] == vol {
			values[fqName(m)] = metricValue(m)
		}
	}

	cases := []struct {
		name string
		want float64
	}{
		{"crusoe_vm_nfs_mount_age_seconds", 245},
		{"crusoe_vm_nfs_mount_normal_read_bytes_total", 0},
		{"crusoe_vm_nfs_mount_normal_write_bytes_total", 1626377887},
		{"crusoe_vm_nfs_mount_direct_read_bytes_total", 668377022464},
		{"crusoe_vm_nfs_mount_server_read_bytes_total", 668377022464},
		{"crusoe_vm_nfs_mount_server_write_bytes_total", 1465170212},
		{"crusoe_vm_nfs_mount_write_pages_total", 357718},
		// The delay/congestion/short_* events are all 0 in this
		// snapshot — the VM is doing healthy direct I/O. We still
		// expect the series to be emitted (so PromQL can see them
		// at 0 and rate() will hit zero rather than no-data).
		{"crusoe_vm_nfs_mount_delay_events_total", 0},
		{"crusoe_vm_nfs_mount_congestion_wait_events_total", 0},
	}
	for _, tc := range cases {
		got, ok := values[tc.name]
		if !ok {
			t.Errorf("missing series %s in golden fixture output", tc.name)
			continue
		}
		if got != tc.want {
			t.Errorf("%s = %v, want %v (from captured data)", tc.name, got, tc.want)
		}
	}
}
