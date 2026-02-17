package collectors

import (
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// writeTempMountStats creates a temp file with the given content for NFS tests.
func writeTempMountStats(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "mountstats-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		t.Fatalf("failed to write temp file: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestNFSStatsCollector_Describe(t *testing.T) {
	c := NewNFSStatsCollector("/dev/null")
	ch := make(chan *prometheus.Desc, 10)
	c.Describe(ch)
	close(ch)

	var descs []*prometheus.Desc
	for d := range ch {
		descs = append(descs, d)
	}

	if len(descs) != 4 {
		t.Fatalf("expected 4 descriptors, got %d", len(descs))
	}
}

func TestNFSStatsCollector_ValidSingleVolume(t *testing.T) {
	// Simulates /proc/self/mountstats output for an NFS mount.
	// The READ:/WRITE: lines have 10+ fields:
	// OP: ops transmissions timeouts bytes_sent bytes_recv queue_time rtt_time exe_time errors
	content := `device nfs.crusoecloudcompute.com:/volumes/abc-123-def mounted on /mnt/data with fstype nfs4
	per-op statistics
	READ: 500 500 0 1000 2000 100 250 300 0
	WRITE: 300 300 0 2000 1000 80 150 200 0
`
	path := writeTempMountStats(t, content)

	c := NewNFSStatsCollector(path)
	metrics := collectMetrics(t, c)

	// 3 metrics per operation (count, rtt, exe) * 2 operations + 1 error counter = 7
	if len(metrics) != 7 {
		t.Fatalf("expected 7 metrics, got %d", len(metrics))
	}

	// READ metrics: count=500, rtt=250, exe=300
	readCount := metricValue(t, metrics[0])
	if readCount != 500 {
		t.Errorf("expected READ count=500, got %f", readCount)
	}
	readLabels := metricLabels(t, metrics[0])
	if readLabels["nfs_volume_id"] != "abc-123-def" {
		t.Errorf("expected volume_id=abc-123-def, got %s", readLabels["nfs_volume_id"])
	}
	if readLabels["nfs_operation"] != "read" {
		t.Errorf("expected operation=read, got %s", readLabels["nfs_operation"])
	}

	readRtt := metricValue(t, metrics[1])
	if readRtt != 250 {
		t.Errorf("expected READ rtt=250, got %f", readRtt)
	}

	readExe := metricValue(t, metrics[2])
	if readExe != 300 {
		t.Errorf("expected READ exe=300, got %f", readExe)
	}

	// WRITE metrics: count=300, rtt=150, exe=200
	writeCount := metricValue(t, metrics[3])
	if writeCount != 300 {
		t.Errorf("expected WRITE count=300, got %f", writeCount)
	}
	writeLabels := metricLabels(t, metrics[3])
	if writeLabels["nfs_operation"] != "write" {
		t.Errorf("expected operation=write, got %s", writeLabels["nfs_operation"])
	}

	writeRtt := metricValue(t, metrics[4])
	if writeRtt != 150 {
		t.Errorf("expected WRITE rtt=150, got %f", writeRtt)
	}

	writeExe := metricValue(t, metrics[5])
	if writeExe != 200 {
		t.Errorf("expected WRITE exe=200, got %f", writeExe)
	}

	// Error counter should be 0
	errVal := metricValue(t, metrics[6])
	if errVal != 0 {
		t.Errorf("expected error count 0, got %f", errVal)
	}
}

func TestNFSStatsCollector_MultipleVolumes(t *testing.T) {
	content := `device nfs.crusoecloudcompute.com:/volumes/vol-aaa mounted on /mnt/a with fstype nfs4
	per-op statistics
	READ: 100 100 0 500 1000 50 120 140 0
	WRITE: 200 200 0 1000 500 40 80 100 0
device nfs.crusoecloudcompute.com:/volumes/vol-bbb mounted on /mnt/b with fstype nfs4
	per-op statistics
	READ: 300 300 0 1500 3000 150 360 420 0
`
	path := writeTempMountStats(t, content)

	c := NewNFSStatsCollector(path)
	metrics := collectMetrics(t, c)

	// vol-aaa: READ(3) + WRITE(3) = 6, vol-bbb: READ(3) = 3, + 1 error counter = 10
	if len(metrics) != 10 {
		t.Fatalf("expected 10 metrics, got %d", len(metrics))
	}

	// Verify second volume labels
	labels := metricLabels(t, metrics[6])
	if labels["nfs_volume_id"] != "vol-bbb" {
		t.Errorf("expected volume_id=vol-bbb, got %s", labels["nfs_volume_id"])
	}
}

func TestNFSStatsCollector_ZeroOpsSkipped(t *testing.T) {
	content := `device nfs.crusoecloudcompute.com:/volumes/abc-123 mounted on /mnt/data with fstype nfs4
	per-op statistics
	READ: 0 0 0 0 0 0 0 0 0
	WRITE: 100 100 0 500 250 40 80 100 0
`
	path := writeTempMountStats(t, content)

	c := NewNFSStatsCollector(path)
	metrics := collectMetrics(t, c)

	// READ skipped (0 ops), WRITE emits 3 metrics + 1 error counter = 4
	if len(metrics) != 4 {
		t.Fatalf("expected 4 metrics (zero ops skipped), got %d", len(metrics))
	}

	labels := metricLabels(t, metrics[0])
	if labels["nfs_operation"] != "write" {
		t.Errorf("expected operation=write, got %s", labels["nfs_operation"])
	}
}

func TestNFSStatsCollector_NonNFSDeviceIgnored(t *testing.T) {
	// Device path without /volumes/ should be ignored
	content := `device /dev/vda1 mounted on / with fstype ext4
	READ: 1000 1000 0 5000 10000 500 1200 1400 0
`
	path := writeTempMountStats(t, content)

	c := NewNFSStatsCollector(path)
	metrics := collectMetrics(t, c)

	// No volume ID matched, only error counter
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (error counter only), got %d", len(metrics))
	}

	errVal := metricValue(t, metrics[0])
	if errVal != 0 {
		t.Errorf("expected error count 0, got %f", errVal)
	}
}

func TestNFSStatsCollector_MissingFile(t *testing.T) {
	c := NewNFSStatsCollector("/nonexistent/path/mountstats")
	metrics := collectMetrics(t, c)

	// Should emit a single error metric with value 1
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (error), got %d", len(metrics))
	}

	errVal := metricValue(t, metrics[0])
	if errVal != 1 {
		t.Errorf("expected error count 1, got %f", errVal)
	}
}

func TestNFSStatsCollector_ShortOperationLine(t *testing.T) {
	// READ line with fewer than 10 fields should be skipped
	content := `device nfs.crusoecloudcompute.com:/volumes/abc-123 mounted on /mnt/data with fstype nfs4
	per-op statistics
	READ: 500 500 0
	WRITE: 100 100 0 500 250 40 80 100 0
`
	path := writeTempMountStats(t, content)

	c := NewNFSStatsCollector(path)
	metrics := collectMetrics(t, c)

	// READ skipped (too few fields), WRITE emits 3 metrics + 1 error counter = 4
	if len(metrics) != 4 {
		t.Fatalf("expected 4 metrics, got %d", len(metrics))
	}
}

func TestNFSStatsCollector_UnparseableOpsCount(t *testing.T) {
	content := `device nfs.crusoecloudcompute.com:/volumes/abc-123 mounted on /mnt/data with fstype nfs4
	per-op statistics
	READ: xyz 500 0 1000 2000 100 250 300 0
`
	path := writeTempMountStats(t, content)

	c := NewNFSStatsCollector(path)
	metrics := collectMetrics(t, c)

	// Parse error on ops count → error counter = 1
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (error counter), got %d", len(metrics))
	}

	errVal := metricValue(t, metrics[0])
	if errVal != 1 {
		t.Errorf("expected error count 1, got %f", errVal)
	}
}

func TestNFSStatsCollector_UnparseableRtt(t *testing.T) {
	content := `device nfs.crusoecloudcompute.com:/volumes/abc-123 mounted on /mnt/data with fstype nfs4
	per-op statistics
	READ: 500 500 0 1000 2000 100 bad 300 0
`
	path := writeTempMountStats(t, content)

	c := NewNFSStatsCollector(path)
	metrics := collectMetrics(t, c)

	// Parse error on rtt → error counter = 1
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (error counter), got %d", len(metrics))
	}

	errVal := metricValue(t, metrics[0])
	if errVal != 1 {
		t.Errorf("expected error count 1, got %f", errVal)
	}
}

func TestNFSStatsCollector_UnparseableExe(t *testing.T) {
	content := `device nfs.crusoecloudcompute.com:/volumes/abc-123 mounted on /mnt/data with fstype nfs4
	per-op statistics
	READ: 500 500 0 1000 2000 100 250 bad 0
`
	path := writeTempMountStats(t, content)

	c := NewNFSStatsCollector(path)
	metrics := collectMetrics(t, c)

	// Parse error on exe → error counter = 1
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (error counter), got %d", len(metrics))
	}

	errVal := metricValue(t, metrics[0])
	if errVal != 1 {
		t.Errorf("expected error count 1, got %f", errVal)
	}
}

func TestNFSStatsCollector_EmptyFile(t *testing.T) {
	path := writeTempMountStats(t, "")

	c := NewNFSStatsCollector(path)
	metrics := collectMetrics(t, c)

	// Only error counter with value 0
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}

	errVal := metricValue(t, metrics[0])
	if errVal != 0 {
		t.Errorf("expected error count 0, got %f", errVal)
	}
}
