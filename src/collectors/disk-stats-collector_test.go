package collectors

import (
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// helper: collect all metrics from a collector into a slice
func collectMetrics(t *testing.T, c prometheus.Collector) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)
	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}
	return metrics
}

// helper: extract the float value from a prometheus.Metric
func metricValue(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()
	pb := &dto.Metric{}
	if err := m.Write(pb); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	if pb.Counter != nil {
		return pb.Counter.GetValue()
	}
	if pb.Gauge != nil {
		return pb.Gauge.GetValue()
	}
	return 0
}

// helper: extract label values from a prometheus.Metric
func metricLabels(t *testing.T, m prometheus.Metric) map[string]string {
	t.Helper()
	pb := &dto.Metric{}
	if err := m.Write(pb); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	labels := make(map[string]string)
	for _, lp := range pb.Label {
		labels[lp.GetName()] = lp.GetValue()
	}
	return labels
}

// writeTempFile creates a temp file with the given content and returns its path.
func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "diskstats-test-*")
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

func TestDiskStatsCollector_Describe(t *testing.T) {
	c := NewDiskStatsCollector("/dev/null")
	ch := make(chan *prometheus.Desc, 10)
	c.Describe(ch)
	close(ch)

	var descs []*prometheus.Desc
	for d := range ch {
		descs = append(descs, d)
	}

	if len(descs) != 5 {
		t.Fatalf("expected 5 descriptors, got %d", len(descs))
	}
}

func TestDiskStatsCollector_ValidSingleDevice(t *testing.T) {
	// /proc/diskstats format (14+ fields):
	// major minor device reads_completed reads_merged sectors_read time_reading
	// writes_completed writes_merged sectors_written time_writing ios_in_progress
	// time_in_io weighted_time_in_io
	content := "   8       0 vda 1000 50 2048 500 2000 100 4096 800 0 600 1300\n"
	path := writeTempFile(t, content)

	c := NewDiskStatsCollector(path)
	metrics := collectMetrics(t, c)

	// Expect 4 data metrics + 1 error counter = 5
	if len(metrics) != 5 {
		t.Fatalf("expected 5 metrics, got %d", len(metrics))
	}

	// Verify values: reads_completed=1000, read_time_ms=500, writes_completed=2000, write_time_ms=800
	expected := []struct {
		value float64
		label string
	}{
		{1000, "vda"},
		{500, "vda"},
		{2000, "vda"},
		{800, "vda"},
	}

	for i, exp := range expected {
		v := metricValue(t, metrics[i])
		if v != exp.value {
			t.Errorf("metric[%d]: expected value %f, got %f", i, exp.value, v)
		}
		labels := metricLabels(t, metrics[i])
		if labels["device"] != exp.label {
			t.Errorf("metric[%d]: expected device=%s, got %s", i, exp.label, labels["device"])
		}
	}

	// Last metric is the error counter, should be 0
	errVal := metricValue(t, metrics[4])
	if errVal != 0 {
		t.Errorf("expected error count 0, got %f", errVal)
	}
}

func TestDiskStatsCollector_MultipleDevices(t *testing.T) {
	content := "   8       0 vda 100 10 200 50 200 20 400 80 0 60 130\n" +
		"   8      16 vdb 300 30 600 150 400 40 800 200 0 180 350\n"
	path := writeTempFile(t, content)

	c := NewDiskStatsCollector(path)
	metrics := collectMetrics(t, c)

	// 4 metrics per device * 2 devices + 1 error counter = 9
	if len(metrics) != 9 {
		t.Fatalf("expected 9 metrics, got %d", len(metrics))
	}
}

func TestDiskStatsCollector_IgnoresPartitions(t *testing.T) {
	content := "   8       0 vda 100 10 200 50 200 20 400 80 0 60 130\n" +
		"   8       1 vda1 50 5 100 25 100 10 200 40 0 30 65\n"
	path := writeTempFile(t, content)

	c := NewDiskStatsCollector(path)
	metrics := collectMetrics(t, c)

	// Only vda should match (4 metrics) + 1 error counter = 5
	if len(metrics) != 5 {
		t.Fatalf("expected 5 metrics (partitions ignored), got %d", len(metrics))
	}

	labels := metricLabels(t, metrics[0])
	if labels["device"] != "vda" {
		t.Errorf("expected device=vda, got %s", labels["device"])
	}
}

func TestDiskStatsCollector_IgnoresNonVdDevices(t *testing.T) {
	content := "   8       0 sda 100 10 200 50 200 20 400 80 0 60 130\n" +
		"   8      16 nvme0n1 300 30 600 150 400 40 800 200 0 180 350\n"
	path := writeTempFile(t, content)

	c := NewDiskStatsCollector(path)
	metrics := collectMetrics(t, c)

	// No matching devices, only error counter = 1
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (error counter only), got %d", len(metrics))
	}

	errVal := metricValue(t, metrics[0])
	if errVal != 0 {
		t.Errorf("expected error count 0, got %f", errVal)
	}
}

func TestDiskStatsCollector_MissingFile(t *testing.T) {
	c := NewDiskStatsCollector("/nonexistent/path/diskstats")
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

func TestDiskStatsCollector_ShortLines(t *testing.T) {
	// Lines with fewer than 14 fields should be skipped
	content := "   8       0 vda 100\n" +
		"too short\n"
	path := writeTempFile(t, content)

	c := NewDiskStatsCollector(path)
	metrics := collectMetrics(t, c)

	// No valid device lines, only error counter
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (error counter only), got %d", len(metrics))
	}

	errVal := metricValue(t, metrics[0])
	if errVal != 0 {
		t.Errorf("expected error count 0, got %f", errVal)
	}
}

func TestDiskStatsCollector_UnparseableFields(t *testing.T) {
	// reads_completed field is "abc" — unparseable
	content := "   8       0 vda abc 10 200 50 200 20 400 80 0 60 130\n"
	path := writeTempFile(t, content)

	c := NewDiskStatsCollector(path)
	metrics := collectMetrics(t, c)

	// Should have only the error counter with value 1
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (error counter), got %d", len(metrics))
	}

	errVal := metricValue(t, metrics[0])
	if errVal != 1 {
		t.Errorf("expected error count 1, got %f", errVal)
	}
}

func TestDiskStatsCollector_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "")

	c := NewDiskStatsCollector(path)
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
