package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func writeTempMeminfo(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "meminfo")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp meminfo: %v", err)
	}
	return path
}

func collectMemMetrics(t *testing.T, c *MemoryPressureCollector) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)
	var out []prometheus.Metric
	for m := range ch {
		out = append(out, m)
	}
	return out
}

func containsLabels(got, want map[string]string) bool {
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func mustFind(t *testing.T, metrics []prometheus.Metric, desc *prometheus.Desc, labels map[string]string) float64 {
	t.Helper()
	for _, m := range metrics {
		if m.Desc() == desc && containsLabels(metricLabels(m), labels) {
			return metricValue(m)
		}
	}
	t.Fatalf("metric not found: %s labels=%v", desc.String(), labels)
	return 0
}

func countWithDesc(metrics []prometheus.Metric, desc *prometheus.Desc) int {
	n := 0
	for _, m := range metrics {
		if m.Desc() == desc {
			n++
		}
	}
	return n
}

func approx(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}

const fixtureMeminfo = `MemTotal:       16384000 kB
MemFree:         1000000 kB
MemAvailable:    8192000 kB
SwapTotal:       2048000 kB
SwapFree:        1024000 kB
`

// TestMemoryPressure_PSIPresent verifies the full happy path: PSI available,
// ratios emitted as 0-1 fractions, stall counter in seconds, meminfo gauges in
// bytes, and a zero error count.
func TestMemoryPressure_PSIPresent(t *testing.T) {
	psi := `some avg10=10.00 avg60=20.00 avg300=30.00 total=2000000
full avg10=0.00 avg60=0.00 avg300=0.00 total=1000000
`
	c := NewMemoryPressureCollector(
		writeTempPSIFile(t, psi),
		writeTempMeminfo(t, fixtureMeminfo),
	)
	metrics := collectMemMetrics(t, c)

	if n := countWithDesc(metrics, c.psiRatioDesc); n != 6 {
		t.Errorf("expected 6 psi_memory_ratio series, got %d", n)
	}
	if n := countWithDesc(metrics, c.psiStallSecondsDesc); n != 2 {
		t.Errorf("expected 2 psi_memory_stall_seconds_total series, got %d", n)
	}

	if got := mustFind(t, metrics, c.psiRatioDesc, map[string]string{"scope": "some", "window": "10"}); !approx(got, 0.10) {
		t.Errorf("ratio{some,10}: got %v, want 0.10", got)
	}
	if got := mustFind(t, metrics, c.psiRatioDesc, map[string]string{"scope": "some", "window": "300"}); !approx(got, 0.30) {
		t.Errorf("ratio{some,300}: got %v, want 0.30", got)
	}

	if got := mustFind(t, metrics, c.psiStallSecondsDesc, map[string]string{"scope": "some"}); !approx(got, 2.0) {
		t.Errorf("stall{some}: got %v, want 2.0", got)
	}
	if got := mustFind(t, metrics, c.psiStallSecondsDesc, map[string]string{"scope": "full"}); !approx(got, 1.0) {
		t.Errorf("stall{full}: got %v, want 1.0", got)
	}

	if got := mustFind(t, metrics, c.memAvailableDesc, nil); got != 8192000*1024 {
		t.Errorf("mem_available_bytes: got %v, want %v", got, 8192000*1024)
	}
	if got := mustFind(t, metrics, c.swapUsedDesc, nil); got != (2048000-1024000)*1024 {
		t.Errorf("swap_used_bytes: got %v, want %v", got, (2048000-1024000)*1024)
	}

	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 0 {
		t.Errorf("collection_errors: got %v, want 0", got)
	}
}

func TestMemoryPressure_PSIUnavailable(t *testing.T) {
	c := NewMemoryPressureCollector(
		filepath.Join(t.TempDir(), "no-pressure-file"),
		writeTempMeminfo(t, fixtureMeminfo),
	)
	metrics := collectMemMetrics(t, c)

	if n := countWithDesc(metrics, c.psiRatioDesc); n != 0 {
		t.Errorf("expected no ratio series when PSI unavailable, got %d", n)
	}
	if n := countWithDesc(metrics, c.psiStallSecondsDesc); n != 0 {
		t.Errorf("expected no stall series when PSI unavailable, got %d", n)
	}

	if got := mustFind(t, metrics, c.memAvailableDesc, nil); got != 8192000*1024 {
		t.Errorf("mem_available_bytes should still emit, got %v", got)
	}
	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 0 {
		t.Errorf("collection_errors: got %v, want 0 (PSI absent is not an error)", got)
	}
}

func TestMemoryPressure_MeminfoMissingIncrementsErrors(t *testing.T) {
	psi := "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
	c := NewMemoryPressureCollector(
		writeTempPSIFile(t, psi),
		filepath.Join(t.TempDir(), "no-meminfo"),
	)
	metrics := collectMemMetrics(t, c)

	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 1 {
		t.Errorf("collection_errors: got %v, want 1", got)
	}
	if n := countWithDesc(metrics, c.memAvailableDesc); n != 0 {
		t.Errorf("mem_available_bytes should be absent when meminfo unreadable, got %d", n)
	}
	if n := countWithDesc(metrics, c.psiRatioDesc); n != 6 {
		t.Errorf("psi_memory_ratio should still emit despite meminfo failure, got %d series", n)
	}
}
