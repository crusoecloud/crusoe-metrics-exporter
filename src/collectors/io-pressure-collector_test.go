package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func writeTempProcStat(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stat")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp stat: %v", err)
	}
	return path
}

func collectIOMetrics(t *testing.T, c *IOPressureCollector) []prometheus.Metric {
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

const fixtureProcStat = `cpu  100 0 50 1000 5 0 3 8 0 0
cpu0 100 0 50 1000 5 0 3 8 0 0
procs_running 2
procs_blocked 3
`

func TestIOPressure_PSIPresent(t *testing.T) {
	psi := `some avg10=10.00 avg60=20.00 avg300=30.00 total=2000000
full avg10=0.00 avg60=0.00 avg300=0.00 total=1000000
`
	c := NewIOPressureCollector(
		writeTempPSIFile(t, psi),
		writeTempProcStat(t, fixtureProcStat),
	)
	metrics := collectIOMetrics(t, c)

	if n := countWithDesc(metrics, c.psiRatioDesc); n != 6 {
		t.Errorf("expected 6 psi_io_ratio series, got %d", n)
	}
	if n := countWithDesc(metrics, c.psiStallSecondsDesc); n != 2 {
		t.Errorf("expected 2 psi_io_stall_seconds_total series, got %d", n)
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

	if got := mustFind(t, metrics, c.procsBlockedDesc, nil); got != 3 {
		t.Errorf("procs_blocked: got %v, want 3", got)
	}

	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 0 {
		t.Errorf("collection_errors: got %v, want 0", got)
	}
}

func TestIOPressure_PSIUnavailable(t *testing.T) {
	c := NewIOPressureCollector(
		filepath.Join(t.TempDir(), "no-pressure-file"),
		writeTempProcStat(t, fixtureProcStat),
	)
	metrics := collectIOMetrics(t, c)

	if n := countWithDesc(metrics, c.psiRatioDesc); n != 0 {
		t.Errorf("expected no ratio series when PSI unavailable, got %d", n)
	}
	if n := countWithDesc(metrics, c.psiStallSecondsDesc); n != 0 {
		t.Errorf("expected no stall series when PSI unavailable, got %d", n)
	}
	if got := mustFind(t, metrics, c.procsBlockedDesc, nil); got != 3 {
		t.Errorf("procs_blocked should still emit, got %v", got)
	}
	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 0 {
		t.Errorf("collection_errors: got %v, want 0 (PSI absent is not an error)", got)
	}
}

func TestIOPressure_ProcStatMissingIncrementsErrors(t *testing.T) {
	psi := "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
	c := NewIOPressureCollector(
		writeTempPSIFile(t, psi),
		filepath.Join(t.TempDir(), "no-stat"),
	)
	metrics := collectIOMetrics(t, c)

	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 1 {
		t.Errorf("collection_errors: got %v, want 1", got)
	}
	if n := countWithDesc(metrics, c.procsBlockedDesc); n != 0 {
		t.Errorf("procs_blocked should be absent when /proc/stat unreadable, got %d", n)
	}
	if n := countWithDesc(metrics, c.psiRatioDesc); n != 6 {
		t.Errorf("psi_io_ratio should still emit despite /proc/stat failure, got %d series", n)
	}
}
