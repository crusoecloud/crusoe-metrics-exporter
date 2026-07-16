package collectors

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func collectCPUMetrics(t *testing.T, c *CPUStealCollector) []prometheus.Metric {
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

func TestCPUSteal_HappyPath(t *testing.T) {
	// cpu0's steal (99) deliberately differs from the aggregate cpu line's (8)
	// so a regression that read a per-cpu line instead of the aggregate is caught.
	stat := `cpu  100 0 50 1000 5 0 3 8 0 0
cpu0 60 0 30 500 3 0 2 99 0 0
procs_running 2
procs_blocked 3
`
	c := NewCPUStealCollector(writeTempProcStat(t, stat))
	metrics := collectCPUMetrics(t, c)

	if got := mustFind(t, metrics, c.stealSecondsDesc, nil); !approx(got, 0.08) {
		t.Errorf("cpu_steal_seconds_total: got %v, want 0.08 (8 jiffies / USER_HZ 100)", got)
	}
	if got := mustFind(t, metrics, c.procsRunningDesc, nil); got != 2 {
		t.Errorf("procs_running: got %v, want 2", got)
	}
	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 0 {
		t.Errorf("collection_errors: got %v, want 0", got)
	}
}

func TestCPUSteal_StatMissing(t *testing.T) {
	c := NewCPUStealCollector(filepath.Join(t.TempDir(), "no-stat"))
	metrics := collectCPUMetrics(t, c)

	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 1 {
		t.Errorf("collection_errors: got %v, want 1", got)
	}
	if n := countWithDesc(metrics, c.stealSecondsDesc); n != 0 {
		t.Errorf("steal series should be absent when stat unreadable, got %d", n)
	}
	if n := countWithDesc(metrics, c.procsRunningDesc); n != 0 {
		t.Errorf("procs_running should be absent when stat unreadable, got %d", n)
	}
}

func TestCPUSteal_NoStealColumn(t *testing.T) {
	stat := `cpu  100 0 50 1000
procs_running 4
`
	c := NewCPUStealCollector(writeTempProcStat(t, stat))
	metrics := collectCPUMetrics(t, c)

	if n := countWithDesc(metrics, c.stealSecondsDesc); n != 0 {
		t.Errorf("steal series should be absent without a steal column, got %d", n)
	}
	if got := mustFind(t, metrics, c.procsRunningDesc, nil); got != 4 {
		t.Errorf("procs_running should still emit, got %v", got)
	}
	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 1 {
		t.Errorf("collection_errors: got %v, want 1", got)
	}
}
func TestCPUSteal_NoProcsRunning(t *testing.T) {
	// Mirror of TestCPUSteal_NoStealColumn: steal present, procs_running line absent.
	stat := `cpu  100 0 50 1000 5 0 3 8 0 0
procs_blocked 1
`
	c := NewCPUStealCollector(writeTempProcStat(t, stat))
	metrics := collectCPUMetrics(t, c)

	if got := mustFind(t, metrics, c.stealSecondsDesc, nil); !approx(got, 0.08) {
		t.Errorf("steal should still emit, got %v", got)
	}
	if n := countWithDesc(metrics, c.procsRunningDesc); n != 0 {
		t.Errorf("procs_running series should be absent, got %d", n)
	}
	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 1 {
		t.Errorf("collection_errors: got %v, want 1", got)
	}
}

func TestCPUSteal_MalformedSteal(t *testing.T) {
	// A malformed steal value is treated like a missing column: steal is dropped
	// and counted, but a valid procs_running on another line still emits.
	stat := `cpu  100 0 50 1000 5 0 3 notanumber 0 0
procs_running 5
`
	c := NewCPUStealCollector(writeTempProcStat(t, stat))
	metrics := collectCPUMetrics(t, c)

	if n := countWithDesc(metrics, c.stealSecondsDesc); n != 0 {
		t.Errorf("steal series should be absent for a malformed value, got %d", n)
	}
	if got := mustFind(t, metrics, c.procsRunningDesc, nil); got != 5 {
		t.Errorf("procs_running should still emit despite a bad steal value, got %v", got)
	}
	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 1 {
		t.Errorf("collection_errors: got %v, want 1", got)
	}
}

func TestCPUSteal_MalformedProcsRunning(t *testing.T) {
	// Symmetric to the malformed-steal case: a bad procs_running value must not
	// discard the valid steal reading.
	stat := `cpu  100 0 50 1000 5 0 3 8 0 0
procs_running notanumber
`
	c := NewCPUStealCollector(writeTempProcStat(t, stat))
	metrics := collectCPUMetrics(t, c)

	if got := mustFind(t, metrics, c.stealSecondsDesc, nil); !approx(got, 0.08) {
		t.Errorf("steal should still emit despite a bad procs_running value, got %v", got)
	}
	if n := countWithDesc(metrics, c.procsRunningDesc); n != 0 {
		t.Errorf("procs_running series should be absent for a malformed value, got %d", n)
	}
	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 1 {
		t.Errorf("collection_errors: got %v, want 1", got)
	}
}

func TestCPUSteal_BothFieldsMissing(t *testing.T) {
	// A readable /proc/stat missing both fields increments the error counter
	// once per missing field (2), not once for the file.
	stat := `intr 12345 0 0
procs_blocked 0
`
	c := NewCPUStealCollector(writeTempProcStat(t, stat))
	metrics := collectCPUMetrics(t, c)

	if n := countWithDesc(metrics, c.stealSecondsDesc); n != 0 {
		t.Errorf("steal series should be absent, got %d", n)
	}
	if n := countWithDesc(metrics, c.procsRunningDesc); n != 0 {
		t.Errorf("procs_running series should be absent, got %d", n)
	}
	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 2 {
		t.Errorf("collection_errors: got %v, want 2 (one per missing field)", got)
	}
}

func TestCPUSteal_ErrorsAccumulate(t *testing.T) {
	c := NewCPUStealCollector(filepath.Join(t.TempDir(), "no-stat"))
	collectCPUMetrics(t, c)
	metrics := collectCPUMetrics(t, c)

	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 2 {
		t.Errorf("collection_errors after two failing scrapes: got %v, want 2", got)
	}
}

func TestCPUSteal_OversizedIntrLine(t *testing.T) {
	// A real /proc/stat carries an intr line with one counter per IRQ vector,
	// which can exceed the 64KB default scanner token. Because procs_running
	// follows intr, an over-long line must not abort the scan and drop metrics.
	bigIntr := "intr 0 " + strings.Repeat("1 ", 60000) // ~120KB, well over the 64KB default
	stat := "cpu  100 0 50 1000 5 0 3 8 0 0\n" +
		bigIntr + "\n" +
		"procs_running 2\n"
	c := NewCPUStealCollector(writeTempProcStat(t, stat))
	metrics := collectCPUMetrics(t, c)

	if got := mustFind(t, metrics, c.stealSecondsDesc, nil); !approx(got, 0.08) {
		t.Errorf("steal should emit past a huge intr line, got %v", got)
	}
	if got := mustFind(t, metrics, c.procsRunningDesc, nil); got != 2 {
		t.Errorf("procs_running (after intr) should still emit, got %v", got)
	}
	if got := mustFind(t, metrics, c.collectionErrors.Desc(), nil); got != 0 {
		t.Errorf("collection_errors: got %v, want 0", got)
	}
}
