package collectors

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func newTestSoftLockupCollector() *SoftLockupCollector {
	return &SoftLockupCollector{
		softLockups: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "test_soft_lockups_total",
		}),
		collectionErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "test_soft_lockup_errors_total",
		}),
		stopCh: make(chan struct{}),
	}
}

func TestMatchSoftLockup(t *testing.T) {
	cases := []struct {
		name   string
		record string
		want   bool
	}{
		{
			"watchdog format",
			"6,1234,56789012,-;watchdog: BUG: soft lockup - CPU#3 stuck for 22s! [stress-ng:4567]",
			true,
		},
		{
			"older format without watchdog prefix",
			"6,1,1,-;BUG: soft lockup - CPU#0 stuck for 11s! [kworker/0:1:42]",
			true,
		},
		{
			"unrelated kernel message",
			"5,1000,100,-;random driver probe succeeded",
			false,
		},
		{
			"continuation line",
			" SUBSYSTEM=cpu",
			false,
		},
		{
			"no semicolon, no match",
			"just some noise without a separator",
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchSoftLockup(tc.record); got != tc.want {
				t.Errorf("matchSoftLockup(%q) = %v, want %v", tc.record, got, tc.want)
			}
		})
	}
}

// TestSoftLockupTail_CountsEvents feeds the tailer a stream that ends (EOF) and
// verifies it counts one increment per soft-lockup record and nothing else.
func TestSoftLockupTail_CountsEvents(t *testing.T) {
	stream := strings.Join([]string{
		"6,1,1,-;watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [a:1]",
		"5,2,2,-;some other message",
		" DEVICE=+cpu:0", // continuation line, must not count
		"6,3,3,-;watchdog: BUG: soft lockup - CPU#1 stuck for 23s! [b:2]",
	}, "\n") + "\n"

	c := newTestSoftLockupCollector()
	c.tail(strings.NewReader(stream)) // returns at EOF

	if got := metricValue(c.softLockups); got != 2 {
		t.Errorf("soft_lockups: got %v, want 2", got)
	}
	if got := metricValue(c.collectionErrors); got != 0 {
		t.Errorf("collection_errors: got %v, want 0", got)
	}
}

// TestSoftLockupCollector_MissingDevice verifies the constructor self-disables
// (returns an error) when the kmsg path can't be opened, so main can continue
// without it.
func TestSoftLockupCollector_MissingDevice(t *testing.T) {
	_, err := NewSoftLockupCollector(filepath.Join(t.TempDir(), "no-kmsg"))
	if err == nil {
		t.Fatal("expected an error opening a nonexistent kmsg path, got nil")
	}
}

// TestSoftLockupTail_BlocksAndStops exercises the real mechanism: the tailer
// blocks on a pipe waiting for records, counts one as it arrives, and Stop()
// unblocks the read so the goroutine returns.
func TestSoftLockupTail_BlocksAndStops(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Close()

	c := newTestSoftLockupCollector()
	c.file = pr // Stop() closes this to unblock the read

	done := make(chan struct{})
	go func() {
		c.tail(pr)
		close(done)
	}()

	if _, err := pw.WriteString("6,1,1,-;watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [x:1]\n"); err != nil {
		t.Fatal(err)
	}

	// Wait (bounded) for the goroutine to observe the record.
	deadline := time.Now().Add(2 * time.Second)
	for metricValue(c.softLockups) < 1 {
		if time.Now().After(deadline) {
			t.Fatal("tailer did not count the soft lockup in time")
		}
		time.Sleep(5 * time.Millisecond)
	}

	c.Stop() // closes pr, unblocking the pending read
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tailer did not stop after Stop()")
	}

	if got := metricValue(c.softLockups); got != 1 {
		t.Errorf("soft_lockups: got %v, want 1", got)
	}
}

// TestSoftLockupTail_SeekToEndSkipsBacklog verifies the restart-safety
// invariant: after seeking to the end of the log (as the constructor does),
// pre-existing records are skipped and only records written afterward count.
// Without the seek this would read both lines and report 2.
func TestSoftLockupTail_SeekToEndSkipsBacklog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kmsg")
	backlog := "6,1,1,-;watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [old:1]\n"
	if err := os.WriteFile(path, []byte(backlog), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Seek(0, io.SeekEnd); err != nil { // same call the constructor makes
		t.Fatal(err)
	}

	// Append a fresh record past the seek position.
	af, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := af.WriteString("6,2,2,-;watchdog: BUG: soft lockup - CPU#1 stuck for 23s! [new:2]\n"); err != nil {
		t.Fatal(err)
	}
	af.Close()

	c := newTestSoftLockupCollector()
	c.tail(f) // reads from the post-seek position to EOF

	if got := metricValue(c.softLockups); got != 1 {
		t.Errorf("soft_lockups: got %v, want 1 (backlog must be skipped, only the post-seek record counted)", got)
	}
}
