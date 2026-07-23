package collectors

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"metrics-exporter/src/log"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// kmsgOverflowBackoff paces the tailer after a ring-buffer overflow (EPIPE) so a
// sustained lockup storm doesn't spin the loop or flood the logs.
const kmsgOverflowBackoff = 100 * time.Millisecond

// SoftLockupCollector counts kernel soft-lockup events by tailing /dev/kmsg.
//
// Unlike the other collectors, a soft lockup is an event in the kernel log
// stream, not a value that can be read at scrape time. So instead of reading on
// each scrape, a long-lived goroutine follows /dev/kmsg for the life of the
// process and increments a counter whenever the watchdog logs a soft lockup;
// Collect() just emits the current counter values.
//
// Hard-lockup detection is out of scope: it relies on the NMI watchdog, which
// is typically unavailable in cloud VMs.
type SoftLockupCollector struct {
	file *os.File

	softLockups      prometheus.Counter
	collectionErrors prometheus.Counter

	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewSoftLockupCollector opens kmsgPath (typically /dev/kmsg), seeks past the
// existing ring-buffer backlog, and starts the tailer goroutine. It returns an
// error if the device cannot be opened — reading /dev/kmsg needs CAP_SYSLOG (or
// root, or kernel.dmesg_restrict=0) — so the caller can log and continue
// without the collector rather than failing to start.
func NewSoftLockupCollector(kmsgPath string) (*SoftLockupCollector, error) {
	file, err := os.Open(kmsgPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", kmsgPath, err)
	}

	// Seek to the end so we count only lockups logged from now on, not the
	// ring-buffer backlog. A counter resets to 0 on every process restart, so
	// replaying history would re-count old lockups each time and inject a
	// phantom rate() spike; seeking to the end keeps the counter restart-safe.
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		file.Close()
		return nil, fmt.Errorf("seek %s: %w", kmsgPath, err)
	}

	c := &SoftLockupCollector{
		file: file,
		softLockups: prometheus.NewCounter(prometheus.CounterOpts{
			Name: MetricPrefix + "kernel_soft_lockups_total",
			Help: "Cumulative count of kernel soft-lockup events observed in /dev/kmsg since the exporter started.",
		}),
		collectionErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: MetricPrefix + "kernel_soft_lockup_collection_errors_total",
			Help: "Total number of errors encountered while tailing /dev/kmsg for soft lockups.",
		}),
		stopCh: make(chan struct{}),
	}

	go c.tail(file)
	return c, nil
}

func (c *SoftLockupCollector) Describe(ch chan<- *prometheus.Desc) {
	c.softLockups.Describe(ch)
	c.collectionErrors.Describe(ch)
}

func (c *SoftLockupCollector) Collect(ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("SoftLockupCollector panic recovered: %v", r)
		}
	}()

	ch <- c.softLockups
	ch <- c.collectionErrors
}

// Stop terminates the tailer goroutine. Closing the file unblocks the pending
// read so the goroutine can return.
func (c *SoftLockupCollector) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		c.file.Close()
	})
}

func (c *SoftLockupCollector) isStopped() bool {
	select {
	case <-c.stopCh:
		return true
	default:
		return false
	}
}

// tail reads kmsg records until the reader ends or Stop is called, counting
// soft-lockup lines. It is passed an io.Reader (rather than reading c.file
// directly) so tests can drive it with a pipe or string.
func (c *SoftLockupCollector) tail(r io.Reader) {
	for {
		scanner := bufio.NewScanner(r)
		// kmsg records are usually small, but the intr-style long lines and
		// multi-field records warrant a generous cap over the 64KB default.
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			if matchSoftLockup(scanner.Text()) {
				c.softLockups.Inc()
			}
		}

		err := scanner.Err()
		if err == nil {
			// Clean EOF: a regular file/string in tests. /dev/kmsg blocks for
			// new records rather than returning EOF, so this path is tests only.
			return
		}
		if c.isStopped() {
			return
		}
		c.collectionErrors.Inc()
		if !errors.Is(err, syscall.EPIPE) {
			// EPIPE means we fell behind and the kernel dropped records — a
			// recoverable overflow we resume from. Anything else is unexpected;
			// stop the tailer rather than spin on a persistent error.
			log.Warnf("soft lockup: kmsg read error, tailer stopping: %v", err)
			return
		}
		log.Warnf("soft lockup: kmsg ring buffer overflow, some records were dropped")
		time.Sleep(kmsgOverflowBackoff)
		// Loop with a fresh scanner; the file position advances to the next
		// available record, so reading resumes from there.
	}
}

// matchSoftLockup reports whether a /dev/kmsg record is a soft-lockup report.
// A record is "<prio>,<seq>,<ts>,<flags>;<message>"; the watchdog prints
// "watchdog: BUG: soft lockup - CPU#N stuck for Xs! [comm:pid]" (older kernels
// omit the "watchdog:" prefix), so matching the "soft lockup" substring in the
// message is robust across versions.
//
// This counts each watchdog *report*: a CPU that stays stuck is re-reported
// (with a growing duration), so a single prolonged episode increments the
// counter more than once. Per-episode deduplication is deferred pending
// alignment with the host-side collector's callstack fingerprint/dedup scheme.
func matchSoftLockup(record string) bool {
	msg := record
	if _, after, found := strings.Cut(record, ";"); found {
		msg = after
	}
	return strings.Contains(msg, "soft lockup")
}
