package collectors

import (
	"bufio"
	"metrics-exporter/src/log"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type IOPressureCollector struct {
	psiIOPath    string
	procStatPath string

	psiRatioDesc        *prometheus.Desc
	psiStallSecondsDesc *prometheus.Desc
	procsBlockedDesc    *prometheus.Desc
	collectionErrors    prometheus.Counter
}

func NewIOPressureCollector(psiIOPath, procStatPath string) *IOPressureCollector {
	return &IOPressureCollector{
		psiIOPath:    psiIOPath,
		procStatPath: procStatPath,
		psiRatioDesc: prometheus.NewDesc(
			MetricPrefix+"psi_io_ratio",
			"I/O pressure stall as a fraction (0-1) of the rolling window, per PSI scope.",
			[]string{"scope", "window"}, nil,
		),
		psiStallSecondsDesc: prometheus.NewDesc(
			MetricPrefix+"psi_io_stall_seconds_total",
			"Cumulative time tasks were stalled waiting on I/O, per PSI scope.",
			[]string{"scope"}, nil,
		),
		procsBlockedDesc: prometheus.NewDesc(
			MetricPrefix+"procs_blocked",
			"Number of tasks in uninterruptible sleep (D-state), from /proc/stat procs_blocked.",
			nil, nil,
		),
		collectionErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: MetricPrefix + "io_collection_errors_total",
			Help: "Total number of errors encountered during I/O pressure collection.",
		}),
	}
}

func (c *IOPressureCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.psiRatioDesc
	ch <- c.psiStallSecondsDesc
	ch <- c.procsBlockedDesc
	c.collectionErrors.Describe(ch)
}

func (c *IOPressureCollector) Collect(ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("IOPressureCollector panic recovered: %v", r)
		}
	}()

	errs := 0.0

	stats, available, err := ParsePSI(c.psiIOPath)
	switch {
	case err != nil:
		log.Warnf("io pressure: failed to parse %s: %v", c.psiIOPath, err)
		errs++
	case !available:
		//psi not enabled publish none
	default:
		c.emitPSI(ch, stats)
	}

	blocked, ok, err := parseProcsBlocked(c.procStatPath)
	switch {
	case err != nil:
		log.Warnf("io pressure: failed to read %s: %v", c.procStatPath, err)
		errs++
	case !ok:
		log.Warnf("io pressure: procs_blocked missing from %s", c.procStatPath)
		errs++
	default:
		ch <- prometheus.MustNewConstMetric(c.procsBlockedDesc, prometheus.GaugeValue, blocked)
	}

	c.collectionErrors.Add(errs)
	ch <- c.collectionErrors
}

// reuses PSI windows form memory-pressure-collector
func (c *IOPressureCollector) emitPSI(ch chan<- prometheus.Metric, stats *PSIStats) {
	for _, s := range []struct {
		name string
		line PSILine
	}{
		{"some", stats.Some},
		{"full", stats.Full},
	} {
		for _, w := range psiWindows {
			ch <- prometheus.MustNewConstMetric(
				c.psiRatioDesc, prometheus.GaugeValue, w.pick(s.line)/100.0, s.name, w.label,
			)
		}
		ch <- prometheus.MustNewConstMetric(
			c.psiStallSecondsDesc, prometheus.CounterValue, s.line.TotalSeconds, s.name,
		)
	}
}

func parseProcsBlocked(path string) (float64, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "procs_blocked" {
			v, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return 0, false, err
			}
			return v, true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, false, err
	}
	return 0, false, nil
}
