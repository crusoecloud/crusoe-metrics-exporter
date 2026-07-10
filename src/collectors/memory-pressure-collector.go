package collectors

import (
	"bufio"
	"fmt"
	"metrics-exporter/src/log"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var meminfoKeys = map[string]bool{
	"MemAvailable": true,
	"SwapTotal":    true,
	"SwapFree":     true,
}

var psiWindows = []struct {
	label string
	pick  func(PSILine) float64
}{
	{"10", func(l PSILine) float64 { return l.Avg10 }},
	{"60", func(l PSILine) float64 { return l.Avg60 }},
	{"300", func(l PSILine) float64 { return l.Avg300 }},
}

type MemoryPressureCollector struct {
	psiMemoryPath string
	meminfoPath   string

	psiRatioDesc        *prometheus.Desc
	psiStallSecondsDesc *prometheus.Desc
	memAvailableDesc    *prometheus.Desc
	swapUsedDesc        *prometheus.Desc
	collectionErrors    prometheus.Counter
}

// NewMemoryPressureCollector builds the collector. psiMemoryPath and meminfoPath
// are typically <HOST_PROC_PATH>/pressure/memory and <HOST_PROC_PATH>/meminfo.
func NewMemoryPressureCollector(psiMemoryPath, meminfoPath string) *MemoryPressureCollector {
	return &MemoryPressureCollector{
		psiMemoryPath: psiMemoryPath,
		meminfoPath:   meminfoPath,
		psiRatioDesc: prometheus.NewDesc(
			MetricPrefix+"psi_memory_ratio",
			"Memory pressure stall as a fraction (0-1) of the rolling window, per PSI scope.",
			[]string{"scope", "window"}, nil,
		),
		psiStallSecondsDesc: prometheus.NewDesc(
			MetricPrefix+"psi_memory_stall_seconds_total",
			"Cumulative time tasks were stalled waiting on memory, per PSI scope.",
			[]string{"scope"}, nil,
		),
		memAvailableDesc: prometheus.NewDesc(
			MetricPrefix+"mem_available_bytes",
			"Memory available for new allocations without swapping, from /proc/meminfo MemAvailable.",
			nil, nil,
		),
		swapUsedDesc: prometheus.NewDesc(
			MetricPrefix+"swap_used_bytes",
			"Swap currently in use (SwapTotal - SwapFree), from /proc/meminfo.",
			nil, nil,
		),
		collectionErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: MetricPrefix + "mem_collection_errors_total",
			Help: "Total number of errors encountered during memory pressure collection.",
		}),
	}
}

func (c *MemoryPressureCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.psiRatioDesc
	ch <- c.psiStallSecondsDesc
	ch <- c.memAvailableDesc
	ch <- c.swapUsedDesc
	c.collectionErrors.Describe(ch)
}

func (c *MemoryPressureCollector) Collect(ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("MemoryPressureCollector panic recovered: %v", r)
		}
	}()

	errs := 0.0

	stats, available, err := ParsePSI(c.psiMemoryPath)
	switch {
	case err != nil:

		log.Warnf("memory pressure: failed to parse %s: %v", c.psiMemoryPath, err)
		errs++
	case !available:
		// PSI not enabled publish no PSI series.
	default:
		c.emitPSI(ch, stats)
	}

	mem, err := parseMeminfoBytes(c.meminfoPath, meminfoKeys)
	if err != nil {
		log.Warnf("memory pressure: failed to read %s: %v", c.meminfoPath, err)
		errs++
	} else {
		if v, ok := mem["MemAvailable"]; ok {
			ch <- prometheus.MustNewConstMetric(c.memAvailableDesc, prometheus.GaugeValue, v)
		} else {
			log.Warnf("memory pressure: MemAvailable missing from %s", c.meminfoPath)
			errs++
		}
		total, okT := mem["SwapTotal"]
		free, okF := mem["SwapFree"]
		if okT && okF {
			ch <- prometheus.MustNewConstMetric(c.swapUsedDesc, prometheus.GaugeValue, total-free)
		} else {
			log.Warnf("memory pressure: SwapTotal/SwapFree missing from %s", c.meminfoPath)
			errs++
		}
	}

	c.collectionErrors.Add(errs)
	ch <- c.collectionErrors
}

func (c *MemoryPressureCollector) emitPSI(ch chan<- prometheus.Metric, stats *PSIStats) {
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

func parseMeminfoBytes(path string, want map[string]bool) (map[string]float64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	out := make(map[string]float64, len(want))
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		if !want[key] {
			continue
		}
		val, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil, fmt.Errorf("meminfo %s: bad value for %s: %w", path, key, err)
		}
		if len(fields) >= 3 && fields[2] == "kB" {
			val *= 1024
		}
		out[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
