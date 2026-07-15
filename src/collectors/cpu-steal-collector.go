package collectors

import (
	"bufio"
	"metrics-exporter/src/log"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// userHz converts the jiffie counts in /proc/stat to seconds. The ticket
// suggests sysconf(_SC_CLK_TCK), but the procfs ABI fixes USER_HZ at 100 for
// userspace regardless of the kernel's internal CONFIG_HZ, so the columns are
// always in 1/100s units here. A constant avoids a cgo sysconf call.
const userHz = 100.0

type CPUStealCollector struct {
	procStatPath string

	stealSecondsDesc *prometheus.Desc
	procsRunningDesc *prometheus.Desc
	collectionErrors prometheus.Counter
}

func NewCPUStealCollector(procStatPath string) *CPUStealCollector {
	return &CPUStealCollector{
		procStatPath: procStatPath,
		stealSecondsDesc: prometheus.NewDesc(
			MetricPrefix+"cpu_steal_seconds_total",
			"Cumulative time the guest vCPUs were runnable but not scheduled by the host, aggregated across vCPUs, from /proc/stat.",
			nil, nil,
		),
		procsRunningDesc: prometheus.NewDesc(
			MetricPrefix+"procs_running",
			"Number of runnable (R-state) tasks, from /proc/stat procs_running.",
			nil, nil,
		),
		collectionErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: MetricPrefix + "cpu_collection_errors_total",
			Help: "Total number of errors encountered during CPU steal collection.",
		}),
	}
}

func (c *CPUStealCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.stealSecondsDesc
	ch <- c.procsRunningDesc
	c.collectionErrors.Describe(ch)
}

func (c *CPUStealCollector) Collect(ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("CPUStealCollector panic recovered: %v", r)
		}
	}()

	errs := 0.0

	stat, err := parseCPUStat(c.procStatPath)
	if err != nil {
		log.Warnf("cpu steal: failed to read %s: %v", c.procStatPath, err)
		errs++
	} else {
		if stat.hasSteal {
			ch <- prometheus.MustNewConstMetric(
				c.stealSecondsDesc, prometheus.CounterValue, stat.stealJiffies/userHz,
			)
		} else {
			log.Warnf("cpu steal: steal column missing or unparseable in %s", c.procStatPath)
			errs++
		}
		if stat.hasProcsRunning {
			ch <- prometheus.MustNewConstMetric(
				c.procsRunningDesc, prometheus.GaugeValue, stat.procsRunning,
			)
		} else {
			log.Warnf("cpu steal: procs_running missing or unparseable in %s", c.procStatPath)
			errs++
		}
	}

	c.collectionErrors.Add(errs)
	ch <- c.collectionErrors
}

type cpuStat struct {
	stealJiffies    float64
	procsRunning    float64
	hasSteal        bool
	hasProcsRunning bool
}

func parseCPUStat(path string) (cpuStat, error) {
	var out cpuStat

	file, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "cpu":
			if len(fields) < 9 {
				continue
			}
			// cpu  user nice system idle iowait irq softirq steal guest guest_nice — steal is fields[8].
			// A malformed value is left as hasSteal=false so procs_running still emits; Collect counts it.
			if v, perr := strconv.ParseFloat(fields[8], 64); perr == nil {
				out.stealJiffies = v
				out.hasSteal = true
			}
		case "procs_running":
			if v, perr := strconv.ParseFloat(fields[1], 64); perr == nil {
				out.procsRunning = v
				out.hasProcsRunning = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}
