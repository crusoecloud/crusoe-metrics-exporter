package collectors

import (
	"metrics-exporter/src/log"

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
	cpuCountDesc     *prometheus.Desc
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
		cpuCountDesc: prometheus.NewDesc(
			MetricPrefix+"cpu_count",
			"Number of online vCPUs, counted from the per-cpu lines in /proc/stat. Divides cpu_steal_seconds_total into a fraction of the VM's compute.",
			nil, nil,
		),
		collectionErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: MetricPrefix + "cpu_steal_collection_errors_total",
			Help: "Total number of errors encountered during CPU steal collection.",
		}),
	}
}

func (c *CPUStealCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.stealSecondsDesc
	ch <- c.procsRunningDesc
	ch <- c.cpuCountDesc
	c.collectionErrors.Describe(ch)
}

func (c *CPUStealCollector) Collect(ch chan<- prometheus.Metric) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("CPUStealCollector panic recovered: %v", r)
		}
	}()

	errs := 0.0

	stat, err := readProcStat(c.procStatPath)
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
		if stat.cpuCount > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.cpuCountDesc, prometheus.GaugeValue, stat.cpuCount,
			)
		} else {
			log.Warnf("cpu steal: no per-cpu lines found in %s", c.procStatPath)
			errs++
		}
	}

	c.collectionErrors.Add(errs)
	ch <- c.collectionErrors
}
