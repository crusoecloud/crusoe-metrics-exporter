package collectors

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// DNSProbeCollector periodically resolves a target hostname and emits
// latency, success, failure, and total counters.
type DNSProbeCollector struct {
	target   string
	resolver string
	interval time.Duration

	latency *prometheus.Desc
	total   *prometheus.Desc
	success *prometheus.Desc
	failure *prometheus.Desc

	mu      sync.Mutex
	results dnsProbeResult

	closeCh chan struct{}
}

type dnsProbeResult struct {
	latencySeconds float64
	total          float64
	success        float64
	failure        float64
}

func NewDNSProbeCollector(target, resolver string, interval time.Duration) *DNSProbeCollector {
	c := &DNSProbeCollector{
		target:   target,
		resolver: resolver,
		interval: interval,
		closeCh:  make(chan struct{}),
		latency: prometheus.NewDesc(
			MetricPrefix+"dns_probe_latency_seconds",
			"DNS resolution latency in seconds for the most recent probe",
			[]string{"target", "resolver"}, nil,
		),
		total: prometheus.NewDesc(
			MetricPrefix+"dns_probe_total",
			"Total DNS probe attempts",
			[]string{"target", "resolver"}, nil,
		),
		success: prometheus.NewDesc(
			MetricPrefix+"dns_probe_success_total",
			"Successful DNS probe attempts",
			[]string{"target", "resolver"}, nil,
		),
		failure: prometheus.NewDesc(
			MetricPrefix+"dns_probe_failure_total",
			"Failed DNS probe attempts",
			[]string{"target", "resolver"}, nil,
		),
	}
	go c.probeLoop()
	return c
}

func (c *DNSProbeCollector) probeLoop() {
	c.probe()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.probe()
		case <-c.closeCh:
			return
		}
	}
}

func (c *DNSProbeCollector) probe() {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", c.resolver+":53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err := r.LookupHost(ctx, c.target)
	latency := time.Since(start).Seconds()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.results.total++
	if err == nil {
		c.results.success++
		c.results.latencySeconds = latency
	} else {
		c.results.failure++
		c.results.latencySeconds = 0
	}
}

func (c *DNSProbeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.latency
	ch <- c.total
	ch <- c.success
	ch <- c.failure
}

func (c *DNSProbeCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch <- prometheus.MustNewConstMetric(c.latency, prometheus.GaugeValue, c.results.latencySeconds, c.target, c.resolver)
	ch <- prometheus.MustNewConstMetric(c.total, prometheus.CounterValue, c.results.total, c.target, c.resolver)
	ch <- prometheus.MustNewConstMetric(c.success, prometheus.CounterValue, c.results.success, c.target, c.resolver)
	ch <- prometheus.MustNewConstMetric(c.failure, prometheus.CounterValue, c.results.failure, c.target, c.resolver)
}

func (c *DNSProbeCollector) Close() {
	close(c.closeCh)
}
