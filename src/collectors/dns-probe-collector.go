package collectors

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// DNSProbeCollector periodically resolves a list of target hostnames and emits
// latency, success, failure, and total counters per target.
type DNSProbeCollector struct {
	targets  []string
	resolver string
	interval time.Duration

	latency *prometheus.Desc
	total   *prometheus.Desc
	success *prometheus.Desc
	failure *prometheus.Desc

	mu      sync.Mutex
	results map[string]dnsProbeResult

	closeCh chan struct{}
}

type dnsProbeResult struct {
	latencySeconds float64
	total          float64
	success        float64
	failure        float64
}

func NewDNSProbeCollector(targets []string, resolver string, interval time.Duration) *DNSProbeCollector {
	c := &DNSProbeCollector{
		targets:  targets,
		resolver: resolver,
		interval: interval,
		closeCh:  make(chan struct{}),
		results:  make(map[string]dnsProbeResult),
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
	c.probeAll()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.probeAll()
		case <-c.closeCh:
			return
		}
	}
}

func (c *DNSProbeCollector) probeAll() {
	var wg sync.WaitGroup
	for _, target := range c.targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			c.probe(t)
		}(target)
	}
	wg.Wait()
}

func (c *DNSProbeCollector) probe(target string) {
	var r *net.Resolver
	if c.resolver != "" {
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", c.resolver+":53")
			},
		}
	} else {
		r = net.DefaultResolver
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err := r.LookupHost(ctx, target)
	latency := time.Since(start).Seconds()

	c.mu.Lock()
	defer c.mu.Unlock()
	res := c.results[target]
	res.total++
	if err == nil {
		res.success++
		res.latencySeconds = latency
	} else {
		res.failure++
		res.latencySeconds = 0
	}
	c.results[target] = res
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
	resolver := c.resolver
	if resolver == "" {
		resolver = "default"
	}
	for target, res := range c.results {
		ch <- prometheus.MustNewConstMetric(c.latency, prometheus.GaugeValue, res.latencySeconds, target, resolver)
		ch <- prometheus.MustNewConstMetric(c.total, prometheus.CounterValue, res.total, target, resolver)
		ch <- prometheus.MustNewConstMetric(c.success, prometheus.CounterValue, res.success, target, resolver)
		ch <- prometheus.MustNewConstMetric(c.failure, prometheus.CounterValue, res.failure, target, resolver)
	}
}

func (c *DNSProbeCollector) Close() {
	close(c.closeCh)
}
