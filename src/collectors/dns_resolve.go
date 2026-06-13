package collectors

import (
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	DNSResolveTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricPrefix + "dns_resolve_total",
			Help: "Total number of DNS resolution attempts",
		},
		[]string{"type", "host"},
	)

	DNSResolveSuccesses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricPrefix + "dns_resolve_successes_total",
			Help: "Total number of successful DNS resolutions",
		},
		[]string{"type", "host"},
	)

	DNSResolveFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricPrefix + "dns_resolve_failures_total",
			Help: "Total number of DNS resolution failures",
		},
		[]string{"type", "host"},
	)

	DNSResolveLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    MetricPrefix + "dns_resolve_latency_seconds",
			Help:    "Latency of DNS resolution attempts in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
		},
		[]string{"type", "host"},
	)
)

// LookupIP wraps net.LookupIP and records DNS metrics labelled by type and host.
func LookupIP(host, dnsType string) ([]net.IP, error) {
	DNSResolveTotal.WithLabelValues(dnsType, host).Inc()
	start := time.Now()
	ips, err := net.LookupIP(host)
	DNSResolveLatency.WithLabelValues(dnsType, host).Observe(time.Since(start).Seconds())
	if err != nil {
		DNSResolveFailures.WithLabelValues(dnsType, host).Inc()
	} else {
		DNSResolveSuccesses.WithLabelValues(dnsType, host).Inc()
	}
	return ips, err
}

// LookupHost wraps net.LookupHost and records DNS metrics labelled by type and host.
func LookupHost(host, dnsType string) ([]string, error) {
	DNSResolveTotal.WithLabelValues(dnsType, host).Inc()
	start := time.Now()
	addrs, err := net.LookupHost(host)
	DNSResolveLatency.WithLabelValues(dnsType, host).Observe(time.Since(start).Seconds())
	if err != nil {
		DNSResolveFailures.WithLabelValues(dnsType, host).Inc()
	} else {
		DNSResolveSuccesses.WithLabelValues(dnsType, host).Inc()
	}
	return addrs, err
}
