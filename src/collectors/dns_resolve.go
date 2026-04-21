package collectors

import "github.com/prometheus/client_golang/prometheus"

// DNSResolveFailures tracks DNS resolution failures for NFS and ObjectStore endpoints.
// Increment with: DNSResolveFailures.WithLabelValues("nfs").Inc()
// or:             DNSResolveFailures.WithLabelValues("objectstore").Inc()
var DNSResolveFailures = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: MetricPrefix + "dns_resolve_failures_total",
		Help: "Total number of DNS resolution failures",
	},
	[]string{"type"},
)
