package collectors

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// newTestDNSCollector creates a collector with a long interval so the background
// goroutine never fires during the test.
func newTestDNSCollector(targets []string, resolver string) *DNSProbeCollector {
	return NewDNSProbeCollector(targets, resolver, 1*time.Hour)
}

func TestDNSProbeCollector_Describe(t *testing.T) {
	c := newTestDNSCollector([]string{"example.com"}, "")
	defer c.Close()

	ch := make(chan *prometheus.Desc, 10)
	c.Describe(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	if count != 4 {
		t.Errorf("expected 4 descriptors, got %d", count)
	}
}

func TestDNSProbeCollector_CollectEmpty(t *testing.T) {
	c := newTestDNSCollector([]string{"example.com"}, "")
	defer c.Close()

	// No probes have run yet — nothing should be emitted
	c.mu.Lock()
	c.results = map[string]dnsProbeResult{}
	c.mu.Unlock()

	ch := make(chan prometheus.Metric, 10)
	c.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 metrics with no results, got %d", count)
	}
}

func TestDNSProbeCollector_CollectSingleTarget(t *testing.T) {
	c := newTestDNSCollector([]string{"example.com"}, "")
	defer c.Close()

	c.mu.Lock()
	c.results = map[string]dnsProbeResult{
		"example.com": {latencySeconds: 0.01, total: 3, success: 3, failure: 0},
	}
	c.mu.Unlock()

	ch := make(chan prometheus.Metric, 10)
	c.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	// latency + total + success + failure = 4 metrics per target
	if count != 4 {
		t.Errorf("expected 4 metrics for one target, got %d", count)
	}
}

func TestDNSProbeCollector_CollectMultipleTargets(t *testing.T) {
	targets := []string{"example.com", "google.com", "cloudflare.com"}
	c := newTestDNSCollector(targets, "8.8.8.8")
	defer c.Close()

	c.mu.Lock()
	c.results = map[string]dnsProbeResult{
		"example.com":   {latencySeconds: 0.01, total: 1, success: 1, failure: 0},
		"google.com":    {latencySeconds: 0.02, total: 2, success: 2, failure: 0},
		"cloudflare.com": {latencySeconds: 0.03, total: 3, success: 2, failure: 1},
	}
	c.mu.Unlock()

	ch := make(chan prometheus.Metric, 20)
	c.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	// 4 metrics per target × 3 targets = 12
	if count != 12 {
		t.Errorf("expected 12 metrics for 3 targets, got %d", count)
	}
}

func TestDNSProbeCollector_FailureLatencyIsZero(t *testing.T) {
	c := newTestDNSCollector([]string{"example.com"}, "")
	defer c.Close()

	c.mu.Lock()
	c.results = map[string]dnsProbeResult{
		"example.com": {latencySeconds: 0, total: 1, success: 0, failure: 1},
	}
	c.mu.Unlock()

	ch := make(chan prometheus.Metric, 10)
	c.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	// Still emits 4 metrics even on failure
	if count != 4 {
		t.Errorf("expected 4 metrics even on failure, got %d", count)
	}
}

func TestDNSProbeCollector_EmptyResolverEmitsFourMetrics(t *testing.T) {
	// When no resolver is configured, Collect should still emit 4 metrics
	// (the "default" label substitution is validated via /metrics output)
	c := newTestDNSCollector([]string{"example.com"}, "")
	defer c.Close()

	c.mu.Lock()
	c.results = map[string]dnsProbeResult{
		"example.com": {latencySeconds: 0.01, total: 1, success: 1, failure: 0},
	}
	c.mu.Unlock()

	ch := make(chan prometheus.Metric, 10)
	c.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	if count != 4 {
		t.Errorf("expected 4 metrics with empty resolver, got %d", count)
	}
}

func TestDNSProbeCollector_Close(t *testing.T) {
	c := newTestDNSCollector([]string{"example.com"}, "")
	c.Close() // must not panic
}
