package collectors

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLookupIP_Success_IncrementsCounters(t *testing.T) {
	host, dnsType := "localhost", "nfs"
	beforeTotal := testutil.ToFloat64(DNSResolveTotal.WithLabelValues(dnsType, host))
	beforeSuccesses := testutil.ToFloat64(DNSResolveSuccesses.WithLabelValues(dnsType, host))
	beforeFailures := testutil.ToFloat64(DNSResolveFailures.WithLabelValues(dnsType, host))

	_, err := LookupIP(host, dnsType)
	if err != nil {
		t.Fatalf("LookupIP(%q) unexpected error: %v", host, err)
	}

	if got := testutil.ToFloat64(DNSResolveTotal.WithLabelValues(dnsType, host)) - beforeTotal; got != 1 {
		t.Errorf("dns_resolve_total delta: want 1, got %v", got)
	}
	if got := testutil.ToFloat64(DNSResolveSuccesses.WithLabelValues(dnsType, host)) - beforeSuccesses; got != 1 {
		t.Errorf("dns_resolve_successes_total delta: want 1, got %v", got)
	}
	if got := testutil.ToFloat64(DNSResolveFailures.WithLabelValues(dnsType, host)) - beforeFailures; got != 0 {
		t.Errorf("dns_resolve_failures_total delta: want 0, got %v", got)
	}
}

func TestLookupIP_Failure_IncrementsFailureCounter(t *testing.T) {
	host, dnsType := "lookupip-fail-xyzabc.invalid", "objectstore"
	beforeTotal := testutil.ToFloat64(DNSResolveTotal.WithLabelValues(dnsType, host))
	beforeFailures := testutil.ToFloat64(DNSResolveFailures.WithLabelValues(dnsType, host))
	beforeSuccesses := testutil.ToFloat64(DNSResolveSuccesses.WithLabelValues(dnsType, host))

	_, err := LookupIP(host, dnsType)
	if err == nil {
		t.Fatal("LookupIP with invalid host should have returned an error")
	}

	if got := testutil.ToFloat64(DNSResolveTotal.WithLabelValues(dnsType, host)) - beforeTotal; got != 1 {
		t.Errorf("dns_resolve_total delta: want 1, got %v", got)
	}
	if got := testutil.ToFloat64(DNSResolveFailures.WithLabelValues(dnsType, host)) - beforeFailures; got != 1 {
		t.Errorf("dns_resolve_failures_total delta: want 1, got %v", got)
	}
	if got := testutil.ToFloat64(DNSResolveSuccesses.WithLabelValues(dnsType, host)) - beforeSuccesses; got != 0 {
		t.Errorf("dns_resolve_successes_total delta: want 0, got %v", got)
	}
}

func TestLookupHost_Success_IncrementsCounters(t *testing.T) {
	host, dnsType := "localhost", "nfs"
	beforeTotal := testutil.ToFloat64(DNSResolveTotal.WithLabelValues(dnsType, host))
	beforeSuccesses := testutil.ToFloat64(DNSResolveSuccesses.WithLabelValues(dnsType, host))

	addrs, err := LookupHost(host, dnsType)
	if err != nil {
		t.Fatalf("LookupHost(%q) unexpected error: %v", host, err)
	}
	if len(addrs) == 0 {
		t.Fatal("LookupHost(localhost) returned no addresses")
	}

	if got := testutil.ToFloat64(DNSResolveTotal.WithLabelValues(dnsType, host)) - beforeTotal; got != 1 {
		t.Errorf("dns_resolve_total delta: want 1, got %v", got)
	}
	if got := testutil.ToFloat64(DNSResolveSuccesses.WithLabelValues(dnsType, host)) - beforeSuccesses; got != 1 {
		t.Errorf("dns_resolve_successes_total delta: want 1, got %v", got)
	}
}

func TestLookupHost_Failure_IncrementsFailureCounter(t *testing.T) {
	host, dnsType := "lookuphost-fail-xyzabc.invalid", "nfs"
	beforeTotal := testutil.ToFloat64(DNSResolveTotal.WithLabelValues(dnsType, host))
	beforeFailures := testutil.ToFloat64(DNSResolveFailures.WithLabelValues(dnsType, host))

	_, err := LookupHost(host, dnsType)
	if err == nil {
		t.Fatal("LookupHost with invalid host should have returned an error")
	}

	if got := testutil.ToFloat64(DNSResolveTotal.WithLabelValues(dnsType, host)) - beforeTotal; got != 1 {
		t.Errorf("dns_resolve_total delta: want 1, got %v", got)
	}
	if got := testutil.ToFloat64(DNSResolveFailures.WithLabelValues(dnsType, host)) - beforeFailures; got != 1 {
		t.Errorf("dns_resolve_failures_total delta: want 1, got %v", got)
	}
}
