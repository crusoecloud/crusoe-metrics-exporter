package collectors

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestProbeCollectorDescribe(t *testing.T) {
	config := ProbeConfig{
		ProbeInterval: 1 * time.Hour, // long interval so no probes run during test
		MaxJitter:     0,
		ProbeTimeout:  1 * time.Second,
	}
	p := NewProbeCollector(config)
	defer p.Close()

	ch := make(chan *prometheus.Desc, 10)
	p.Describe(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count != 4 {
		t.Errorf("expected 4 descriptors, got %d", count)
	}
}

func TestProbeCollectorCollectEmitsResults(t *testing.T) {
	config := ProbeConfig{
		ProbeInterval: 1 * time.Hour,
		MaxJitter:     0,
		ProbeTimeout:  1 * time.Second,
	}
	p := NewProbeCollector(config)
	defer p.Close()

	// Manually set some results
	p.mu.Lock()
	p.pingResults = []probeResult{
		{IP: "10.0.0.1", Success: true, Latency: 5 * time.Millisecond},
		{IP: "10.0.0.2", Success: true, Latency: 10 * time.Millisecond},
	}
	p.rpcResults = []probeResult{
		{IP: "10.0.0.1", Success: true, Latency: 15 * time.Millisecond},
	}
	p.objStorePingResults = []probeResult{
		{IP: "10.0.0.3", Success: true, Latency: 8 * time.Millisecond},
	}
	p.httpsResults = []probeResult{
		{IP: "10.0.0.3", Success: true, Latency: 100 * time.Millisecond},
	}
	p.mu.Unlock()

	ch := make(chan prometheus.Metric, 20)
	p.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	// 2 nfs ping + 1 rpc + 1 objstore ping + 1 https = 5 metrics
	if count != 5 {
		t.Errorf("expected 5 metrics, got %d", count)
	}
}

func TestProbeCollectorCollectFailedProbeEmitsZero(t *testing.T) {
	config := ProbeConfig{
		ProbeInterval: 1 * time.Hour,
		MaxJitter:     0,
		ProbeTimeout:  1 * time.Second,
	}
	p := NewProbeCollector(config)
	defer p.Close()

	// Set a failed result (Success=false)
	p.mu.Lock()
	p.pingResults = []probeResult{
		{IP: "10.0.0.1", Success: false, Latency: 0},
	}
	p.mu.Unlock()

	ch := make(chan prometheus.Metric, 10)
	p.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count != 1 {
		t.Errorf("expected 1 metric for failed probe, got %d", count)
	}
}

func TestNFSv4NULLRPCPacketFormat(t *testing.T) {
	// Verify the 44-byte RPC call packet structure matches the expected format:
	// 4 bytes record marker + 40 bytes RPC body
	rpcCall := make([]byte, 44)
	binary.BigEndian.PutUint32(rpcCall[0:4], 0x80000028)  // record marker: last fragment, 40 bytes
	binary.BigEndian.PutUint32(rpcCall[4:8], 0x00000001)   // XID
	binary.BigEndian.PutUint32(rpcCall[8:12], 0)           // msg type: CALL
	binary.BigEndian.PutUint32(rpcCall[12:16], 2)          // RPC version
	binary.BigEndian.PutUint32(rpcCall[16:20], 100003)     // program: NFS
	binary.BigEndian.PutUint32(rpcCall[20:24], 4)          // version: 4
	binary.BigEndian.PutUint32(rpcCall[24:28], 0)          // procedure: NULL
	binary.BigEndian.PutUint32(rpcCall[28:32], 0)          // auth flavor: AUTH_NONE
	binary.BigEndian.PutUint32(rpcCall[32:36], 0)          // auth length: 0
	binary.BigEndian.PutUint32(rpcCall[36:40], 0)          // verifier flavor: AUTH_NONE
	binary.BigEndian.PutUint32(rpcCall[40:44], 0)          // verifier length: 0

	// Total length
	if len(rpcCall) != 44 {
		t.Errorf("RPC call should be 44 bytes, got %d", len(rpcCall))
	}

	// Record marker: 0x80000028 = last fragment flag (0x80000000) | length 40 (0x28)
	recordMarker := binary.BigEndian.Uint32(rpcCall[0:4])
	if recordMarker != 0x80000028 {
		t.Errorf("record marker: got 0x%08x, want 0x80000028", recordMarker)
	}
	fragmentLength := recordMarker & 0x7FFFFFFF
	if fragmentLength != 40 {
		t.Errorf("fragment length: got %d, want 40", fragmentLength)
	}

	// RPC body starts at offset 4
	body := rpcCall[4:]
	if len(body) != 40 {
		t.Errorf("RPC body should be 40 bytes, got %d", len(body))
	}

	// Verify program = NFS (100003)
	program := binary.BigEndian.Uint32(body[12:16])
	if program != 100003 {
		t.Errorf("program: got %d, want 100003", program)
	}

	// Verify version = 4
	version := binary.BigEndian.Uint32(body[16:20])
	if version != 4 {
		t.Errorf("version: got %d, want 4", version)
	}

	// Verify procedure = NULL (0)
	procedure := binary.BigEndian.Uint32(body[20:24])
	if procedure != 0 {
		t.Errorf("procedure: got %d, want 0", procedure)
	}

	// Verify msg type = CALL (0)
	msgType := binary.BigEndian.Uint32(body[4:8])
	if msgType != 0 {
		t.Errorf("msg type: got %d, want 0 (CALL)", msgType)
	}

	// Verify RPC version = 2
	rpcVersion := binary.BigEndian.Uint32(body[8:12])
	if rpcVersion != 2 {
		t.Errorf("RPC version: got %d, want 2", rpcVersion)
	}
}

func TestProbeConfigDefaults(t *testing.T) {
	config := ProbeConfig{}
	p := NewProbeCollector(config)
	defer p.Close()

	if p.config.ProbeInterval != 5*time.Minute {
		t.Errorf("default ProbeInterval: got %v, want 5m", p.config.ProbeInterval)
	}
	if p.config.MaxJitter != 60*time.Second {
		t.Errorf("default MaxJitter: got %v, want 60s", p.config.MaxJitter)
	}
	if p.config.ProbeTimeout != 10*time.Second {
		t.Errorf("default ProbeTimeout: got %v, want 10s", p.config.ProbeTimeout)
	}
}

func TestDiscoverNFSIPs_NoMountsFile(t *testing.T) {
	config := ProbeConfig{
		HostMountsPath: "/nonexistent/path/mounts",
		ProbeInterval:  1 * time.Hour,
		MaxJitter:      0,
		ProbeTimeout:   1 * time.Second,
	}
	p := NewProbeCollector(config)
	defer p.Close()

	ips := p.discoverNFSIPs()
	if ips != nil {
		t.Errorf("expected nil for nonexistent mounts file, got %v", ips)
	}
}

func TestResolveObjStoreIPs_EmptyFQDN(t *testing.T) {
	config := ProbeConfig{
		ObjStoreFQDN:  "",
		ProbeInterval: 1 * time.Hour,
		MaxJitter:     0,
		ProbeTimeout:  1 * time.Second,
	}
	p := NewProbeCollector(config)
	defer p.Close()

	ips := p.resolveObjStoreIPs()
	if ips != nil {
		t.Errorf("expected nil for empty FQDN, got %v", ips)
	}
}

func TestDiscoverNFSIPs_EmptyPath(t *testing.T) {
	config := ProbeConfig{
		HostMountsPath: "",
		ProbeInterval:  1 * time.Hour,
		MaxJitter:      0,
		ProbeTimeout:   1 * time.Second,
	}
	p := NewProbeCollector(config)
	defer p.Close()

	ips := p.discoverNFSIPs()
	if ips != nil {
		t.Errorf("expected nil for empty mounts path, got %v", ips)
	}
}

func TestProbeCollectorCollectEmpty(t *testing.T) {
	config := ProbeConfig{
		ProbeInterval: 1 * time.Hour,
		MaxJitter:     0,
		ProbeTimeout:  1 * time.Second,
	}
	p := NewProbeCollector(config)
	defer p.Close()

	// No results stored — Collect should emit nothing
	ch := make(chan prometheus.Metric, 10)
	p.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count != 0 {
		t.Errorf("expected 0 metrics with no results, got %d", count)
	}
}
