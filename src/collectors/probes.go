package collectors

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"metrics-exporter/src/log"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// probeResult holds the outcome of a single health probe.
type probeResult struct {
	IP      string
	Success bool
	Latency time.Duration
}

// probeICMPPing sends an ICMP Echo Request and waits for an Echo Reply.
// Requires CAP_NET_RAW (the container already runs privileged for eBPF).
func (p *ProbeCollector) probeICMPPing(ip string) probeResult {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Debugf("ICMP listen failed for %s: %v", ip, err)
		return probeResult{IP: ip}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(p.config.ProbeTimeout))

	// Build Echo Request
	id := os.Getpid() & 0xffff
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  1,
			Data: []byte("crusoe-probe"),
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		log.Debugf("ICMP marshal failed for %s: %v", ip, err)
		return probeResult{IP: ip}
	}

	dst := &net.IPAddr{IP: net.ParseIP(ip)}
	start := time.Now()

	if _, err := conn.WriteTo(wb, dst); err != nil {
		log.Debugf("ICMP write failed for %s: %v", ip, err)
		return probeResult{IP: ip}
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			log.Debugf("ICMP read failed for %s: %v", ip, err)
			return probeResult{IP: ip}
		}
		rtt := time.Since(start)

		parsed, err := icmp.ParseMessage(1, rb[:n]) // protocol number 1 = ICMP
		if err != nil {
			continue
		}
		if parsed.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		// Verify this reply is for our request
		reply, ok := parsed.Body.(*icmp.Echo)
		if !ok || reply.ID != id {
			continue
		}

		_ = peer // peer should match dst
		return probeResult{IP: ip, Success: true, Latency: rtt}
	}
}

// probeNFSv4NULL sends an ONC RPC NULL procedure call to NFSv4 (port 2049)
// and measures the round-trip time.
// The NULL procedure is the simplest RPC call — it takes no arguments and
// returns nothing, making it ideal for health checking.
func (p *ProbeCollector) probeNFSv4NULL(ip string) probeResult {
	start := time.Now()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "2049"), p.config.ProbeTimeout)
	if err != nil {
		log.Debugf("NFS TCP connect failed for %s: %v", ip, err)
		return probeResult{IP: ip}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(p.config.ProbeTimeout))

	// Build ONC RPC call for NFS NULL procedure:
	//   4 bytes: record marker (0x80000028 = last fragment, 40 bytes)
	//   4 bytes: XID (transaction ID)
	//   4 bytes: message type = CALL (0)
	//   4 bytes: RPC version = 2
	//   4 bytes: program = NFS (100003)
	//   4 bytes: version = 4
	//   4 bytes: procedure = NULL (0)
	//   4 bytes: auth flavor = AUTH_NONE (0)
	//   4 bytes: auth length = 0
	//   4 bytes: verifier flavor = AUTH_NONE (0)
	//   4 bytes: verifier length = 0
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

	if _, err := conn.Write(rpcCall); err != nil {
		log.Debugf("NFS RPC write failed for %s: %v", ip, err)
		return probeResult{IP: ip}
	}

	// Read reply: at least 4 bytes record marker + 8 bytes (XID + msg type)
	reply := make([]byte, 128)
	n, err := conn.Read(reply)
	if err != nil {
		log.Debugf("NFS RPC read failed for %s: %v", ip, err)
		return probeResult{IP: ip}
	}

	rtt := time.Since(start)

	// Validate: need at least record marker (4) + XID (4) + msg type (4) = 12 bytes
	if n < 12 {
		log.Debugf("NFS RPC reply too short from %s: %d bytes", ip, n)
		return probeResult{IP: ip}
	}

	// Check message type = REPLY (1)
	msgType := binary.BigEndian.Uint32(reply[8:12])
	if msgType != 1 {
		log.Debugf("NFS RPC unexpected msg type from %s: %d (expected 1=REPLY)", ip, msgType)
		return probeResult{IP: ip}
	}

	return probeResult{IP: ip, Success: true, Latency: rtt}
}

// probeHTTPS performs an HTTPS GET to the given IP using the configured FQDN
// for SNI/Host header. Any HTTP response (including 4xx/5xx) counts as success
// since we're measuring reachability, not content.
func (p *ProbeCollector) probeHTTPS(ip string) probeResult {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: p.config.ObjStoreFQDN,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   p.config.ProbeTimeout,
		// Don't follow redirects — any response is a success
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	url := fmt.Sprintf("https://%s:443/", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Debugf("HTTPS request creation failed for %s: %v", ip, err)
		return probeResult{IP: ip}
	}
	req.Host = p.config.ObjStoreFQDN

	start := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(start)

	if err != nil {
		log.Debugf("HTTPS probe failed for %s: %v", ip, err)
		return probeResult{IP: ip}
	}
	resp.Body.Close()

	// Any HTTP response = success (measures reachability)
	return probeResult{IP: ip, Success: true, Latency: rtt}
}
