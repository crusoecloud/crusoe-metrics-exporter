// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Crusoe Energy */
//
// Object store latency probe.  Measures the real elapsed time between an
// outbound tcp_sendmsg and the next inbound tcp_recvmsg on the *same*
// socket, provided the socket's destination IP is present in the
// objstore_server_ips map AND the destination port matches the configured
// target port (typically 80 or 443).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "objstore_latency.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// -----------------------------------------------------------------------
// Structures
// -----------------------------------------------------------------------

// Configuration structure expected by Go collector
struct config {
    __u16 target_port;  // network byte order
    __u16 padding;
};

// HTTP method classification
#define HTTP_METHOD_UNKNOWN 0
#define HTTP_METHOD_GET     1
#define HTTP_METHOD_PUT     2
#define HTTP_METHOD_POST    3
#define HTTP_METHOD_DELETE  4
#define HTTP_METHOD_HEAD    5

// Composite key for per-IP, per-method stats.
struct stats_key {
    __u32 dest_ip;
    __u32 method;   // HTTP_METHOD_*
};

// Track in-flight requests per socket
struct active_request {
    __u64 send_time_ns;
    __u64 send_size;
    __u32 dest_ip;
    __u32 method;   // HTTP_METHOD_*
};

// Latency statistics structure
struct latency_stats {
    __u64 request_count;
    __u64 total_latency_ns;
    __u64 histogram[HISTOGRAM_BUCKETS];
    __u64 retransmit_count;
    __u64 bytes_sent;
    __u64 bytes_recv;
};

// -----------------------------------------------------------------------
// Maps
// -----------------------------------------------------------------------

// Config map -- Go collector writes the target port here.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

// Per-IP, per-method latency stats consumed by the Go collector.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct stats_key);
    __type(value, struct latency_stats);
} objstore_latency_by_ip SEC(".maps");

// Object store server IPs -- populated by the Go collector at start-up.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} objstore_server_ips SEC(".maps");

// In-flight request tracking.  Key = socket pointer cast to __u64.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct active_request);
} active_requests SEC(".maps");

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// Check whether dest_ip is one of the known object store server IPs.
static __always_inline bool is_objstore_server(__u32 dest_ip)
{
    for (__u32 i = 0; i < 64; i++) {
        __u32 idx = i;
        __u32 *ip = bpf_map_lookup_elem(&objstore_server_ips, &idx);
        if (!ip || *ip == 0)
            break;
        if (*ip == dest_ip)
            return true;
    }
    return false;
}

// Histogram bucket assignment -- 20 geometric buckets from 0.1ms to 25ms
// matching Go-side objstore histogram boundaries.
// Input is in nanoseconds.
static __always_inline void update_objstore_histogram(__u64 *histogram,
                                                       __u64 latency_ns)
{
    __u64 latency_us = latency_ns / 1000;  // convert to microseconds

    int bucket;
    if (latency_us < 100)             bucket = 0;   // < 0.10ms
    else if (latency_us < 134)        bucket = 1;   // 0.10-0.13ms
    else if (latency_us < 179)        bucket = 2;   // 0.13-0.18ms
    else if (latency_us < 239)        bucket = 3;   // 0.18-0.24ms
    else if (latency_us < 320)        bucket = 4;   // 0.24-0.32ms
    else if (latency_us < 428)        bucket = 5;   // 0.32-0.43ms
    else if (latency_us < 572)        bucket = 6;   // 0.43-0.57ms
    else if (latency_us < 765)        bucket = 7;   // 0.57-0.77ms
    else if (latency_us < 1022)       bucket = 8;   // 0.77-1.02ms
    else if (latency_us < 1367)       bucket = 9;   // 1.02-1.37ms
    else if (latency_us < 1828)       bucket = 10;  // 1.37-1.83ms
    else if (latency_us < 2445)       bucket = 11;  // 1.83-2.45ms
    else if (latency_us < 3270)       bucket = 12;  // 2.45-3.27ms
    else if (latency_us < 4372)       bucket = 13;  // 3.27-4.37ms
    else if (latency_us < 5847)       bucket = 14;  // 4.37-5.85ms
    else if (latency_us < 7818)       bucket = 15;  // 5.85-7.82ms
    else if (latency_us < 10455)      bucket = 16;  // 7.82-10.46ms
    else if (latency_us < 13981)      bucket = 17;  // 10.46-13.98ms
    else if (latency_us < 18695)      bucket = 18;  // 13.98-18.70ms
    else                              bucket = 19;  // >= 18.70ms

    if (bucket < HISTOGRAM_BUCKETS)
        __sync_fetch_and_add(&histogram[bucket], 1);
}

// Detect the HTTP method from the first few bytes of a send buffer.
// Returns HTTP_METHOD_* constant.
//
// We use raw bpf_probe_read_kernel (no CO-RE) because iov_iter field
// names changed between kernel 5.15 and 6.x.  The msghdr layout on
// x86_64 is stable:
//   msg_name(8) + msg_namelen(4) + pad(4) = 16 bytes -> msg_iter at +16
//
// Inside iov_iter the iov pointer lives at different offsets:
//   5.15: type(4)+pad(4)+iov_offset(8)+count(8)+union -> iov at +24
//   6.x:  iter_type(1)+bools(2)+pad(5)+iov_offset(8)+union -> iov at +16
//
// The iov pointer points to a struct iovec whose first field (iov_base)
// is the user-space buffer address -- stable across all versions.
//
// We try offset 16 first (6.x), then 24 (5.15).  If the first candidate
// yields a readable HTTP method we return it; otherwise try the second.
#define MSGHDR_ITER_OFFSET  16   // offsetof(msghdr, msg_iter) on x86_64
#define IOV_OFFSET_6X       16   // iov_iter union offset on 6.x
#define IOV_OFFSET_515      24   // iov_iter union offset on 5.15

static __always_inline __u32 try_read_http_method(void *iov_ptr)
{
    // iov_ptr -> struct iovec; first field is iov_base (user-space ptr)
    void *iov_base = NULL;
    if (bpf_probe_read_kernel(&iov_base, sizeof(iov_base), iov_ptr) < 0)
        return HTTP_METHOD_UNKNOWN;
    if (!iov_base)
        return HTTP_METHOD_UNKNOWN;

    char buf[4] = {};
    if (bpf_probe_read_user(buf, 4, iov_base) < 0)
        return HTTP_METHOD_UNKNOWN;

    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ')
        return HTTP_METHOD_GET;
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ')
        return HTTP_METHOD_PUT;
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T')
        return HTTP_METHOD_POST;
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D')
        return HTTP_METHOD_HEAD;
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E')
        return HTTP_METHOD_DELETE;

    return HTTP_METHOD_UNKNOWN;
}

static __always_inline __u32 detect_http_method(struct msghdr *msg)
{
    // Read the iov pointer at the 6.x offset first
    void *iov_ptr = NULL;
    void *iter_addr = (void *)msg + MSGHDR_ITER_OFFSET;

    if (bpf_probe_read_kernel(&iov_ptr, sizeof(iov_ptr),
                              iter_addr + IOV_OFFSET_6X) < 0)
        return HTTP_METHOD_UNKNOWN;

    if (iov_ptr) {
        __u32 method = try_read_http_method(iov_ptr);
        if (method != HTTP_METHOD_UNKNOWN)
            return method;
    }

    // Fall back to 5.15 offset
    iov_ptr = NULL;
    if (bpf_probe_read_kernel(&iov_ptr, sizeof(iov_ptr),
                              iter_addr + IOV_OFFSET_515) < 0)
        return HTTP_METHOD_UNKNOWN;

    if (iov_ptr)
        return try_read_http_method(iov_ptr);

    return HTTP_METHOD_UNKNOWN;
}

// Record bytes sent for the given destination IP and method.
// Called from tcp_sendmsg_entry on every outbound TCP segment.
static __always_inline void record_send_bytes(struct stats_key *key, __u64 send_bytes)
{
    struct latency_stats *stats =
        bpf_map_lookup_elem(&objstore_latency_by_ip, key);
    if (stats) {
        __sync_fetch_and_add(&stats->bytes_sent, send_bytes);
    } else {
        struct latency_stats new_stats = {};
        new_stats.bytes_sent = send_bytes;
        bpf_map_update_elem(&objstore_latency_by_ip, key,
                            &new_stats, BPF_NOEXIST);
    }
}

// Record a completed request: increment request_count, latency, and recv bytes.
// Called from tcp_cleanup_rbuf when the server delivers application data,
// which corresponds to an HTTP response.  This gives us one count per
// request-response pair rather than one per TCP segment.
static __always_inline void record_recv(struct stats_key *key, __u64 latency_ns,
                                         __u64 recv_bytes)
{
    struct latency_stats *stats =
        bpf_map_lookup_elem(&objstore_latency_by_ip, key);
    if (stats) {
        __sync_fetch_and_add(&stats->request_count, 1);
        __sync_fetch_and_add(&stats->total_latency_ns, latency_ns);
        __sync_fetch_and_add(&stats->bytes_recv, recv_bytes);
        update_objstore_histogram(stats->histogram, latency_ns);
    }
}

// -----------------------------------------------------------------------
// Probes
// -----------------------------------------------------------------------

// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
//
// On every outbound TCP send we check whether the socket targets a known
// object store IP on the configured port.  If so we record a timestamp
// keyed by the socket pointer so we can pair it with the next receive.
SEC("kprobe/tcp_sendmsg")
int tcp_sendmsg_entry(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    // Only handle AF_INET (IPv4)
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    __u32 dest_ip   = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dest_port = BPF_CORE_READ(sk, __sk_common.skc_dport);

    // Check target port from config (port is in network byte order)
    __u32 cfg_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (cfg) {
        __u16 target_port_net = bpf_htons(cfg->target_port);
        if (dest_port != target_port_net)
            return 0;
    }

    // Check if this destination is a known object store server
    if (!is_objstore_server(dest_ip))
        return 0;

    __u64 size = (__u64)PT_REGS_PARM3(ctx);

    // Detect HTTP method from the send payload.  Only the first
    // tcp_sendmsg of a request carries the HTTP request line;
    // continuation segments will return UNKNOWN and we keep the
    // method from the first segment via BPF_NOEXIST below.
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    __u32 method = HTTP_METHOD_UNKNOWN;
    if (msg)
        method = detect_http_method(msg);

    // Look up existing active_request for this socket.  If one exists
    // this is a continuation segment -- reuse its method and accumulate
    // bytes into the same stats key.
    __u64 sk_key = (__u64)sk;
    struct active_request *existing =
        bpf_map_lookup_elem(&active_requests, &sk_key);
    if (existing) {
        // Continuation of an existing request -- keep original method
        // and timestamp, just accumulate bytes.
        struct stats_key skey = {};
        skey.dest_ip = existing->dest_ip;
        skey.method  = existing->method;
        record_send_bytes(&skey, size);
        return 0;
    }

    // New request on this socket -- record method and timestamp.
    struct stats_key skey = {};
    skey.dest_ip = dest_ip;
    skey.method  = method;
    record_send_bytes(&skey, size);

    struct active_request req = {};
    req.send_time_ns = bpf_ktime_get_ns();
    req.dest_ip      = dest_ip;
    req.send_size    = size;
    req.method       = method;

    bpf_map_update_elem(&active_requests, &sk_key, &req, BPF_NOEXIST);
    return 0;
}

// tcp_cleanup_rbuf(struct sock *sk, int copied)
//
// Called after every successful TCP receive, regardless of whether the
// application used recvmsg, read, readv, splice, or io_uring.  This is
// the most reliable hook for tracking inbound data.  "copied" is the
// actual number of bytes delivered to the application.
SEC("kprobe/tcp_cleanup_rbuf")
int tcp_cleanup_rbuf_entry(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    int copied = (int)PT_REGS_PARM2(ctx);
    if (copied <= 0)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    __u32 dest_ip   = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dest_port = BPF_CORE_READ(sk, __sk_common.skc_dport);

    __u32 cfg_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (cfg) {
        __u16 target_port_net = bpf_htons(cfg->target_port);
        if (dest_port != target_port_net)
            return 0;
    }

    if (!is_objstore_server(dest_ip))
        return 0;

    // Look up the pending send-side timestamp for this socket
    __u64 sk_key = (__u64)sk;
    struct active_request *req =
        bpf_map_lookup_elem(&active_requests, &sk_key);
    if (!req)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 latency_ns = now - req->send_time_ns;

    struct stats_key skey = {};
    skey.dest_ip = req->dest_ip;
    skey.method  = req->method;
    record_recv(&skey, latency_ns, (__u64)copied);

    // Delete the entry so the next tcp_sendmsg (new HTTP request)
    // creates a fresh entry with a new method and timestamp.
    bpf_map_delete_elem(&active_requests, &sk_key);
    return 0;
}

// tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
//
// Fires on every TCP retransmission.  We check if the socket targets a
// known object store server IP and increment the per-IP retransmit counter.
SEC("kprobe/tcp_retransmit_skb")
int tcp_retransmit_entry(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    __u32 dest_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    if (!is_objstore_server(dest_ip))
        return 0;

    // Retransmits are not associated with a specific HTTP method,
    // so we use HTTP_METHOD_UNKNOWN (0) as the method key.
    struct stats_key skey = {};
    skey.dest_ip = dest_ip;
    skey.method  = HTTP_METHOD_UNKNOWN;
    struct latency_stats *stats =
        bpf_map_lookup_elem(&objstore_latency_by_ip, &skey);
    if (stats) {
        __sync_fetch_and_add(&stats->retransmit_count, 1);
    } else {
        struct latency_stats new_stats = {};
        new_stats.retransmit_count = 1;
        bpf_map_update_elem(&objstore_latency_by_ip, &skey,
                            &new_stats, BPF_NOEXIST);
    }
    return 0;
}

