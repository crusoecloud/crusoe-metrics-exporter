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

// Request classification by TCP byte-ratio.
// Works for both HTTP and HTTPS since it does not inspect payload.
#define METHOD_OTHER   0
#define METHOD_GET     1
#define METHOD_PUT     2

// Byte threshold: a request must send or receive more than this many
// bytes to be classified as PUT or GET.  Below this, it is OTHER
// (HEAD, DELETE, LIST, small objects, etc.).
#define CLASSIFY_MIN_BYTES  4096

// Composite key for per-IP, per-method stats.
struct stats_key {
    __u32 dest_ip;
    __u32 method;   // METHOD_*
};

// Track in-flight requests per socket.
// Both tcp_sendmsg and tcp_cleanup_rbuf accumulate bytes here.
// Metrics are finalized when the next tcp_sendmsg arrives on the
// same socket (indicating the previous HTTP request completed).
struct active_request {
    __u64 send_time_ns;      // timestamp of first tcp_sendmsg
    __u64 recv_time_ns;      // timestamp of last tcp_cleanup_rbuf (0 = no recv yet)
    __u64 total_bytes_sent;  // accumulated across all tcp_sendmsg calls
    __u64 total_bytes_recv;  // accumulated across all tcp_cleanup_rbuf calls
    __u32 dest_ip;
    __u32 retransmit_count;  // retransmits during this request
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

// Histogram bucket assignment -- 20 geometric buckets from 1ms to 1000ms
// matching Go-side objstore histogram boundaries.
// Geometric ratio ~1.468 (1000/1)^(1/19).
// Input is in nanoseconds.
static __always_inline void update_objstore_histogram(__u64 *histogram,
                                                       __u64 latency_ns)
{
    __u64 latency_us = latency_ns / 1000;  // convert to microseconds

    int bucket;
    if (latency_us < 1000)            bucket = 0;   // < 1.00ms
    else if (latency_us < 1468)       bucket = 1;   // 1.00-1.47ms
    else if (latency_us < 2154)       bucket = 2;   // 1.47-2.15ms
    else if (latency_us < 3162)       bucket = 3;   // 2.15-3.16ms
    else if (latency_us < 4642)       bucket = 4;   // 3.16-4.64ms
    else if (latency_us < 6813)       bucket = 5;   // 4.64-6.81ms
    else if (latency_us < 10000)      bucket = 6;   // 6.81-10.00ms
    else if (latency_us < 14678)      bucket = 7;   // 10.00-14.68ms
    else if (latency_us < 21544)      bucket = 8;   // 14.68-21.54ms
    else if (latency_us < 31623)      bucket = 9;   // 21.54-31.62ms
    else if (latency_us < 46416)      bucket = 10;  // 31.62-46.42ms
    else if (latency_us < 68129)      bucket = 11;  // 46.42-68.13ms
    else if (latency_us < 100000)     bucket = 12;  // 68.13-100.00ms
    else if (latency_us < 146780)     bucket = 13;  // 100.00-146.78ms
    else if (latency_us < 215443)     bucket = 14;  // 146.78-215.44ms
    else if (latency_us < 316228)     bucket = 15;  // 215.44-316.23ms
    else if (latency_us < 464159)     bucket = 16;  // 316.23-464.16ms
    else if (latency_us < 681292)     bucket = 17;  // 464.16-681.29ms
    else if (latency_us < 1000000)    bucket = 18;  // 681.29-1000.00ms
    else                              bucket = 19;  // >= 1000ms

    if (bucket < HISTOGRAM_BUCKETS)
        __sync_fetch_and_add(&histogram[bucket], 1);
}

// Classify a completed request as GET, PUT, or OTHER based on the
// ratio of bytes sent vs bytes received.
static __always_inline __u32 classify_method(__u64 bytes_sent, __u64 bytes_recv)
{
    if (bytes_sent > CLASSIFY_MIN_BYTES && bytes_sent > 4 * bytes_recv)
        return METHOD_PUT;
    if (bytes_recv > CLASSIFY_MIN_BYTES && bytes_recv > 4 * bytes_sent)
        return METHOD_GET;
    return METHOD_OTHER;
}

// Finalize a completed request: classify by byte ratio, then record all
// metrics (request count, latency, bytes, histogram) into the appropriate
// per-method stats bucket.  Called from tcp_sendmsg when it detects a
// previous request on the same socket, or could be called on socket close.
static __always_inline void finalize_request(struct active_request *req)
{
    // Must have received something to be a completed request
    if (req->recv_time_ns == 0)
        return;

    __u64 latency_ns = req->recv_time_ns - req->send_time_ns;
    __u32 method = classify_method(req->total_bytes_sent,
                                   req->total_bytes_recv);

    struct stats_key skey = {};
    skey.dest_ip = req->dest_ip;
    skey.method  = method;

    struct latency_stats *stats =
        bpf_map_lookup_elem(&objstore_latency_by_ip, &skey);
    if (stats) {
        __sync_fetch_and_add(&stats->request_count, 1);
        __sync_fetch_and_add(&stats->total_latency_ns, latency_ns);
        __sync_fetch_and_add(&stats->bytes_sent, req->total_bytes_sent);
        __sync_fetch_and_add(&stats->bytes_recv, req->total_bytes_recv);
        __sync_fetch_and_add(&stats->retransmit_count, req->retransmit_count);
        update_objstore_histogram(stats->histogram, latency_ns);
    } else {
        struct latency_stats new_stats = {};
        new_stats.request_count = 1;
        new_stats.total_latency_ns = latency_ns;
        new_stats.bytes_sent = req->total_bytes_sent;
        new_stats.bytes_recv = req->total_bytes_recv;
        new_stats.retransmit_count = req->retransmit_count;
        update_objstore_histogram(new_stats.histogram, latency_ns);
        bpf_map_update_elem(&objstore_latency_by_ip, &skey,
                            &new_stats, BPF_NOEXIST);
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
    __u64 sk_key = (__u64)sk;

    // Look up existing active_request for this socket.
    struct active_request *existing =
        bpf_map_lookup_elem(&active_requests, &sk_key);
    if (existing) {
        if (existing->recv_time_ns != 0) {
            // Previous request has received data and now a new send
            // is starting -- finalize the previous request's metrics.
            finalize_request(existing);
            // Replace with a new request entry.
            struct active_request req = {};
            req.send_time_ns     = bpf_ktime_get_ns();
            req.dest_ip          = dest_ip;
            req.total_bytes_sent = size;
            bpf_map_update_elem(&active_requests, &sk_key,
                                &req, BPF_ANY);
        } else {
            // Still uploading (no recv yet) -- accumulate bytes.
            __sync_fetch_and_add(&existing->total_bytes_sent, size);
        }
        return 0;
    }

    // New request on this socket -- record timestamp and first send size.
    struct active_request req = {};
    req.send_time_ns     = bpf_ktime_get_ns();
    req.dest_ip          = dest_ip;
    req.total_bytes_sent = size;

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

    // Look up the active request for this socket and accumulate recv bytes.
    // We do NOT finalize here -- that happens on the next tcp_sendmsg,
    // which signals the start of a new HTTP request.
    __u64 sk_key = (__u64)sk;
    struct active_request *req =
        bpf_map_lookup_elem(&active_requests, &sk_key);
    if (!req)
        return 0;

    __sync_fetch_and_add(&req->total_bytes_recv, (__u64)copied);
    // Always update recv_time_ns to the latest receive timestamp.
    // Use a direct write (not atomic) since only one CPU handles
    // a given socket's receive path at a time.
    req->recv_time_ns = bpf_ktime_get_ns();
    return 0;
}

// tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
//
// Fires on every TCP retransmission.  We accumulate retransmits in the
// active request so they get attributed to the correct operation
// (PUT/GET/OTHER) when the request is finalized.
SEC("kprobe/tcp_retransmit_skb")
int tcp_retransmit_entry(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    __u64 sk_key = (__u64)sk;
    struct active_request *req =
        bpf_map_lookup_elem(&active_requests, &sk_key);
    if (!req)
        return 0;

    __sync_fetch_and_add(&req->retransmit_count, 1);
    return 0;
}

