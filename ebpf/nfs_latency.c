// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Crusoe Energy */
//
// NFS latency probe.  Measures real elapsed time between an outbound
// tcp_sendmsg and the next inbound tcp_recvmsg on the *same* socket,
// provided the socket's destination IP is present in the nfs_server_ips
// map AND the destination port matches the configured target port
// (typically 2049).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "nfs_latency.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// -----------------------------------------------------------------------
// Structures
// -----------------------------------------------------------------------

// Configuration structure expected by Go collector
struct config {
    __u16 target_port;  // host byte order; converted to network order in probe
    __u16 padding;
};

// Track in-flight requests per socket
struct active_request {
    __u64 send_time_ns;
    __u32 dest_ip;
};

// NFS latency statistics structure
// Histogram buckets must match Go-side CalculatePercentiles boundaries:
struct nfs_latency_stats {
    __u64 request_count;
    __u64 total_latency_ns;
    __u64 histogram[HISTOGRAM_BUCKETS];
    __u64 retransmit_count;
};

// -----------------------------------------------------------------------
// Maps
// -----------------------------------------------------------------------

// Config map -- Go collector writes the target port (2049) here.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

// Per-IP latency stats consumed by the Go collector.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct nfs_latency_stats);
} nfs_latency_by_ip SEC(".maps");

// NFS server IPs -- populated by the Go collector from /proc/mounts.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} nfs_server_ips SEC(".maps");

// In-flight request tracking.  Key = socket pointer cast to __u64.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct active_request);
} active_requests SEC(".maps");

// recvmsg_sock_map kept for backward compatibility with Go loader but unused.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u64);
    __type(value, __u64);
} recvmsg_sock_map SEC(".maps");

// Debug counters for tracing code paths (handy when you have no idea what's going on)
// Index 0: tcp_sendmsg_entry called
// Index 1: tcp_sendmsg passed AF_INET check
// Index 2: tcp_sendmsg passed port check
// Index 3: tcp_sendmsg passed is_nfs_server check (added to active_requests)
// Index 4: tcp_recvmsg_entry called
// Index 5: tcp_recvmsg_entry found active_request match
// Index 6: record_latency called
// Index 7: record_latency existing stats path
// Index 8: record_latency new stats path
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} nfs_debug_counters SEC(".maps");

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// Increment a debug counter if EBPF_DEBUG > 0 (set in Makefile)
static __always_inline void debug_inc(__u32 idx)
{
    #if EBPF_DEBUG > 0
    __u64 *val = bpf_map_lookup_elem(&nfs_debug_counters, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
    #endif
}

// Check whether dest_ip is one of the known NFS server IPs
static __always_inline bool is_nfs_server(__u32 dest_ip)
{
    for (__u32 i = 0; i < 64; i++) {
        __u32 idx = i;
        __u32 *ip = bpf_map_lookup_elem(&nfs_server_ips, &idx);
        if (!ip || *ip == 0)
            break;
        if (*ip == dest_ip)
            return true;
    }
    return false;
}

// Histogram bucket assignment -- 20 buckets must match Go-side boundaries.
static __always_inline void update_nfs_histogram(__u64 *histogram,
                                                  __u64 latency_ns)
{
    __u64 latency_us = latency_ns / 1000;  // convert to microseconds

    int bucket;
    if (latency_us < 500)             bucket = 0;   // < 0.50ms
    else if (latency_us < 637)        bucket = 1;   // 0.50-0.64ms
    else if (latency_us < 812)        bucket = 2;   // 0.64-0.81ms
    else if (latency_us < 1035)       bucket = 3;   // 0.81-1.04ms
    else if (latency_us < 1318)       bucket = 4;   // 1.04-1.32ms
    else if (latency_us < 1680)       bucket = 5;   // 1.32-1.68ms
    else if (latency_us < 2141)       bucket = 6;   // 1.68-2.14ms
    else if (latency_us < 2728)       bucket = 7;   // 2.14-2.73ms
    else if (latency_us < 3476)       bucket = 8;   // 2.73-3.48ms
    else if (latency_us < 4429)       bucket = 9;   // 3.48-4.43ms
    else if (latency_us < 5644)       bucket = 10;  // 4.43-5.64ms
    else if (latency_us < 7192)       bucket = 11;  // 5.64-7.19ms
    else if (latency_us < 9165)       bucket = 12;  // 7.19-9.17ms
    else if (latency_us < 11679)      bucket = 13;  // 9.17-11.68ms
    else if (latency_us < 14882)      bucket = 14;  // 11.68-14.88ms
    else if (latency_us < 18963)      bucket = 15;  // 14.88-18.96ms
    else if (latency_us < 24165)      bucket = 16;  // 18.96-24.17ms
    else if (latency_us < 30792)      bucket = 17;  // 24.17-30.79ms
    else if (latency_us < 39238)      bucket = 18;  // 30.79-39.24ms
    else                              bucket = 19;  // >= 39.24ms

    if (bucket < HISTOGRAM_BUCKETS)
        __sync_fetch_and_add(&histogram[bucket], 1);
}

// Record a measured latency sample for the given destination IP.
static __always_inline void record_latency(__u32 dest_ip, __u64 latency_ns)
{
    #if EBPF_DEBUG > 0
    debug_inc(6);  // record_latency called
    #endif
    struct nfs_latency_stats *stats =
        bpf_map_lookup_elem(&nfs_latency_by_ip, &dest_ip);
    if (stats) {
        #if EBPF_DEBUG > 0
        debug_inc(7);  // existing stats path
        #endif
        __sync_fetch_and_add(&stats->request_count, 1);
        __sync_fetch_and_add(&stats->total_latency_ns, latency_ns);
        update_nfs_histogram(stats->histogram, latency_ns);
    } else {
        #if EBPF_DEBUG > 0
        debug_inc(8);  // new stats path
        #endif
        struct nfs_latency_stats new_stats = {};
        new_stats.request_count = 1;
        new_stats.total_latency_ns = latency_ns;
        update_nfs_histogram(new_stats.histogram, latency_ns);
        bpf_map_update_elem(&nfs_latency_by_ip, &dest_ip,
                            &new_stats, BPF_ANY);
    }
}

// -----------------------------------------------------------------------
// Probes
// -----------------------------------------------------------------------

// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
//
// On every outbound TCP send we check whether the socket targets a known
// NFS server IP on the configured port.  If so we record a timestamp
// keyed by the socket pointer so we can pair it with the next receive.
SEC("kprobe/tcp_sendmsg")
int tcp_sendmsg_entry(struct pt_regs *ctx)
{
    #if EBPF_DEBUG > 0
    debug_inc(0);  // tcp_sendmsg_entry called
    #endif

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    // Only handle AF_INET (IPv4)
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    #if EBPF_DEBUG > 0
    debug_inc(1);  // passed AF_INET check
    #endif

    __u32 dest_ip   = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dest_port = BPF_CORE_READ(sk, __sk_common.skc_dport);

    // Check target port from config (port stored as host order, kernel has network order)
    __u32 cfg_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (cfg) {
        __u16 target_port_net = bpf_htons(cfg->target_port);
        if (dest_port != target_port_net)
            return 0;
    }

    #if EBPF_DEBUG > 0
    debug_inc(2);  // passed port check
    #endif

    // Check if this destination is a known NFS server
    if (!is_nfs_server(dest_ip))
        return 0;

    #if EBPF_DEBUG > 0
    debug_inc(3);  // passed is_nfs_server check
    #endif

    // Record the send timestamp keyed by the socket pointer
    __u64 sk_key = (__u64)sk;
    struct active_request req = {};
    req.send_time_ns = bpf_ktime_get_ns();
    req.dest_ip      = dest_ip;

    bpf_map_update_elem(&active_requests, &sk_key, &req, BPF_ANY);
    return 0;
}

// tcp_recvmsg entry -- look up the socket in active_requests and compute
// latency immediately.  We do this in the entry probe because we already
// have the sock pointer (first arg) and don't need the return value.
// This avoids the pid_tgid mismatch problem where NFS sends and receives
// happen on different threads (especially with nconnect>1).
SEC("kprobe/tcp_recvmsg")
int tcp_recvmsg_entry(struct pt_regs *ctx)
{
    #if EBPF_DEBUG > 0
    debug_inc(4);  // tcp_recvmsg_entry called
    #endif

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 sk_key = (__u64)sk;

    // Look up the matching send-side timestamp for this socket
    struct active_request *req =
        bpf_map_lookup_elem(&active_requests, &sk_key);
    if (!req)
        return 0;

    #if EBPF_DEBUG > 0
    debug_inc(5);  // found active_request match
    #endif

    __u64 recv_time = bpf_ktime_get_ns();
    __u64 latency_ns = recv_time - req->send_time_ns;

    // Sanity check: ignore negative or impossibly large latencies (>60s)
    if (latency_ns > 60000000000ULL)
        latency_ns = 60000000000ULL;

    // Record real measured latency
    record_latency(req->dest_ip, latency_ns);

    // Remove the active request so we measure one round-trip per send
    bpf_map_delete_elem(&active_requests, &sk_key);
    return 0;
}

// kretprobe for tcp_recvmsg -- kept as no-op for Go loader compatibility.
SEC("kretprobe/tcp_recvmsg")
int tcp_recvmsg_exit(struct pt_regs *ctx)
{
    return 0;
}

// tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
//
// Fires on every TCP retransmission.  We check if the socket targets a
// known NFS server IP and increment the per-IP retransmit counter.
SEC("kprobe/tcp_retransmit_skb")
int tcp_retransmit_entry(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    __u32 dest_ip  = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 dest_port = BPF_CORE_READ(sk, __sk_common.skc_dport);

    // Check target port from config (must match NFS port, typically 2049)
    __u32 cfg_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (cfg) {
        __u16 target_port_net = bpf_htons(cfg->target_port);
        if (dest_port != target_port_net)
            return 0;
    }

    if (!is_nfs_server(dest_ip))
        return 0;

    struct nfs_latency_stats *stats =
        bpf_map_lookup_elem(&nfs_latency_by_ip, &dest_ip);
    if (stats) {
        __sync_fetch_and_add(&stats->retransmit_count, 1);
    } else {
        struct nfs_latency_stats new_stats = {};
        new_stats.retransmit_count = 1;
        bpf_map_update_elem(&nfs_latency_by_ip, &dest_ip,
                            &new_stats, BPF_ANY);
    }
    return 0;
}

// UDP sendmsg entry -- placeholder for NFS-over-UDP support.
// Currently a no-op; NFS v4 uses TCP exclusively.
SEC("kprobe/udp_sendmsg")
int nfs_udp_sendmsg_entry(struct pt_regs *ctx)
{
    return 0;
}
