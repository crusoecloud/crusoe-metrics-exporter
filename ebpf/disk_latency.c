// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Crusoe Energy */
//
// Disk I/O latency probe.  One BTF tracepoint at request completion
// (block_rq_complete) reads the request's own start timestamp, so nothing
// is recorded at issue time and there is no in-flight map.
//
// Why: the previous design inserted every block request into a preallocated
// hash map at blk_mq_start_request and deleted it at blk_mq_end_request.  On
// VMs with many vCPUs the map's per-CPU free lists ran dry and every insert
// walked all CPUs' lists under spinlocks, cutting 4 KiB random IOPS by up to
// 80% (and ~10% when healthy) on local NVMe that this collector never
// reports.  Here, only virtio disks are counted (the Go side reports vd*
// only), and per-device stats are per-CPU, so the I/O path takes no locks
// and does no cross-CPU writes.
//
// Latency start point, per request:
//   io_start_time_ns  issue to the device; set by blk_mq_start_request only
//                     when the queue has block-layer stats enabled
//                     (QUEUE_FLAG_STATS).  Same start point as before.
//   start_time_ns     request allocation; set whenever iostats is on (the
//                     default).  Includes time queued in the block layer.
// The first non-zero one is used; completions timed from allocation are
// counted separately so the difference is visible.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "disk_latency.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Block layer constants
#define REQ_OP_MASK  0xff
#define REQ_OP_READ  0
#define REQ_OP_WRITE 1

// Major number of virtio-blk, set by the Go loader from /proc/devices before
// load (it is allocated at boot, not fixed).  0 = not set: count every device.
const volatile __u32 vd_major = 0;

// -----------------------------------------------------------------------
// Structures
// -----------------------------------------------------------------------

// Disk latency statistics structure -- must match Go collector's value struct
struct disk_latency_stats {
    __u64 read_count;
    __u64 write_count;
    __u64 read_bytes;
    __u64 write_bytes;
    __u64 read_latency_ns;
    __u64 write_latency_ns;
    __u64 read_histogram[DISK_HISTOGRAM_BUCKETS];
    __u64 write_histogram[DISK_HISTOGRAM_BUCKETS];
    __u64 read_error_count;   // I/O errors for reads
    __u64 write_error_count;  // I/O errors for writes
    __u64 alloc_ts_count;     // completions timed from allocation (no dispatch timestamp)
};

// -----------------------------------------------------------------------
// Maps
// -----------------------------------------------------------------------

// Per-device I/O statistics consumed by the Go collector.  Per-CPU: each CPU
// updates its own copy without atomics; the collector sums them at scrape.
// An element is created once per device, not per I/O.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);  // device_id = (major << 8) | (minor & 0xFF)
    __type(value, struct disk_latency_stats);
} disk_io_stats SEC(".maps");

// -----------------------------------------------------------------------
// Helpers functions
// -----------------------------------------------------------------------

// Histogram bucket assignment -- 20 exponential buckets matching
// Go-side CalculateDiskPercentiles boundaries.
static __always_inline int disk_histogram_bucket(__u64 latency_ns)
{
    __u64 latency_us = latency_ns / 1000;

    if (latency_us < 10)    return 0;   // < 10us
    if (latency_us < 14)    return 1;   // 10-14us
    if (latency_us < 21)    return 2;   // 14-21us
    if (latency_us < 30)    return 3;   // 21-30us
    if (latency_us < 43)    return 4;   // 30-43us
    if (latency_us < 62)    return 5;   // 43-62us
    if (latency_us < 89)    return 6;   // 62-89us
    if (latency_us < 127)   return 7;   // 89-127us
    if (latency_us < 183)   return 8;   // 127-183us
    if (latency_us < 264)   return 9;   // 183-264us
    if (latency_us < 379)   return 10;  // 264-379us
    if (latency_us < 546)   return 11;  // 379-546us
    if (latency_us < 785)   return 12;  // 546-785us
    if (latency_us < 1129)  return 13;  // 785us-1.13ms
    if (latency_us < 1624)  return 14;  // 1.13-1.62ms
    if (latency_us < 2336)  return 15;  // 1.62-2.34ms
    if (latency_us < 3360)  return 16;  // 2.34-3.36ms
    if (latency_us < 4833)  return 17;  // 3.36-4.83ms
    if (latency_us < 6952)  return 18;  // 4.83-6.95ms
    return 19;                          // >= 6.95ms
}

// Extract device ID matching the Go collector's encoding: (major << 8) | (minor & 0xFF)
static __always_inline __u32 get_device_id(struct request *rq)
{
    // Try the 5.18+ path first: rq->part->bd_dev
    struct block_device *part = BPF_CORE_READ(rq, part);
    if (part) {
        unsigned int bd_dev = BPF_CORE_READ(part, bd_dev);
        // bd_dev encodes MAJOR(dev) and MINOR(dev) as kernel dev_t
        // MAJOR = bd_dev >> 20, MINOR = bd_dev & 0xFFFFF on modern kernels
        // But Go uses (major << 8) | (minor & 0xFF)
        __u32 major = bd_dev >> 20;
        __u32 minor = bd_dev & 0xFFFFF;
        return (major << 8) | (minor & 0xFF);
    }

    // Fallback for pre-5.18: rq->rq_disk (only if field exists)
    if (bpf_core_field_exists(rq->rq_disk)) {
        struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
        if (disk) {
            int major = BPF_CORE_READ(disk, major);
            int first_minor = BPF_CORE_READ(disk, first_minor);
            return ((__u32)major << 8) | ((__u32)first_minor & 0xFF);
        }
    }

    return 0;
}

// -----------------------------------------------------------------------
// Probe
// -----------------------------------------------------------------------

// block_rq_complete fires from blk_update_request, which both
// blk_mq_end_request and the batched blk_mq_end_request_batch path reach, so
// batched completions (kernel 5.16+) are counted too.  It can fire more than
// once per request on partial completions; only the final one is counted.
// Signature: (struct request *rq, blk_status_t error, unsigned int nr_bytes);
// blk_status_t is a u8, 0 = success.
SEC("tp_btf/block_rq_complete")
int BPF_PROG(io_done, struct request *rq, int error, unsigned int nr_bytes)
{
    if (!rq)
        return 0;

    // partial completion: bytes remain after this one
    if (nr_bytes < BPF_CORE_READ(rq, __data_len))
        return 0;

    __u32 dev_id = get_device_id(rq);
    if (dev_id == 0)
        return 0;
    if (vd_major && (dev_id >> 8) != vd_major)
        return 0;   // not a virtio disk: the collector doesn't report it

    unsigned int op = BPF_CORE_READ(rq, cmd_flags) & REQ_OP_MASK;
    if (op != REQ_OP_READ && op != REQ_OP_WRITE)
        return 0;

    __u64 start = BPF_CORE_READ(rq, io_start_time_ns);
    int from_alloc = 0;
    if (!start) {
        start = BPF_CORE_READ(rq, start_time_ns);
        from_alloc = 1;
    }
    __u64 now = bpf_ktime_get_ns();
    if (!start || start > now)
        return 0;
    __u64 latency_ns = now - start;

    struct disk_latency_stats *stats = bpf_map_lookup_elem(&disk_io_stats, &dev_id);
    if (!stats) {
        // first I/O on this device: create its (per-CPU) element once
        struct disk_latency_stats zero = {};
        bpf_map_update_elem(&disk_io_stats, &dev_id, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&disk_io_stats, &dev_id);
        if (!stats)
            return 0;
    }

    // per-CPU value: plain increments, no atomics
    int bucket = disk_histogram_bucket(latency_ns);
    if (op == REQ_OP_WRITE) {
        stats->write_count++;
        stats->write_bytes += nr_bytes;
        stats->write_latency_ns += latency_ns;
        if (bucket >= 0 && bucket < DISK_HISTOGRAM_BUCKETS)
            stats->write_histogram[bucket]++;
        if (error)
            stats->write_error_count++;
    } else {
        stats->read_count++;
        stats->read_bytes += nr_bytes;
        stats->read_latency_ns += latency_ns;
        if (bucket >= 0 && bucket < DISK_HISTOGRAM_BUCKETS)
            stats->read_histogram[bucket]++;
        if (error)
            stats->read_error_count++;
    }
    if (from_alloc)
        stats->alloc_ts_count++;
    return 0;
}
