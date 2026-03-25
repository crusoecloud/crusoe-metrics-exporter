// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Crusoe Energy */
//
// Disk I/O latency probe.  Measures real elapsed time between when a
// block I/O request is issued to the device (blk_mq_start_request) and
// when it completes (blk_mq_end_request).  Extracts device ID, data
// length, and read/write flag from struct request.

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

// VIRTIO disk major number (252 = virtblk)
#define VIRTIO_BLK_MAJOR 252

// -----------------------------------------------------------------------
// Structures
// -----------------------------------------------------------------------

// In-flight I/O request tracking
struct inflight_io {
    __u64 start_time_ns;
    __u32 device_id;
    __u32 data_len;
    __u32 is_write;
    __u32 _pad;
};

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
};

// -----------------------------------------------------------------------
// Maps
// -----------------------------------------------------------------------

// Per-device I/O statistics consumed by the Go collector.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256); // should never have more than 256 nvme-tcp devices ?
    __type(key, __u32);  // device_id = (major << 8) | (minor & 0xFF)
    __type(value, struct disk_latency_stats);
} disk_io_stats SEC(".maps");

// In-flight I/O requests.  Key = struct request pointer.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct inflight_io);
} active_disk_requests SEC(".maps");

// -----------------------------------------------------------------------
// Helpers functions
// -----------------------------------------------------------------------

// Histogram bucket assignment -- 20 exponential buckets matching
// Go-side CalculateDiskPercentiles boundaries.
static __always_inline void update_disk_histogram(__u64 *histogram,
                                                   __u64 latency_ns)
{
    __u64 latency_us = latency_ns / 1000;

    int bucket;
    if (latency_us < 10)              bucket = 0;   // < 10us
    else if (latency_us < 14)         bucket = 1;   // 10-14us
    else if (latency_us < 21)         bucket = 2;   // 14-21us
    else if (latency_us < 30)         bucket = 3;   // 21-30us
    else if (latency_us < 43)         bucket = 4;   // 30-43us
    else if (latency_us < 62)         bucket = 5;   // 43-62us
    else if (latency_us < 89)         bucket = 6;   // 62-89us
    else if (latency_us < 127)        bucket = 7;   // 89-127us
    else if (latency_us < 183)        bucket = 8;   // 127-183us
    else if (latency_us < 264)        bucket = 9;   // 183-264us
    else if (latency_us < 379)        bucket = 10;  // 264-379us
    else if (latency_us < 546)        bucket = 11;  // 379-546us
    else if (latency_us < 785)        bucket = 12;  // 546-785us
    else if (latency_us < 1129)       bucket = 13;  // 785us-1.13ms
    else if (latency_us < 1624)       bucket = 14;  // 1.13-1.62ms
    else if (latency_us < 2336)       bucket = 15;  // 1.62-2.34ms
    else if (latency_us < 3360)       bucket = 16;  // 2.34-3.36ms
    else if (latency_us < 4833)       bucket = 17;  // 3.36-4.83ms
    else if (latency_us < 6952)       bucket = 18;  // 4.83-6.95ms
    else                              bucket = 19;  // >= 6.95ms

    if (bucket < DISK_HISTOGRAM_BUCKETS)
        __sync_fetch_and_add(&histogram[bucket], 1);
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

    // Fallback for pre-5.18: rq->rq_disk
    struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
    if (disk) {
        int major = BPF_CORE_READ(disk, major);
        int first_minor = BPF_CORE_READ(disk, first_minor);
        return ((__u32)major << 8) | ((__u32)first_minor & 0xFF);
    }

    return 0;
}

// Record a completed I/O operation in the stats map.
// error == 0 means success, non-zero means I/O error (blk_status_t).
static __always_inline void record_io(struct inflight_io *io, __u64 latency_ns, __u8 error)
{
    __u32 dev_id = io->device_id;

    struct disk_latency_stats *stats =
        bpf_map_lookup_elem(&disk_io_stats, &dev_id);

    if (stats) {
        if (io->is_write) {
            __sync_fetch_and_add(&stats->write_count, 1);
            __sync_fetch_and_add(&stats->write_bytes, io->data_len);
            __sync_fetch_and_add(&stats->write_latency_ns, latency_ns);
            update_disk_histogram(stats->write_histogram, latency_ns);
            if (error != 0)
                __sync_fetch_and_add(&stats->write_error_count, 1);
        } else {
            __sync_fetch_and_add(&stats->read_count, 1);
            __sync_fetch_and_add(&stats->read_bytes, io->data_len);
            __sync_fetch_and_add(&stats->read_latency_ns, latency_ns);
            update_disk_histogram(stats->read_histogram, latency_ns);
            if (error != 0)
                __sync_fetch_and_add(&stats->read_error_count, 1);
        }
    } else {
        struct disk_latency_stats new_stats = {};
        if (io->is_write) {
            new_stats.write_count = 1;
            new_stats.write_bytes = io->data_len;
            new_stats.write_latency_ns = latency_ns;
            update_disk_histogram(new_stats.write_histogram, latency_ns);
            if (error != 0)
                new_stats.write_error_count = 1;
        } else {
            new_stats.read_count = 1;
            new_stats.read_bytes = io->data_len;
            new_stats.read_latency_ns = latency_ns;
            update_disk_histogram(new_stats.read_histogram, latency_ns);
            if (error != 0)
                new_stats.read_error_count = 1;
        }
        bpf_map_update_elem(&disk_io_stats, &dev_id, &new_stats, BPF_NOEXIST);
    }
}

// -----------------------------------------------------------------------
// Probes
// -----------------------------------------------------------------------

// blk_mq_start_request -- called when a block I/O request is dispatched
// to the device driver.  We record the start timestamp and request metadata.
SEC("kprobe/blk_mq_start_request")
int io_start(struct pt_regs *ctx)
{
    struct request *rq = (struct request *)PT_REGS_PARM1(ctx);
    if (!rq)
        return 0;

    __u32 dev_id = get_device_id(rq);
    if (dev_id == 0)
        return 0;

    unsigned int cmd_flags = BPF_CORE_READ(rq, cmd_flags);
    unsigned int op = cmd_flags & REQ_OP_MASK;

    // Only track reads and writes
    if (op != REQ_OP_READ && op != REQ_OP_WRITE)
        return 0;

    struct inflight_io io = {};
    io.start_time_ns = bpf_ktime_get_ns();
    io.device_id     = dev_id;
    io.data_len      = BPF_CORE_READ(rq, __data_len);
    io.is_write      = (op == REQ_OP_WRITE) ? 1 : 0;

    __u64 rq_key = (__u64)rq;
    bpf_map_update_elem(&active_disk_requests, &rq_key, &io, BPF_ANY);
    return 0;
}

// blk_mq_end_request -- called when a block I/O request completes.
// We look up the matching start record, compute latency, and update stats.
// Signature: void blk_mq_end_request(struct request *rq, blk_status_t error)
// blk_status_t is an unsigned char (u8): 0 = BLK_STS_OK (success), non-zero = error.
SEC("kprobe/blk_mq_end_request")
int io_done(struct pt_regs *ctx)
{
    struct request *rq = (struct request *)PT_REGS_PARM1(ctx);
    if (!rq)
        return 0;

    // Capture the error status (second parameter)
    // blk_status_t is u8, but passed as unsigned long in registers
    __u8 error = (__u8)PT_REGS_PARM2(ctx);

    __u64 rq_key = (__u64)rq;
    struct inflight_io *io =
        bpf_map_lookup_elem(&active_disk_requests, &rq_key);
    if (!io)
        return 0;

    __u64 end_time = bpf_ktime_get_ns();
    __u64 latency_ns = end_time - io->start_time_ns;

    record_io(io, latency_ns, error);

    bpf_map_delete_elem(&active_disk_requests, &rq_key);
    return 0;
}
