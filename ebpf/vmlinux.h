// vmlinux.h for BPF CO-RE
// Contains kernel types needed for tcp_latency.c
//
// For production: This should ideally be generated from target kernel using:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//
// This version includes the minimal set of types needed for BPF_KPROBE/BPF_KRETPROBE macros

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

// Basic types
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;

typedef __u64 __kernel_size_t;
typedef unsigned int __wsum;

typedef _Bool bool;
#define true 1
#define false 0
// BPF map types
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define AF_INET 2


// pt_regs: Architecture-specific register state for x86_64
// Required by BPF_KPROBE and BPF_KRETPROBE macros
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

// Socket family
#define AF_INET 2

// sock_common: Common socket structure fields
struct sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };
    short unsigned int skc_family;
};

// sock: Full socket structure
struct sock {
    struct sock_common __sk_common;
};

// -----------------------------------------------------------------------
// Block layer types needed by disk_latency.c
// -----------------------------------------------------------------------

// gendisk: Generic disk structure
struct gendisk {
    int major;
    int first_minor;
    // remaining fields omitted -- BPF CO-RE handles the actual layout
};

// request_queue: Block device request queue
struct request_queue {
    // We only need it as a pointer target; no fields accessed directly
};

// block_device: Block device
struct block_device {
    unsigned int bd_dev;
    // remaining fields omitted
};

// request: Block I/O request structure
// Fields accessed by our eBPF program via BPF_CORE_READ.
struct request {
    struct request_queue *q;
    struct gendisk *rq_disk;       // pre-5.18 kernels
    struct block_device *part;     // 5.18+ kernels (replaces rq_disk)
    unsigned int cmd_flags;
    unsigned int __data_len;
    __u64 __sector;                // sector offset
};

#pragma clang attribute pop

#endif // __VMLINUX_H__
