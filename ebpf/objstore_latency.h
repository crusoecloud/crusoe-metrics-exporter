#ifndef __OBJSTORE_LATENCY_H__
#define __OBJSTORE_LATENCY_H__

// Note: When using vmlinux.h, we must NOT include kernel headers like <linux/types.h>
// vmlinux.h already contains all kernel type definitions

// Histogram bucket count for latency tracking
#define HISTOGRAM_BUCKETS 20


// Helper function prototypes (implemented in the eBPF program)
static __always_inline int is_tcp_connection(struct sock *sk);
static __always_inline __u32 get_dest_ip(struct sock *sk);
static __always_inline void update_histogram(__u64 *histogram, __u64 latency_ns);

#endif // __OBJSTORE_LATENCY_H__
