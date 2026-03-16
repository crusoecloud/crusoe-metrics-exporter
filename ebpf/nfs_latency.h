#ifndef __NFS_LATENCY_H__
#define __NFS_LATENCY_H__

// Note: When using vmlinux.h, we must NOT include kernel headers like <linux/types.h>
// vmlinux.h already contains all kernel type definitions

// Histogram bucket count for latency tracking
#define HISTOGRAM_BUCKETS 20

// NFS operation types
// Unclear if we want to export per-op types or just total latency
#define NFS_OP_READ    0
#define NFS_OP_WRITE   1
#define NFS_OP_GETATTR 2
#define NFS_OP_SETATTR 3
#define NFS_OP_LOOKUP  4
#define NFS_OP_CREATE  5
#define NFS_OP_REMOVE  6
#define NFS_OP_OTHER   99


#endif /* __NFS_LATENCY_H__ */
