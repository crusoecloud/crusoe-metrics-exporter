# Crusoe Metrics Exporter -- Design Document

## Overview

The Crusoe Metrics Exporter is a Prometheus-compatible agent that runs inside every Crusoe VM to measure the real-world performance of storage and network I/O as experienced by the guest operating system. It uses eBPF kernel probes to capture latency, throughput, and error metrics for three subsystems -- local disk, NFS, and S3-compatible object storage -- and exports them as Prometheus metrics for scraping by the platform's monitoring infrastructure.

The exporter is deployed as a sidecar container within a Kubernetes DaemonSet (`crusoe-watch-agent`), running with elevated privileges (`CAP_BPF`, `CAP_PERFMON`) to attach eBPF programs to kernel functions.

---

## Why eBPF?

### The view from inside the VM matters

Cloud platform operators typically monitor infrastructure from the hypervisor or control plane: queue depths on storage backends, network switch counters, NFS server IOPS. These metrics tell you how the infrastructure is performing in aggregate but say nothing about what an individual VM actually experiences.

A customer's application sees latency that is the sum of many components: guest kernel scheduling, virtio ring processing, host-side I/O dispatch, network transit, storage backend processing, and the return path. Any of these can introduce jitter, queuing delays, or outright stalls that are invisible from the infrastructure side. The only place to measure true end-to-end latency as the application perceives it is inside the VM itself.

### Why not just use application-level metrics?

Application-level instrumentation (e.g., S3 SDK timers) measures what the application sees, but it conflates client-side processing with actual I/O latency. It also requires cooperation from every application, which is impractical on a multi-tenant platform where customers run arbitrary workloads.

eBPF probes sit at the kernel boundary -- below the application but above the hardware -- capturing every I/O operation regardless of which process initiated it, which language it was written in, or whether the application has any instrumentation at all. This gives a universal, zero-configuration view of I/O performance.

### Why not just read /proc?

Linux exposes some I/O statistics through procfs:

- `/proc/diskstats` provides per-device read/write counts and cumulative time
- `/proc/1/mountstats` provides per-mount NFS RPC counts, RTT, and execution time

The exporter does parse both of these (via the Disk Stats and NFS Stats collectors), but they have significant limitations:

1. **No latency distribution.** Both `diskstats` and `mountstats` report only cumulative totals (total operations, total time). Dividing one by the other gives you the mean, but the mean is a poor summary of latency. A system averaging 2ms per NFS RPC might have 99% of requests completing in 0.5ms and 1% taking 150ms -- a pattern that is invisible in the average but devastating to tail-latency-sensitive workloads.

2. **No per-request granularity.** `mountstats` reports `rtt` and `exe` as cumulative microsecond counters across all RPCs of a given type. There is no way to reconstruct the distribution of individual request latencies from these counters. You cannot compute percentiles, detect bimodal distributions, or identify outlier events.

3. **No object store coverage.** There is no `/proc` interface for S3/object-store traffic. Object store access is just HTTPS over TCP from the kernel's perspective -- there are no filesystem-level statistics to read.

4. **Coarse time resolution.** `mountstats` updates are not atomic and can race with concurrent I/O, leading to brief inconsistencies between counters. eBPF measurements are taken at precise kernel function entry/exit points with nanosecond timestamps.

5. **No retransmit attribution.** `/proc/net/snmp` gives system-wide TCP retransmit counts, but does not attribute them to specific destinations. The eBPF `tcp_retransmit_skb` probe tracks retransmits per destination IP, making it possible to distinguish between retransmits to an NFS server (which may indicate network issues on the storage path) and retransmits to unrelated destinations.

The exporter uses `mountstats` and `diskstats` as a complement -- they provide RPC-level detail (operation type, backlog, timeouts) that eBPF does not easily capture -- but the eBPF probes are the primary source for latency distribution and object store metrics.

---

## Why histograms?

### The problem with averages

Average (mean) latency is the most commonly reported storage performance metric and also the most misleading. Consider two storage systems:

- **System A:** Every request completes in exactly 5ms. Mean = 5ms.
- **System B:** 95% of requests complete in 1ms; 5% take 81ms. Mean = 5ms.

Both systems have the same average latency, but System B has a severe tail-latency problem that will cause periodic stalls in any application with serialized I/O dependencies. An SLA based on average latency would rate them as equivalent.

### What histograms reveal

A histogram records the count of observations that fall into each of a predefined set of buckets. The exporter uses 20 geometric (exponentially-spaced) buckets for each subsystem:

| Collector | Bucket range | Use case |
|-----------|-------------|----------|
| Disk I/O | 10us -- 10ms | Block device latency |
| NFS | 0.5ms -- 50ms | NFS RPC round-trip time |
| Object store | 1ms -- 1000ms | Full HTTP request duration (GET/PUT) |

Geometric spacing provides roughly equal resolution on a log scale, which matches the typical shape of latency distributions: most samples cluster near the mode, with a long right tail.

From a histogram, downstream systems can compute:

- **Percentiles (p50, p95, p99)** -- using `histogram_quantile()` in PromQL. These are far more useful for SLA enforcement than averages.
- **Distribution shape** -- bimodal distributions (e.g., cache hits vs. misses) show up as two peaks in the histogram, which are invisible in any single summary statistic.
- **Tail behavior** -- the fraction of requests exceeding a threshold (e.g., >10ms) is directly readable from the cumulative bucket counts.
- **Rate of change** -- because Prometheus histograms are cumulative counters, `rate()` over a histogram gives you the distribution of latency within a time window, not just since process start.

### Histogram implementation

Each eBPF program maintains a fixed-size array of 20 `uint64` counters in a BPF hash map. When a latency sample is recorded, the probe determines the appropriate bucket via a chain of if/else comparisons (no floating-point arithmetic is available in eBPF) and atomically increments that bucket's counter with `__sync_fetch_and_add`. The Go collector reads the array on each Prometheus scrape and converts it to a `prometheus.MustNewConstHistogram` with cumulative bucket counts and an approximate sum computed from bucket midpoints.

---

## Architecture

### Collector model

Each subsystem is implemented as an independent `prometheus.Collector`:

| Collector | Data source | Probe points |
|-----------|------------|--------------|
| Disk Latency | eBPF tracepoints | `block_rq_issue`, `block_rq_complete` |
| Disk Stats | `/proc/diskstats` | -- |
| NFS Latency | eBPF kprobes | `tcp_sendmsg`, `tcp_recvmsg`, `tcp_retransmit_skb` |
| NFS Stats | `/proc/1/mountstats` | -- |
| Object Store Latency | eBPF kprobes | `tcp_sendmsg`, `tcp_cleanup_rbuf`, `tcp_retransmit_skb` |

Collectors are registered at startup and fail independently. If the kernel lacks BTF support or the required BPF helpers, eBPF collectors log a warning and the exporter continues with only procfs-based collectors.

### eBPF program lifecycle

1. The eBPF C source (`ebpf/*.c`) is compiled to BPF bytecode (`.o`) using clang during the Docker build.
2. The compiled `.o` files are embedded into the Go binary via `go:embed`.
3. At startup, each Go collector loads its eBPF program using the `cilium/ebpf` library, which handles BTF relocation (CO-RE) for cross-kernel compatibility.
4. The collector populates configuration maps (target port, server IP filter list) and attaches kprobes/tracepoints.
5. On each Prometheus scrape, the collector iterates over the stats map, converts raw counters to Prometheus metrics, and emits them.
6. On shutdown, kprobes are detached and maps are closed.

### Filtering

All TCP-based eBPF programs filter traffic by destination IP and port to avoid measuring unrelated connections. The Go collector writes known server IPs into a BPF array map at startup (and refreshes periodically for NFS, as new mounts may appear). The eBPF probe checks every `tcp_sendmsg` against this filter map and ignores non-matching sockets.

---

## Object store latency: design challenges

Measuring object store latency presents unique challenges compared to NFS or block I/O, because the protocol (HTTP/HTTPS over TCP) was not designed with kernel-level observability in mind.

### Challenge 1: Identifying request boundaries

NFS uses a well-defined RPC protocol where each request and response is a discrete message. HTTP over TCP has no such framing at the kernel level -- the kernel sees a stream of `tcp_sendmsg` and `tcp_recvmsg` calls with no indication of where one HTTP request ends and the next begins.

The exporter solves this by tracking per-socket state in an `active_requests` BPF hash map, keyed by the socket pointer (`struct sock *`). The first `tcp_sendmsg` on a socket targeting a known object store IP creates an entry with a nanosecond timestamp. Subsequent sends on the same socket accumulate bytes. When `tcp_cleanup_rbuf` fires (indicating the server has sent data back), the receive bytes and timestamp are recorded. The request is considered complete when the next `tcp_sendmsg` arrives on the same socket, indicating a new HTTP request is starting. At that point, the previous request is finalized: latency is computed, bytes are tallied, and the histogram is updated.

This "finalize on next send" approach is necessary because a single HTTP response may arrive across multiple `tcp_cleanup_rbuf` calls (especially for large GET responses), and there is no kernel-level signal for "end of HTTP response." The tradeoff is that the very last request on a socket before it is closed will not be recorded, since there is no subsequent send to trigger finalization. With connection pooling and sustained traffic, this is negligible.

### Challenge 2: Classifying GET vs. PUT over HTTPS

Knowing whether a request is a read (GET) or a write (PUT) is essential for meaningful latency analysis -- PUTs and GETs have fundamentally different latency profiles (a 10MB PUT takes ~100ms; a 10MB GET has a time-to-first-byte of ~10ms but a full transfer time of ~500ms).

For plaintext HTTP, the request method (`GET`, `PUT`, etc.) is visible in the first bytes of the `tcp_sendmsg` payload. However, this approach fails completely for HTTPS: the payload is TLS ciphertext and cannot be inspected without the session keys.

Attempting to parse the plaintext HTTP method from the kernel also proved fragile across kernel versions. The `msghdr` structure's `msg_iter` field (which contains the pointer to the user-space send buffer) changed layout between kernel 5.15 and 6.x -- the field names `iov` vs. `__iov` and `type` vs. `iter_type` differ, breaking BPF CO-RE field relocation. This required kernel-version-specific offset arithmetic with `bpf_probe_read_kernel`, making the code complex and error-prone.

The exporter instead uses **TCP byte-ratio classification**, which works for both HTTP and HTTPS:

| Classification | Condition | Rationale |
|---------------|-----------|-----------|
| **PUT** | `bytes_sent > 4KB && bytes_sent > 4 * bytes_recv` | Client uploaded significantly more than it received |
| **GET** | `bytes_recv > 4KB && bytes_recv > 4 * bytes_sent` | Client downloaded significantly more than it sent |
| **OTHER** | Everything else | HEAD, DELETE, LIST, small objects, TLS handshakes |

This heuristic is applied at request finalization, after both the send and receive phases are complete and the total byte counts are known. The 4KB minimum threshold avoids misclassifying TLS handshake overhead or small metadata requests. The 4:1 ratio ensures clear asymmetry -- a PUT of any non-trivial object will send orders of magnitude more than it receives (the server response is typically a small `200 OK`).

This approach has several advantages over payload inspection:

- **Works with HTTPS** -- purely TCP-level, no payload access needed.
- **No kernel version dependencies** -- no `msghdr` or `iov_iter` struct access.
- **Simpler eBPF code** -- no `bpf_probe_read_user` or offset arithmetic.
- **Correct for all S3 client libraries** -- does not depend on HTTP request line format.

The limitation is that it cannot distinguish between specific "small" operations (HEAD vs. DELETE vs. LIST) -- these are grouped as OTHER. For storage performance monitoring, the primary interest is in GET and PUT latency for data-plane operations, so this is an acceptable tradeoff.

### Challenge 3: Measuring full request latency

The initial implementation recorded latency as the time from the first `tcp_sendmsg` to the first `tcp_cleanup_rbuf`. This worked well for GET requests (where the first received data is the beginning of the response) but significantly underestimated PUT latency.

For a 10MB PUT, the sequence is:

1. First `tcp_sendmsg` -- client begins uploading (timestamp T0)
2. Many more `tcp_sendmsg` calls -- client continues uploading over ~75ms
3. Server sends `100 Continue` or TCP ACKs -- triggers `tcp_cleanup_rbuf` at T0+20ms
4. Client finishes uploading at T0+80ms
5. Server sends `200 OK` response at T0+100ms

If latency is measured at step 3, the result is ~20ms -- the time from first send to first receive. But the actual request duration is ~100ms (T0 to T0+100ms).

The fix was to defer finalization. Instead of recording latency at `tcp_cleanup_rbuf` time, the probe accumulates both `total_bytes_sent` and `total_bytes_recv` in the per-socket `active_request` entry, updating `recv_time_ns` on each receive. Latency is computed as `recv_time_ns - send_time_ns` only when the request is finalized (on the next `tcp_sendmsg`), giving the full duration from first send to last receive.

---

## Deployment

The exporter runs as a container in the `crusoe-watch-agent` DaemonSet, alongside a log-forwarding sidecar. It requires:

- **Privileged mode** or `CAP_BPF` + `CAP_PERFMON` capabilities
- `/proc` mounted from the host at `/host/proc`
- `/sys` mounted for BTF access (`/sys/kernel/btf/vmlinux`)
- Environment variables for object store endpoint IPs and ports

The exporter listens on port 9500 and exposes `/metrics` (Prometheus) and `/health` endpoints. Metrics are scraped by the platform's Prometheus instance and forwarded through a data processor that maps internal metric names to customer-facing metric names with a `crusoe_vm_` prefix.

---

## Metric naming and downstream processing

All metrics are prefixed with `crusoe_vm_` (defined in `src/collectors/constants.go`). A downstream data processor (`cms-data-processor`) maps these metric names for customer-facing dashboards and internal monitoring. Every metric exported by this agent must have a corresponding entry in the data processor's metric mapping configuration to ensure it is correctly routed and labeled.
