# Crusoe Metrics Exporter

A Prometheus-compatible metrics exporter for Crusoe VMs. Collects guest health signals (CPU steal, memory and I/O pressure, kernel soft lockups) alongside disk I/O, NFS, object store, and NVMe controller health metrics, using a combination of eBPF kernel probes, procfs/PSI/mountstats parsing, kernel-log tailing, and NVMe admin commands.

## Features

- **eBPF-based latency collection** -- kprobes on `tcp_sendmsg`, `tcp_recvmsg`, `tcp_retransmit_skb`, and block I/O tracepoints for high-fidelity, low-overhead measurements
- **Guest health signals** -- CPU steal normalized by vCPU count, PSI memory/I/O pressure, and kernel soft-lockup detection, for diagnosing problems the host's own metrics cannot see from outside the guest
- **Histogram metrics** -- geometric bucket distributions for disk, NFS, and object store latency
- **TCP retransmit counters** -- per-destination retransmit tracking for NFS and object store as an availability signal
- **NFS mountstats parsing** -- RPC counts, RTT, execution time, timeouts, backlog, per-`nconnect`-lane (xprt) state, and per-mount VFS/event counters from `/proc/1/mountstats`
- **Volume ID labeling** -- NFS metrics labeled by Crusoe volume ID extracted from mount paths
- **NVMe SMART/Health monitoring** -- passthrough drive health via admin commands (critical warnings, media errors, endurance, spare capacity)
- **Modular collector architecture** -- each subsystem is an independent `prometheus.Collector`
- **Graceful degradation** -- eBPF collectors log warnings and continue if the kernel lacks support
- **Containerized deployment** -- runs as a sidecar in a Kubernetes DaemonSet

---

## Table of Contents

- [Development](#development)
- [Configuration](#configuration)
- [Collectors](#collectors)
- [Project Structure](#project-structure)
- [Build & Run](#build--run)
- [Adding Custom Collectors](#adding-custom-collectors)

---

### Development

See [BUILD_TEST.md](BUILD_TEST.md) for details on how to build/test eBPF locally on macOS (via Lima VM), and details on how the eBPF code is structured.

---

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PORT` | `9500` | HTTP server port |
| `HOST_PROC_PATH` | `/host/proc` (container) or `/proc` (bare metal) | Root of the host's `/proc` filesystem |
| `MOUNTSTATS_PATH` | `$HOST_PROC_PATH/1/mountstats` | Path to mountstats file for NFS stats collector |
| `NFS_SERVER_IPS` | (auto-detected from `/proc/mounts`) | Comma-separated NFS server IPs for eBPF latency filtering |
| `NFS_TARGET_PORTS` | `2049` | Comma-separated NFS target ports |
| `NFS_ENABLE_VOLUME_ID` | `true` | Enable volume ID extraction from mount paths |
| `NFS_MOUNT_REFRESH_INTERVAL` | `30s` | How often to re-scan mounts for new NFS volumes |
| `PROBE_INTERVAL` | `5m` | How often to run health probes (ICMP ping, NFS RPC, HTTPS). Go duration format (e.g. `30s`, `2m`). Defaults to 5m, as it's not usually useful for a single VM, more for aggregate across a fleet |
| `OBJSTORE_ENDPOINT_FQDN` | - | Object store endpoint FQDN, resolved via DNS to up to 16 IPs (preferred; required to enable collector unless `OBJSTORE_ENDPOINT_IPS` is set) |
| `OBJSTORE_ENDPOINT_IPS` | - | Comma-separated object store endpoint IPs (legacy fallback; ignored when `OBJSTORE_ENDPOINT_FQDN` is set) |
| `OBJSTORE_ENDPOINT_PORT` | `443,80` | Comma-separated ports to monitor for object store traffic (up to 4) |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`, `fatal`) |

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `/metrics` | Prometheus metrics |
| `/health` | Health check (returns `OK`) |

---

## Collectors

> **Note:** All metrics are prefixed with `crusoe_vm_`. This prefix is defined in `src/collectors/constants.go` as `MetricPrefix`.

### Disk Latency Collector (eBPF)

**Source:** `src/collectors/disk-latency-collector.go` | **eBPF:** `ebpf/disk_latency.c`

Measures per-device disk I/O latency using eBPF tracepoints (`block_rq_issue` / `block_rq_complete`). Produces latency histograms with 20 geometric buckets.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_disk_reads_completed_total` | Counter | `device` | Total disk read operations |
| `crusoe_vm_disk_writes_completed_total` | Counter | `device` | Total disk write operations |
| `crusoe_vm_disk_read_bytes_total` | Counter | `device` | Total bytes read |
| `crusoe_vm_disk_write_bytes_total` | Counter | `device` | Total bytes written |
| `crusoe_vm_disk_read_latency_seconds_total` | Counter | `device` | Total read latency (seconds) |
| `crusoe_vm_disk_write_latency_seconds_total` | Counter | `device` | Total write latency (seconds) |
| `crusoe_vm_disk_read_latency_seconds` | Histogram | `device` | Read latency histogram |
| `crusoe_vm_disk_write_latency_seconds` | Histogram | `device` | Write latency histogram |
| `crusoe_vm_disk_collection_errors_total` | Counter | - | Collection errors |

### Disk Usage Collector

**Source:** `src/collectors/disk-usage-collector.go`

Reports filesystem usage per `vd*` partition by reading `HOST_PROC_PATH/1/mounts` and calling `statfs` through `HOST_PROC_PATH/1/root`.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_disk_bytes_used` | Gauge | `device`, `mount_point` | Bytes currently used on disk filesystem |
| `crusoe_vm_disk_bytes_total` | Gauge | `device`, `mount_point` | Total bytes on disk filesystem |
| `crusoe_vm_disk_inodes_used` | Gauge | `device`, `mount_point` | Inodes currently used on disk filesystem |
| `crusoe_vm_disk_inodes_total` | Gauge | `device`, `mount_point` | Total inodes on disk filesystem |
| `crusoe_vm_disk_usage_collection_errors_total` | Counter | - | Collection errors |

### Disk Stats Collector (procfs)

**Source:** `src/collectors/disk-stats-collector.go`

Collects disk I/O statistics from `/proc/diskstats`. Filters for main disk devices (`vda`, `vdb`, etc.) and excludes partitions.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_disk_reads_completed_total` | Counter | `device` | Total reads completed |
| `crusoe_vm_disk_read_time_ms_total` | Counter | `device` | Total time spent reading (ms) |
| `crusoe_vm_disk_writes_completed_total` | Counter | `device` | Total writes completed |
| `crusoe_vm_disk_write_time_ms_total` | Counter | `device` | Total time spent writing (ms) |
| `crusoe_vm_disk_stats_collection_errors_total` | Counter | - | Collection errors |

### NFS Latency Collector (eBPF)

**Source:** `src/collectors/nfs-latency-collector.go` | **eBPF:** `ebpf/nfs_latency.c`

Measures NFS request latency using eBPF kprobes on `tcp_sendmsg` / `tcp_recvmsg`, filtered to known NFS server IPs on port 2049. Also tracks TCP retransmissions via `tcp_retransmit_skb`. Resolves volume IDs from mount paths.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_nfs_latency_seconds` | Counter | `protocol`, `operation`, `volume_id` | Total NFS latency (seconds) |
| `crusoe_vm_nfs_requests_total` | Counter | `protocol`, `operation`, `volume_id` | Total NFS requests |
| `crusoe_vm_nfs_tcp_retransmits_total` | Counter | `protocol`, `operation`, `volume_id` | TCP retransmissions to NFS servers |
| `crusoe_vm_nfs_latency_histogram_seconds` | Histogram | `protocol`, `operation`, `volume_id` | NFS latency histogram (20 geometric buckets, 0.5ms--50ms) |

### NFS Stats Collector (mountstats)

**Source:** `src/collectors/nfs-stats-collector.go`

Parses `/proc/1/mountstats` for NFS RPC statistics and transport-level backlog. Handles duplicate mount blocks for the same volume by deduplicating per volume ID.

Tracked ops are exported even when their op count is zero: an absent counter cannot be told apart from an uninstrumented one, and it breaks `rate()`.

Tracks a fixed set of ops rather than every op in the per-op statistics section, to avoid exporting series for ops that are near-always-zero after mount: `read`, `write`, `getattr`, `lookup`, `access`, `create`, `remove`, `rename`, `commit`, `readdir`, `readdirplus`, plus the mount-time RPCs `null`, `fsstat`, `fsinfo`, `pathconf`. Those four are near-always-zero after mount but are the RPCs that `mount()` itself issues, so they give visibility into mount-time RPC behavior.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_nfs_rpc_count_total` | Counter | `volume_id`, `nfs_operation` | Total RPC operations, per tracked op |
| `crusoe_vm_nfs_rpc_timeouts_total` | Counter | `volume_id`, `nfs_operation` | Total RPC major timeouts |
| `crusoe_vm_nfs_rpc_retransmits_total` | Counter | `volume_id`, `nfs_operation` | RPC retransmissions (`trans - ops`): requests sent again because no reply arrived. |
| `crusoe_vm_nfs_rpc_errors_total` | Counter | `volume_id`, `nfs_operation` | RPCs that completed with an error status. |
| `crusoe_vm_nfs_rpc_rtt_ms_total` | Counter | `volume_id`, `nfs_operation` | Total RTT time (ms) |
| `crusoe_vm_nfs_rpc_exe_ms_total` | Counter | `volume_id`, `nfs_operation` | Total execution time (ms) |
| `crusoe_vm_nfs_rpc_queue_ms_total` | Counter | `volume_id`, `nfs_operation` | Total time queued on this host before transmission (ms). `execute - queue - rtt` is post-reply client time. |
| `crusoe_vm_nfs_rpc_backlog` | Counter | `volume_id` | RPC backlog utilization (`bklog_u` from `xprt: tcp`) |
| `crusoe_vm_nfs_bytes_sent_total` | Counter | `volume_id`, `nfs_operation` | Total bytes sent (from mountstats) |
| `crusoe_vm_nfs_bytes_recv_total` | Counter | `volume_id`, `nfs_operation` | Total bytes received (from mountstats) |
| `crusoe_vm_nfs_stats_collection_errors_total` | Counter | - | Collection errors |

### NFS Per-Xprt Collector (mountstats)

**Source:** `src/collectors/nfs-xprt-collector.go`

Parses the per-`xprt:` lines from `/proc/1/mountstats` and emits one series per `(volume_id, xprt_idx)` for each lane of an `nconnect`-mounted NFS volume. Complements the volume-aggregate NFS Stats Collector — those metrics collapse all `nconnect` transports into a single series, so per-lane diagnostics (dead lane, hot-spot, lane-specific reconnects) need this finer breakdown.

`xprt_idx` is a 0-based index within the mount block, assigned in scan order. It is stable across reconnects (unlike `srcport`, which the kernel regenerates on each socket teardown), so PromQL time series stay continuous through normal NFS reconnect activity.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_nfs_xprt_sends_total` | Counter | `volume_id`, `xprt_idx` | NFS RPC requests sent on this xprt (lane). `rate() == 0` with `connect_count > 0` indicates a dead lane. |
| `crusoe_vm_nfs_xprt_recvs_total` | Counter | `volume_id`, `xprt_idx` | NFS RPC replies received on this xprt (lane). |
| `crusoe_vm_nfs_xprt_connect_count_total` | Counter | `volume_id`, `xprt_idx` | TCP_ESTABLISHED transitions on this xprt (initial connect + every reconnect). NOT the number of connect attempts. |
| `crusoe_vm_nfs_xprt_bad_xids_total` | Counter | `volume_id`, `xprt_idx` | NFS RPC replies with mismatched XIDs — out-of-order or corrupted-frame indicator. |
| `crusoe_vm_nfs_xprt_max_slots` | Gauge | `volume_id`, `xprt_idx` | High-water mark of slot table size. Stuck at 2 (kernel default) with no traffic indicates a lane that was never used. |
| `crusoe_vm_nfs_xprt_idle_seconds` | Gauge | `volume_id`, `xprt_idx` | Seconds since the last activity on this xprt. |
| `crusoe_vm_nfs_xprt_backlog_utilization` | Counter | `volume_id`, `xprt_idx` | Cumulative per-xprt backlog utilization (`bklog_u`). Per-lane breakdown of what NFS Stats Collector aggregates as `nfs_rpc_backlog`. |
| `crusoe_vm_nfs_xprt_sending_utilization` | Counter | `volume_id`, `xprt_idx` | Cumulative sending-queue occupancy (`sending_u`): RPCs that hold a slot and are being transmitted. Compare with backlog (waiting for a slot) and pending (waiting for a reply). |
| `crusoe_vm_nfs_xprt_pending_utilization` | Counter | `volume_id`, `xprt_idx` | Cumulative pending-queue occupancy (`pending_u`): RPCs sent and waiting for the server's reply. |
| `crusoe_vm_nfs_xprt_stats_collection_errors_total` | Counter | - | Collection errors. |

### NFS Mount Events Collector (mountstats)

**Source:** `src/collectors/nfs-mount-events-collector.go`

Parses the per-mount `events:`, `bytes:`, and `age:` lines from `/proc/1/mountstats` and emits one series per `(volume_id)` for kernel-level mount counters. Complements the per-op NFS Stats Collector and the per-xprt collector by exposing **mount-level VFS and kernel-event counters** — bytes broken down by syscall path (page cache vs `O_DIRECT` vs over-the-wire) and event counters for client- and server-side back-pressure signals.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_nfs_mount_age_seconds` | Gauge | `volume_id` | Seconds since the NFS mount was established. Drops to a small value when the mount is recreated. |
| `crusoe_vm_nfs_mount_congestion_wait_events_total` | Counter | `volume_id` | Client-side BDI writeback congestion waits. |
| `crusoe_vm_nfs_mount_silly_rename_events_total` | Counter | `volume_id` | Silly renames: unlinking a file that is still open locally renames it to `.nfsXXXX` on the server, and the REMOVE is sent when the last local reference closes. |
| `crusoe_vm_nfs_mount_short_read_events_total` | Counter | `volume_id` | Reads where the server returned fewer bytes than requested. |
| `crusoe_vm_nfs_mount_short_write_events_total` | Counter | `volume_id` | Writes where the server committed fewer bytes than requested. |
| `crusoe_vm_nfs_mount_delay_events_total` | Counter | `volume_id` | NFSv4 retry-after-DELAY counter (`NFS4ERR_DELAY`). **Structurally zero on NFSv3 mounts** — see caveat below. |
| `crusoe_vm_nfs_mount_normal_read_bytes_total` | Counter | `volume_id` | Bytes returned by buffered (non-`O_DIRECT`) `read()` syscalls. |
| `crusoe_vm_nfs_mount_normal_write_bytes_total` | Counter | `volume_id` | Bytes written by buffered (non-`O_DIRECT`) `write()` syscalls. |
| `crusoe_vm_nfs_mount_direct_read_bytes_total` | Counter | `volume_id` | Bytes returned by `O_DIRECT` reads (what `fio --direct=1` consumes). |
| `crusoe_vm_nfs_mount_direct_write_bytes_total` | Counter | `volume_id` | Bytes written by `O_DIRECT` writes. |
| `crusoe_vm_nfs_mount_server_read_bytes_total` | Counter | `volume_id` | Bytes actually fetched from the NFS server (over the wire). |
| `crusoe_vm_nfs_mount_server_write_bytes_total` | Counter | `volume_id` | Bytes actually written to the NFS server (over the wire). |
| `crusoe_vm_nfs_mount_read_pages_total` | Counter | `volume_id` | Pages read via `readpage`/`readpages` NFS ops. |
| `crusoe_vm_nfs_mount_write_pages_total` | Counter | `volume_id` | Pages written via `writepage`/`writepages` NFS ops. |
| `crusoe_vm_nfs_mount_events_collection_errors_total` | Counter | - | Collection errors. |

> **NFSv3 caveat on `delay_events_total`:** This counter is bumped only by `nfs4_handle_exception` on `NFS4ERR_DELAY` replies, so it is **structurally zero on NFSv3 mounts** (v3 has no `NFS4ERR_DELAY`; the analogous `NFS3ERR_JUKEBOX` retry is handled at the SUNRPC layer and not surfaced as an `NFSIOS_*` event). On v3, server back-pressure surfaces instead as RPC timeouts (`nfs_rpc_timeouts_total`) and TCP-level reconnects (`nfs_xprt_connect_count_total`).

> **Page-cache hit math:** `normal_read + direct_read − server_read` gives bytes served from the page cache. `server_read` accumulates wire fetches for both the buffered and `O_DIRECT` paths; since `O_DIRECT` bypasses the cache by definition, `server_for_direct = direct_read`, so `normal − (server − direct) = normal + direct − server` is the buffered-path bytes that did not go to the wire. On a pure `O_DIRECT` workload this expression is 0 (correct: no cache involvement).

### NVMe Controller Collector

**Source:** `src/collectors/nvme-controller-collector.go` | **Admin commands:** `src/collectors/nvme_admin.go`

Reports controller identity and SMART/Health Log (Page 0x02) for PCIe-passthrough NVMe drives. Enabled only when at least one NVMe controller is visible under `/sys/class/nvme` **and** the device file `/dev/nvme0` is openable. On virtio-only VMs the collector is silently skipped; no metrics are registered.

**No environment variables required.** Enabled/disabled by a one-shot startup probe.

> **Deployment note:** The container must have access to `/dev/nvme*`. Add a bind mount (e.g. `/dev/nvme0:/dev/nvme0`) to the compose file or Helm values. Native systemd deployments have full host access and need no change.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_nvme_info` | Gauge (always 1) | `device`, `serial`, `model`, `firmware_rev` | Controller identity |
| `crusoe_vm_nvme_smart_critical_warning` | Gauge (0/1) | `device`, `serial`, `bit` | SMART critical warning bit (`spare_low`, `temperature`, `reliability`, `readonly`, `volatile_backup_failed`, `pmr_unreliable`) |
| `crusoe_vm_nvme_media_errors_total` | Counter | `device`, `serial` | Uncorrectable media and data integrity errors |
| `crusoe_vm_nvme_error_log_entries_total` | Counter | `device`, `serial` | Lifetime error log entries |
| `crusoe_vm_nvme_percentage_used` | Gauge | `device`, `serial` | Drive life consumed (0--255; 100 = rated endurance reached) |
| `crusoe_vm_nvme_available_spare` | Gauge | `device`, `serial` | Remaining spare capacity (0--100%) |
| `crusoe_vm_nvme_power_on_hours` | Gauge | `device`, `serial` | Lifetime power-on hours |
| `crusoe_vm_nvme_collection_errors_total` | Gauge | - | SMART read errors in this scrape |

### Object Store Connection Collector (eBPF)

**Source:** `src/collectors/objstore-latency-collector.go` | **eBPF:** `ebpf/objstore_latency.c`

Measures object store (S3-compatible) connection-level latency, byte throughput, and TCP retransmissions using eBPF kprobes on `tcp_sendmsg` / `tcp_cleanup_rbuf` / `tcp_retransmit_skb`, filtered to configured endpoint IPs. Enabled when `OBJSTORE_ENDPOINT_FQDN` or `OBJSTORE_ENDPOINT_IPS` is set. The preferred configuration is `OBJSTORE_ENDPOINT_FQDN` (e.g. `object.eu-iceland1-a.crusoecloudcompute.com`), which is resolved via DNS at startup.

> **Note:** With TLS/HTTP2, per-request GET/PUT classification is not possible from the TCP layer. These metrics report aggregate connection-phase statistics per endpoint. Per-request latency should be measured via a proxy-based approach.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_objectstore_connection_latency_seconds` | Counter | `endpoint` | Total connection-phase latency (seconds) |
| `crusoe_vm_objectstore_connections_total` | Counter | `endpoint` | Total connection phases observed |
| `crusoe_vm_objectstore_tcp_retransmits_total` | Counter | `endpoint` | TCP retransmissions to object store |
| `crusoe_vm_objectstore_bytes_sent_total` | Counter | `endpoint` | Total bytes sent to object store |
| `crusoe_vm_objectstore_bytes_recv_total` | Counter | `endpoint` | Total bytes received from object store |
| `crusoe_vm_objectstore_connection_latency_histogram_seconds` | Histogram | `endpoint` | Connection-phase latency histogram (20 geometric buckets, 1ms--1000ms) |

### CPU Steal Collector (procfs)

**Source:** `src/collectors/cpu-steal-collector.go`

Reads the aggregate `cpu` line and the per-cpu (`cpuN`) lines from `HOST_PROC_PATH/stat`. **Steal** is time the guest's vCPUs were runnable but not scheduled by the hypervisor -- on a fleet with pinned CPUs it should sit near zero, so sustained steal points at host-side contention or a placement misconfiguration rather than guest load. Jiffies are converted to seconds using the procfs ABI's fixed `USER_HZ` of 100.

`crusoe_vm_cpu_count` is the denominator that makes steal comparable across instance sizes: `rate(cpu_steal_seconds_total[5m]) / cpu_count` is the fraction of the VM's compute being withheld, which is the form worth alerting on.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_cpu_steal_seconds_total` | Counter | - | Cumulative vCPU-seconds withheld by the hypervisor, summed across vCPUs |
| `crusoe_vm_cpu_count` | Gauge | - | Online vCPUs, counted from the per-cpu lines in `/proc/stat` |
| `crusoe_vm_procs_running` | Gauge | - | Runnable (R-state) tasks -- steal only hurts when this is non-zero |
| `crusoe_vm_cpu_steal_collection_errors_total` | Counter | - | Collection errors (one per missing or unparseable field) |

### Memory Pressure Collector (PSI)

**Source:** `src/collectors/memory-pressure-collector.go`

Parses Linux Pressure Stall Information from `HOST_PROC_PATH/pressure/memory`, plus `MemAvailable` / `SwapTotal` / `SwapFree` from `HOST_PROC_PATH/meminfo`. `scope="some"` is the fraction of the window in which *at least one* task was stalled on memory (contention, but the VM is still making progress); `scope="full"` is the fraction in which *all* non-idle tasks were stalled at once (the VM is thrashing). Publishes nothing when the kernel lacks PSI support.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_psi_memory_ratio` | Gauge | `scope`, `window` | Stalled fraction (0--1) of the rolling window; `scope` is `some`/`full`, `window` is `10`/`60`/`300` seconds |
| `crusoe_vm_psi_memory_stall_seconds_total` | Counter | `scope` | Cumulative time tasks were stalled waiting on memory |
| `crusoe_vm_mem_available_bytes` | Gauge | - | Memory available for new allocations without swapping (`MemAvailable`) |
| `crusoe_vm_swap_used_bytes` | Gauge | - | Swap currently in use (`SwapTotal - SwapFree`) |
| `crusoe_vm_mem_collection_errors_total` | Counter | - | Collection errors |

### I/O Pressure Collector (PSI)

**Source:** `src/collectors/io-pressure-collector.go`

Same PSI scopes and windows as the memory collector, read from `HOST_PROC_PATH/pressure/io`, plus `procs_blocked` from `HOST_PROC_PATH/stat`. On I/O-heavy fleets a high `some` value is normal -- workloads streaming datasets or writing checkpoints spend real time waiting on disk -- so `full` is the signal that a VM is choked rather than merely busy.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_psi_io_ratio` | Gauge | `scope`, `window` | Stalled fraction (0--1) of the rolling window; `scope` is `some`/`full`, `window` is `10`/`60`/`300` seconds |
| `crusoe_vm_psi_io_stall_seconds_total` | Counter | `scope` | Cumulative time tasks were stalled waiting on I/O |
| `crusoe_vm_procs_blocked` | Gauge | - | Tasks in uninterruptible sleep (D-state), almost always waiting on I/O |
| `crusoe_vm_io_collection_errors_total` | Counter | - | Collection errors |

### Kernel Soft Lockup Collector (kmsg)

**Source:** `src/collectors/soft-lockup-collector.go`

A soft lockup is a CPU stuck in kernel mode for 20+ seconds without yielding. Unlike the other collectors this is an *event* in the kernel log rather than a value readable at scrape time, so a long-lived goroutine tails `/dev/kmsg` for the life of the process and increments a counter whenever the watchdog reports one; `Collect()` just emits the current totals.

Requires `CAP_SYSLOG` (or root, or `kernel.dmesg_restrict=0`) and a `/dev/kmsg` mount -- without them the collector logs a warning and disables itself so the exporter still starts. The tailer seeks to the end of the ring buffer at startup, so a restart never re-counts historical lockups and injects a phantom `rate()` spike, and it treats `EPIPE` as a recoverable overflow. Each watchdog *report* counts: a CPU that stays stuck is re-reported roughly every 20 seconds, so one prolonged episode increments the counter more than once. Hard-lockup detection is out of scope -- it relies on the NMI watchdog, typically unavailable in cloud VMs.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_kernel_soft_lockups_total` | Counter | - | Soft-lockup reports observed in `/dev/kmsg` since the exporter started |
| `crusoe_vm_kernel_soft_lockup_collection_errors_total` | Counter | - | Errors while tailing `/dev/kmsg`, including ring-buffer overflows |

### PromQL Examples

```promql
# NFS average latency per volume
rate(crusoe_vm_nfs_latency_seconds[5m]) / rate(crusoe_vm_nfs_requests_total[5m])

# NFS RPC timeout rate per volume
rate(crusoe_vm_nfs_rpc_timeouts_total[5m]) / rate(crusoe_vm_nfs_rpc_count_total[5m])

# NFS TCP retransmit rate
rate(crusoe_vm_nfs_tcp_retransmits_total[5m])

# Alive-lane count per nconnect mount (compare with mount's nconnect option)
count(rate(crusoe_vm_nfs_xprt_sends_total[5m]) > 0) by (volume_id)

# Per-lane backlog hot-spotting (which xprt is queuing)
rate(crusoe_vm_nfs_xprt_backlog_utilization[5m]) > 0

# Per-lane reconnect churn (server is resetting connections on this lane)
rate(crusoe_vm_nfs_xprt_connect_count_total[5m]) > 0

# Page-cache hit bytes per second (see Mount Events Collector for derivation)
rate(crusoe_vm_nfs_mount_normal_read_bytes_total[5m])
  + rate(crusoe_vm_nfs_mount_direct_read_bytes_total[5m])
  - rate(crusoe_vm_nfs_mount_server_read_bytes_total[5m])

# Server short-reply rate (truncated NFS responses — rare but real signal)
rate(crusoe_vm_nfs_mount_short_read_events_total[5m])

# Object store average connection latency per endpoint
rate(crusoe_vm_objectstore_connection_latency_seconds[5m]) / rate(crusoe_vm_objectstore_connections_total[5m])

# Object store TCP retransmit rate
rate(crusoe_vm_objectstore_tcp_retransmits_total[5m])

# Disk write latency p99 (histogram)
histogram_quantile(0.99, rate(crusoe_vm_disk_write_latency_seconds[5m]))

# NVMe drives with any critical warning bit set
crusoe_vm_nvme_smart_critical_warning == 1

# NVMe drives approaching end of life (percentage_used ≥ 90)
crusoe_vm_nvme_percentage_used >= 90

# NVMe media error rate
rate(crusoe_vm_nvme_media_errors_total[1h])
# CPU steal as a fraction of the VM's compute (comparable across instance sizes)
rate(crusoe_vm_cpu_steal_seconds_total[5m]) / crusoe_vm_cpu_count

# Share of the fleet losing more than 5% of its compute to steal
count(rate(crusoe_vm_cpu_steal_seconds_total[5m]) / crusoe_vm_cpu_count > 0.05)
  / count(crusoe_vm_cpu_count)

# Fleet distribution of memory pressure (p50/p99 over the 60s window)
quantile(0.50, crusoe_vm_psi_memory_ratio{scope="some", window="60"})
quantile(0.99, crusoe_vm_psi_memory_ratio{scope="some", window="60"})

# VMs fully stalled on I/O -- all non-idle tasks blocked, not merely busy
crusoe_vm_psi_io_ratio{scope="full", window="60"} > 0.1

# Soft-lockup reports per hour across the fleet
sum(increase(crusoe_vm_kernel_soft_lockups_total[1h]))

```

---

## Project Structure

```
.
├── ebpf/                                        # eBPF C source code
│   ├── disk_latency.c / .h                      # Block I/O tracepoint probe
│   ├── nfs_latency.c / .h                       # NFS TCP kprobe (sendmsg/recvmsg/retransmit)
│   ├── objstore_latency.c / .h                  # Object store TCP kprobe
│   └── vmlinux.h                                # Kernel BTF type definitions
├── src/
│   ├── main.go                                  # Entry point, env config, collector registration
│   ├── log/
│   │   └── log.go                               # Logrus-based logger with level support
│   └── collectors/
│       ├── constants.go                         # MetricPrefix ("crusoe_vm_")
│       ├── bpf_types.go                         # Shared eBPF type definitions
│       ├── histogram_utils.go                   # Histogram bucket math (geometric boundaries)
│       ├── disk-stats-collector.go              # Disk I/O from /proc/diskstats
│       ├── disk-latency-collector.go            # Disk latency via eBPF tracepoints
│       ├── nfs-stats-collector.go               # NFS RPC per-op stats from /proc/1/mountstats
│       ├── nfs-xprt-collector.go                # Per-nconnect-lane (xprt) state from mountstats
│       ├── nfs-mount-events-collector.go        # Per-mount events/bytes/age from mountstats
│       ├── nfs-latency-collector.go             # NFS latency via eBPF kprobes
│       ├── objstore-latency-collector.go        # Object store latency via eBPF kprobes
│       ├── nvme-controller-collector.go         # NVMe SMART/Health via admin commands
│       ├── nvme_admin.go                        # NVMe ioctl helpers (Get Log Page)
│       ├── testdata/                            # Golden fixtures for mountstats parsers
│       └── ebpf/                                # Compiled eBPF bytecode (embedded via go:embed)
│           ├── disk_latency.o
│           ├── nfs_latency.o
│           └── objstore_latency.o
├── crusoe-watch-agent-daemonset.yaml            # Kubernetes DaemonSet manifest
├── Dockerfile                                   # Container build
├── docker-compose.yaml                          # Docker Compose config
├── Makefile                                     # Build automation
├── VERSION                                      # Current version
├── BUILD_TEST.md                                # eBPF build/test guide (macOS/Lima)
├── CONFIG.md                                    # Additional configuration docs
├── go.mod / go.sum                              # Go module
└── README.md
```

---

## Build & Run

### Prerequisites

- Go 1.23+
- Docker (for containerized deployment)
- clang/llvm (for eBPF compilation -- requires Linux or Lima VM on macOS)

### Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Compile eBPF programs + build Go binary to `build/dist/` |
| `make run` | Build and run locally |
| `make ebpf-compile` | Compile all eBPF `.c` to `.o` (requires clang + Linux headers) |
| `make ebpf-clean` | Remove compiled eBPF `.o` files |
| `make docker-build` | Build Docker image |
| `make docker-run` | Build and run in Docker (privileged, mounts `/proc`) |
| `make test` | Run all Go tests |
| `make fmt` | Format Go code |
| `make lint` | Run golangci-lint |
| `make deps` | Download and tidy Go dependencies |
| `make clean` | Remove build artifacts, eBPF objects, and Docker image |
| `make help` | List all targets |

### Manual Build

```bash
# Compile eBPF (must be on Linux or in Lima VM)
make ebpf-compile

# Build Go binary
go build -o build/dist/crusoe-metrics-exporter ./src

# Run
./build/dist/crusoe-metrics-exporter
```

### macOS Development (Lima VM)

eBPF compilation requires a Linux environment. On macOS, use a Lima VM:

```bash
# Clean old objects on host
rm -f src/collectors/ebpf/*.o

# Copy source into Lima VM, build there
limactl shell ebpf-builder sh -c \
  'cp -r crusoe-metrics-exporter /tmp/build && cd /tmp/build && make ebpf-compile'

# Copy compiled .o files back to host
limactl shell ebpf-builder sh -c 'cat /tmp/build/src/collectors/ebpf/nfs_latency.o' > src/collectors/ebpf/nfs_latency.o
limactl shell ebpf-builder sh -c 'cat /tmp/build/src/collectors/ebpf/objstore_latency.o' > src/collectors/ebpf/objstore_latency.o
limactl shell ebpf-builder sh -c 'cat /tmp/build/src/collectors/ebpf/disk_latency.o' > src/collectors/ebpf/disk_latency.o
```

See [BUILD_TEST.md](BUILD_TEST.md) for full details.

---

## Adding Custom Collectors

### Step 1: Create Collector File

Create a new file in `src/collectors/` following the naming convention `<name>-collector.go`:

```go
package collectors

import (
    "github.com/prometheus/client_golang/prometheus"
)

type MyCustomCollector struct {
    configPath       string
    myMetric         *prometheus.Desc
    collectionErrors *prometheus.Desc
}

func NewMyCustomCollector(configPath string) *MyCustomCollector {
    return &MyCustomCollector{
        configPath: configPath,
        myMetric: prometheus.NewDesc(
            MetricPrefix+"my_metric_total",
            "Description of what this measures",
            []string{"label1", "label2"},
            nil,
        ),
        collectionErrors: prometheus.NewDesc(
            MetricPrefix+"my_custom_collection_errors_total",
            "Total errors during collection",
            nil,
            nil,
        ),
    }
}

func (c *MyCustomCollector) Describe(ch chan<- *prometheus.Desc) {
    ch <- c.myMetric
    ch <- c.collectionErrors
}

func (c *MyCustomCollector) Collect(ch chan<- prometheus.Metric) {
    errorCount := 0.0
    value := 42.0
    ch <- prometheus.MustNewConstMetric(c.myMetric, prometheus.CounterValue, value, "val1", "val2")
    ch <- prometheus.MustNewConstMetric(c.collectionErrors, prometheus.CounterValue, errorCount)
}
```

### Step 2: Register in main.go

```go
myCollector := collectors.NewMyCustomCollector("/path/to/config")
prometheus.MustRegister(myCollector)
```

### Best Practices

1. **Metric Prefix** -- all metrics MUST use `MetricPrefix` from `constants.go` (currently `crusoe_vm_`)
2. **Naming** -- file: `<name>-collector.go`, struct: `<Name>Collector`, metric: `MetricPrefix + "<subsystem>_<name>_<unit>_total"`
3. **Error Handling** -- always include a `collectionErrors` metric; use `log.Errorf()` / `log.Warnf()`
4. **Deduplication** -- if a data source can produce duplicate label sets (e.g., same NFS volume mounted twice), accumulate into a map and emit once
5. **Labels** -- keep cardinality low; use consistent names across collectors
6. **Testing** -- test files go in `src/collectors/<name>-collector_test.go`

---

## Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'crusoe-metrics'
    static_configs:
      - targets: ['localhost:9500']
    scrape_interval: 15s
```

---

## eBPF Architecture

Three eBPF programs run as kprobes/tracepoints, each with their own IP filter map and stats structure:

| Program | Probe Points | Filter Map | Stats Map |
|---------|-------------|------------|-----------|
| `nfs_latency.c` | `tcp_sendmsg`, `tcp_recvmsg`, `tcp_retransmit_skb`, `udp_sendmsg` | `nfs_server_ips` | `nfs_latency_by_ip` |
| `objstore_latency.c` | `tcp_sendmsg`, `tcp_cleanup_rbuf`, `tcp_retransmit_skb` | `objstore_server_ips` | `objstore_latency_by_ip` |
| `disk_latency.c` | `block_rq_issue`, `block_rq_complete` (tracepoints) | - | `disk_latency_by_dev` |

Each stats structure contains: `request_count`, `total_latency_ns`, `histogram[20]`, `retransmit_count`, `bytes_sent`, and `bytes_recv` (TCP programs only).

The compiled `.o` files are embedded into the Go binary via `go:embed` and loaded at startup using the `cilium/ebpf` library.

### Requirements

- Linux kernel 5.8+ with BTF support (`ls /sys/kernel/btf/vmlinux`)
- `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN` on older kernels)
- clang 10+ and libbpf-dev for compilation

### Troubleshooting

- **"failed to load eBPF program"** -- check kernel version (`uname -r`, need 5.8+) and BTF support
- **"operation not permitted"** -- add `--cap-add=BPF --cap-add=PERFMON` to Docker, or use `--privileged`
- **Verify loaded programs:** `sudo bpftool prog list`

See also [BUILD_TEST.md](BUILD_TEST.md) for more details on eBPF build/test/troubleshooting.

---

## License

MIT
