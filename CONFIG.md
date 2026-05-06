# Configuration Reference

The crusoe-metrics-exporter runs three eBPF-based collectors: **Disk**, **NFS**, and **Object Store**. All three are always enabled. Configuration is via environment variables.

## Global Settings

| Variable         | Default      | Description                                                    |
|------------------|--------------|----------------------------------------------------------------|
| `PORT`           | `9500`       | HTTP port for the `/metrics` and `/health` endpoints           |
| `HOST_PROC_PATH` | auto-detected | Root of the host's `/proc` filesystem. Set to `/host/proc` when running in a container with the host's procfs mounted, or `/proc` on bare metal. Auto-detection checks for `/host/proc/1/mounts`. |

`HOST_PROC_PATH` is used to derive paths like `HOST_PROC_PATH/1/mounts` for NFS mount discovery.

---

## Disk Latency Collector

Tracks block I/O latency per device using `blk_mq_start_request` / `blk_mq_end_request` kprobes.

**No configuration required.** Always enabled, no env vars needed.

### Metrics

All metrics are labeled by `device` (e.g., `sda`, `nvme0n1`).

| Metric | Type | Description |
|--------|------|-------------|
| `crusoe_vm_disk_reads_completed_total` | counter | Total read operations completed |
| `crusoe_vm_disk_writes_completed_total` | counter | Total write operations completed |
| `crusoe_vm_disk_read_bytes_total` | counter | Total bytes read |
| `crusoe_vm_disk_write_bytes_total` | counter | Total bytes written |
| `crusoe_vm_disk_read_latency_seconds_total` | counter | Cumulative read latency in seconds |
| `crusoe_vm_disk_write_latency_seconds_total` | counter | Cumulative write latency in seconds |
| `crusoe_vm_disk_read_latency_p50_seconds` | gauge | 50th percentile read latency |
| `crusoe_vm_disk_read_latency_p90_seconds` | gauge | 90th percentile read latency |
| `crusoe_vm_disk_read_latency_p99_seconds` | gauge | 99th percentile read latency |
| `crusoe_vm_disk_write_latency_p50_seconds` | gauge | 50th percentile write latency |
| `crusoe_vm_disk_write_latency_p90_seconds` | gauge | 90th percentile write latency |
| `crusoe_vm_disk_write_latency_p99_seconds` | gauge | 99th percentile write latency |
| `crusoe_vm_disk_collection_errors_total` | counter | Collection errors |

---

## Disk Usage Collector

Reports filesystem usage per `vd*` partition by reading `HOST_PROC_PATH/1/mounts` and calling `statfs` through `HOST_PROC_PATH/1/root`.

**No configuration required.** Always enabled, no env vars needed.

### Metrics

All metrics are labeled by `device` (e.g., `vda1`, `vdb1`) and `mount_point` (e.g., `/`, `/boot`).

| Metric | Type | Description |
|--------|------|-------------|
| `crusoe_vm_disk_bytes_used` | gauge | Bytes currently used on disk filesystem |
| `crusoe_vm_disk_inodes_used` | gauge | Inodes currently used on disk filesystem |
| `crusoe_vm_disk_usage_collection_errors_total` | counter | Collection errors |

---

## NFS Latency Collector

Measures NFS RPC round-trip latency by probing `tcp_sendmsg` / `tcp_recvmsg` and filtering on destination IP + port.

Note: Only TCP (NFS4) is implemented. The `NFS_PROTOCOLS` variable exists but UDP probes are not wired up.

### Environment Variables

| Variable                     | Default     | Description |
|------------------------------|-------------|-------------|
| `NFS_SERVER_IPS`             | auto-detected from `HOST_PROC_PATH/1/mounts` | Comma-separated NFS server IPs to monitor. If unset, IPs are discovered by parsing NFS mount entries. |
| `NFS_TARGET_PORTS`           | `2049`      | Comma-separated destination ports to filter on |
| `NFS_PROTOCOLS`              | `tcp,udp`   | Protocols to track (only `tcp` is currently implemented) |
| `NFS_ENABLE_VOLUME_ID`       | `true`      | Resolve NFS volume IDs from mount entries. Set to `false` to disable. |
| `NFS_MOUNT_REFRESH_INTERVAL` | `30s`       | How often to re-scan mounts for new NFS server IPs. Go duration format. |

### Volume ID Resolution

When enabled, the collector parses mount entries like:

```
nfs.crusoecloudcompute.com:/volumes/47d32f7f-1687-42c8-b6fd-67b3a2263c8e on /mnt/data type nfs4
```

It extracts the UUID from the export path and uses it as the `volume_id` label. If no volume ID can be extracted, the server hostname is used as a fallback.

### Metrics

All metrics are labeled by `endpoint`, `protocol`, `operation`, and `volume_id`.

| Metric | Type | Description |
|--------|------|-------------|
| `crusoe_vm_nfs_latency_seconds` | counter | Cumulative NFS request latency in seconds |
| `crusoe_vm_nfs_requests_total` | counter | Total NFS requests |
| `crusoe_vm_nfs_latency_p50_seconds` | gauge | 50th percentile latency |
| `crusoe_vm_nfs_latency_p90_seconds` | gauge | 90th percentile latency |
| `crusoe_vm_nfs_latency_p99_seconds` | gauge | 99th percentile latency |

### Example Configuration

```yaml
env:
- name: HOST_PROC_PATH
  value: /host/proc
# NFS server IPs are auto-discovered from /host/proc/1/mounts.
# Override if needed:
# - name: NFS_SERVER_IPS
#   value: "172.27.255.32,172.27.255.33"
```

---

## Object Store Connection Collector

Measures connection-level latency, byte throughput, and TCP retransmissions to object store endpoints by probing `tcp_sendmsg` / `tcp_cleanup_rbuf` / `tcp_retransmit_skb` and filtering on destination IP + port.

> **Note:** With TLS/HTTP2, per-request GET/PUT classification is not possible from the TCP layer. These metrics report aggregate connection-phase statistics per endpoint. Per-request latency should be measured via a proxy-based approach.

### Environment Variables

| Variable                 | Default | Description |
|--------------------------|---------|-------------|
| `OBJSTORE_ENDPOINT_FQDN` | (none)  | Object store endpoint FQDN (e.g. `object.eu-iceland1-a.crusoecloudcompute.com`). Resolved via DNS at startup to up to 16 IPv4 addresses. **Preferred** -- takes precedence over `OBJSTORE_ENDPOINT_IPS`. |
| `OBJSTORE_ENDPOINT_IPS`  | (none)  | Comma-separated object store server IPs. Legacy fallback -- ignored when `OBJSTORE_ENDPOINT_FQDN` is set. The collector is skipped if neither variable yields IPs. |
| `OBJSTORE_ENDPOINT_PORT` | `443`   | Destination port to filter on |

### Metrics

All metrics are labeled by `endpoint`.

| Metric | Type | Description |
|--------|------|-------------|
| `crusoe_vm_objectstore_connection_latency_seconds` | counter | Cumulative connection-phase latency in seconds |
| `crusoe_vm_objectstore_connections_total` | counter | Total connection phases observed |
| `crusoe_vm_objectstore_tcp_retransmits_total` | counter | TCP retransmissions to object store |
| `crusoe_vm_objectstore_bytes_sent_total` | counter | Total bytes sent to object store |
| `crusoe_vm_objectstore_bytes_recv_total` | counter | Total bytes received from object store |
| `crusoe_vm_objectstore_connection_latency_histogram_seconds` | histogram | Connection-phase latency histogram (20 geometric buckets, 1ms--1000ms) |

### Example Configuration

```yaml
env:
# Preferred: use FQDN (resolved via DNS at startup)
- name: OBJSTORE_ENDPOINT_FQDN
  value: "object.eu-iceland1-a.crusoecloudcompute.com"
- name: OBJSTORE_ENDPOINT_PORT
  value: "443"

# Legacy fallback: explicit IPs (ignored when OBJSTORE_ENDPOINT_FQDN is set)
# - name: OBJSTORE_ENDPOINT_IPS
#   value: "100.63.0.10,10.234.1.180,10.234.1.132"
```

---

## Daemonset Example

Minimal daemonset env block with all three collectors:

```yaml
env:
- name: HOST_PROC_PATH
  value: /host/proc
- name: OBJSTORE_ENDPOINT_FQDN
  value: "object.eu-iceland1-a.crusoecloudcompute.com"
- name: OBJSTORE_ENDPOINT_PORT
  value: "443"
```

The container requires:
- `privileged: true` (for eBPF kprobe attachment)
- Host procfs mounted at `/host/proc` (read-only)
- `/sys/fs/bpf` mounted (for BPF filesystem)
- `hostNetwork: true` (to see host TCP traffic)

## Requirements

- Linux kernel with BPF support
- Container must run as privileged (eBPF kprobe attachment)
- eBPF programs are compiled at Docker build time and embedded in the binary via `go:embed`
