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

## Object Store Latency Collector

Measures HTTP request latency to object store endpoints by probing `tcp_sendmsg` / `tcp_recvmsg` and filtering on destination IP + port.

### Environment Variables

| Variable                | Default | Description |
|-------------------------|---------|-------------|
| `OBJSTORE_ENDPOINT_IPS` | (none)  | Comma-separated object store server IPs. **Required** -- the collector is skipped if this is empty. |
| `OBJSTORE_ENDPOINT_PORT`| `443`   | Destination port to filter on |

### Metrics

All metrics are labeled by `endpoint` and `operation`.

| Metric | Type | Description |
|--------|------|-------------|
| `crusoe_vm_objectstore_latency_seconds` | counter | Cumulative request latency in seconds |
| `crusoe_vm_objectstore_requests_total` | counter | Total requests |
| `crusoe_vm_objectstore_latency_p50_seconds` | gauge | 50th percentile latency |
| `crusoe_vm_objectstore_latency_p90_seconds` | gauge | 90th percentile latency |
| `crusoe_vm_objectstore_latency_p99_seconds` | gauge | 99th percentile latency |

### Example Configuration

```yaml
env:
- name: OBJSTORE_ENDPOINT_IPS
  value: "100.63.0.10,10.234.1.180,10.234.1.132"
- name: OBJSTORE_ENDPOINT_PORT
  value: "8080"
```

---

## Daemonset Example

Minimal daemonset env block with all three collectors:

```yaml
env:
- name: HOST_PROC_PATH
  value: /host/proc
- name: OBJSTORE_ENDPOINT_PORT
  value: "8080"
- name: OBJSTORE_ENDPOINT_IPS
  value: "100.63.0.10,10.234.1.180,10.234.1.132"
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
