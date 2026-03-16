# Crusoe Metrics Exporter

A Prometheus-compatible metrics exporter for Crusoe VMs. Collects disk I/O, NFS, and object store metrics using a combination of eBPF kernel probes and procfs/mountstats parsing.

## Features

- **eBPF-based latency collection** -- kprobes on `tcp_sendmsg`, `tcp_recvmsg`, `tcp_retransmit_skb`, and block I/O tracepoints for high-fidelity, low-overhead measurements
- **Histogram metrics** -- geometric bucket distributions for disk, NFS, and object store latency
- **TCP retransmit counters** -- per-destination retransmit tracking for NFS and object store as an availability signal
- **NFS mountstats parsing** -- RPC counts, RTT, execution time, timeouts, and backlog from `/proc/1/mountstats`
- **Volume ID labeling** -- NFS metrics labeled by Crusoe volume ID extracted from mount paths
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
| `OBJSTORE_ENDPOINT_IPS` | - | Comma-separated object store endpoint IPs (required to enable collector) |
| `OBJSTORE_ENDPOINT_PORT` | `443` | Port to monitor for object store traffic |
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

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_nfs_rpc_count_total` | Counter | `volume_id`, `nfs_operation` | Total RPC operations (read/write) |
| `crusoe_vm_nfs_rpc_timeouts_total` | Counter | `volume_id`, `nfs_operation` | Total RPC timeouts |
| `crusoe_vm_nfs_rpc_rtt_ms_total` | Counter | `volume_id`, `nfs_operation` | Total RTT time (ms) |
| `crusoe_vm_nfs_rpc_exe_ms_total` | Counter | `volume_id`, `nfs_operation` | Total execution time (ms) |
| `crusoe_vm_nfs_rpc_backlog` | Counter | `volume_id` | RPC backlog utilization (`bklog_u` from `xprt: tcp`) |
| `crusoe_vm_nfs_bytes_sent_total` | Counter | `volume_id`, `nfs_operation` | Total bytes sent (from mountstats) |
| `crusoe_vm_nfs_bytes_recv_total` | Counter | `volume_id`, `nfs_operation` | Total bytes received (from mountstats) |
| `crusoe_vm_nfs_stats_collection_errors_total` | Counter | - | Collection errors |

### Object Store Latency Collector (eBPF)

**Source:** `src/collectors/objstore-latency-collector.go` | **eBPF:** `ebpf/objstore_latency.c`

Measures object store (S3-compatible) request latency using eBPF kprobes on `tcp_sendmsg` / `tcp_cleanup_rbuf`, filtered to configured endpoint IPs. Also tracks TCP retransmissions via `tcp_retransmit_skb`. Enabled only when `OBJSTORE_ENDPOINT_IPS` is set.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_objectstore_latency_seconds` | Counter | `endpoint`, `operation` | Total request latency (seconds) |
| `crusoe_vm_objectstore_requests_total` | Counter | `endpoint`, `operation` | Total requests (one per HTTP response) |
| `crusoe_vm_objectstore_tcp_retransmits_total` | Counter | `endpoint`, `operation` | TCP retransmissions to object store |
| `crusoe_vm_objectstore_bytes_sent_total` | Counter | `endpoint`, `operation` | Total bytes sent to object store |
| `crusoe_vm_objectstore_bytes_recv_total` | Counter | `endpoint`, `operation` | Total bytes received from object store |
| `crusoe_vm_objectstore_latency_histogram_seconds` | Histogram | `endpoint`, `operation` | Latency histogram (20 geometric buckets, 0.1ms--25ms) |

### PromQL Examples

```promql
# NFS average latency per volume
rate(crusoe_vm_nfs_latency_seconds[5m]) / rate(crusoe_vm_nfs_requests_total[5m])

# NFS RPC timeout rate per volume
rate(crusoe_vm_nfs_rpc_timeouts_total[5m]) / rate(crusoe_vm_nfs_rpc_count_total[5m])

# NFS TCP retransmit rate
rate(crusoe_vm_nfs_tcp_retransmits_total[5m])

# Object store average latency per endpoint
rate(crusoe_vm_objectstore_latency_seconds[5m]) / rate(crusoe_vm_objectstore_requests_total[5m])

# Object store TCP retransmit rate
rate(crusoe_vm_objectstore_tcp_retransmits_total[5m])

# Disk write latency p99 (histogram)
histogram_quantile(0.99, rate(crusoe_vm_disk_write_latency_seconds[5m]))
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
│       ├── nfs-stats-collector.go               # NFS RPC stats from /proc/1/mountstats
│       ├── nfs-latency-collector.go             # NFS latency via eBPF kprobes
│       ├── objstore-latency-collector.go        # Object store latency via eBPF kprobes
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
