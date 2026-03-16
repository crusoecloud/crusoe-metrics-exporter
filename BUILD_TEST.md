# Build, Test & Debug Guide

## Prerequisites

- Go 1.23+
- Lima VM named `ebpf-builder` (for eBPF cross-compilation on macOS). 
  - limactl create --memory 4 --cpus 4 --name=ebpf-builder template://ubuntu-24.04
- `kubectl` configured for the target cluster
- `bpftool` available inside the container (bundled in the image)

## Project Structure

```
ebpf/                          # eBPF C source files
  nfs_latency.c                # NFS latency kprobes (tcp_sendmsg / tcp_recvmsg)
  objstore_latency.c           # Object store latency kprobes
  disk_latency.c               # Disk I/O latency kprobes (blk_mq_start_request / blk_mq_end_request)
  vmlinux.h                    # Kernel type definitions for CO-RE
  *.h                          # Per-collector header files

src/collectors/ebpf/           # Compiled eBPF .o files (go:embed'd into Go binary)
src/collectors/                # Go collector implementations
src/main.go                    # Entry point, registers all collectors
```

## Building

### Go binary (requires pre-compiled eBPF objects)

```bash
make test
make build
```

### eBPF programs only

On a Linux machine with clang and libbpf-dev:

```bash
make ebpf-compile
```

### eBPF compilation via Lima VM (macOS)

The mounted host directory is read-only in Lima. Copy the project to a writable
temp directory inside the VM, compile there, then copy the `.o` files back.

```bash
# Clean old copy and sync project into the VM
limactl shell ebpf-builder sh -c 'rm -rf /tmp/crusoe-metrics-exporter'
limactl copy -r . ebpf-builder:/tmp/crusoe-metrics-exporter

# Compile all eBPF programs inside the VM
limactl shell ebpf-builder sh -c \
  'cd /tmp/crusoe-metrics-exporter && make ebpf-clean && make ebpf-compile'

# Copy compiled objects back to the host
limactl copy ebpf-builder:/tmp/crusoe-metrics-exporter/src/collectors/ebpf/nfs_latency.o       src/collectors/ebpf/nfs_latency.o
limactl copy ebpf-builder:/tmp/crusoe-metrics-exporter/src/collectors/ebpf/objstore_latency.o   src/collectors/ebpf/objstore_latency.o
limactl copy ebpf-builder:/tmp/crusoe-metrics-exporter/src/collectors/ebpf/disk_latency.o       src/collectors/ebpf/disk_latency.o
```

### Docker image (compiles eBPF inside the container)

```bash
make docker-build
```

## Running Tests

```bash
make test
```

## Versioning and Releasing

1. Bump the version in `VERSION`.
2. Commit and push. The GitLab CI pipeline builds and pushes the Docker image
   automatically for `main`, tags, MRs, and the `ebpf-https` branch.

```bash
# Example
echo "0.0.31" > VERSION
# Update daemonset image tag to match
git add -A && git commit -m "Bump version to 0.0.31"
git push
```

## Deploying to a Cluster

Apply the daemonset after the CI pipeline has pushed the image:

```bash
kubectl apply -f watch-agent-daemonset.yaml
```

Verify the pod is running:

```bash
kubectl get pods -n crusoe-system | grep crusoe-watch-agent
```

## Debugging on the Cluster

All commands below assume a single `crusoe-watch-agent` pod. Adjust if there
are multiple nodes.

```bash
# Shorthand for the pod name
POD=$(kubectl get pods -n crusoe-system -o name | grep crusoe-watch-agent | head -1)
CTR="-c crusoe-metrics-exporter"
NS="-n crusoe-system"
```

### Check logs

```bash
kubectl logs $NS $POD $CTR 2>&1 | grep -i "nfs\|error\|fail\|warn"
```

### Scrape metrics endpoint

```bash
kubectl exec $NS $POD $CTR -it -- wget http://localhost:9500/metrics -O - -q | grep ^crusoe_vm_
```

Filter by collector:

```bash
# Disk metrics
... | grep crusoe_vm_disk

# NFS metrics
... | grep crusoe_vm_nfs

# Object store metrics
... | grep crusoe_vm_objstore
```

### Inspect eBPF maps with bpftool

#### List all loaded eBPF maps

```bash
kubectl exec $NS $POD $CTR -it -- bpftool map show
```

Typical maps and what they contain:

| Map Name             | Type  | Description                                       |
|----------------------|-------|---------------------------------------------------|
| `nfs_server_ips`     | array | NFS server IPs the probe is filtering on           |
| `nfs_latency_by_`   | hash  | Aggregated NFS latency stats keyed by dest IP      |
| `active_requests`    | hash  | In-flight TCP send timestamps (NFS or objstore)    |
| `nfs_debug_counters` | array | Debug hit counters for NFS probe code paths        |
| `config_map`         | array | Target port configuration                          |
| `disk_io_stats`      | hash  | Per-device disk I/O latency stats                  |
| `active_disk_reques` | hash  | In-flight block I/O requests                       |
| `objstore_latenc`    | hash  | Object store latency stats keyed by dest IP        |

#### Dump a specific map by ID

```bash
# Find the map ID from 'bpftool map show', then:
kubectl exec $NS $POD $CTR -it -- bpftool map dump id <MAP_ID> | head -30
```

#### Verify NFS server IPs are populated

```bash
kubectl exec $NS $POD $CTR -it -- bpftool map show | grep nfs_server_ips
# note the ID, then:
kubectl exec $NS $POD $CTR -it -- bpftool map dump id <ID>
```

Each non-zero value is a little-endian IPv4 address. To decode: value
`0a 01 01 c8` = `10.1.1.200`.

#### Check NFS debug counters

The `nfs_debug_counters` array map tracks how far each TCP event gets through
the eBPF probe logic. Dump it after a few seconds of NFS traffic:

```bash
kubectl exec $NS $POD $CTR -it -- bpftool map show | grep nfs_debug
kubectl exec $NS $POD $CTR -it -- bpftool map dump id <ID>
```

Counter index meanings:

| Index | Counter                                              | What to expect     |
|-------|------------------------------------------------------|--------------------|
| 0     | `tcp_sendmsg_entry` called                           | Very large         |
| 1     | Passed AF_INET (IPv4) check                          | Large              |
| 2     | Passed target port (2049) check                      | Much smaller       |
| 3     | Passed `is_nfs_server` check (added to active_requests) | Same as 2       |
| 4     | `tcp_recvmsg_entry` called                           | Very large         |
| 5     | Found matching `active_request` for this socket      | Should be > 0      |
| 6     | `record_latency` called                              | Same as 5          |
| 7     | Existing stats updated (repeat IP)                   | Growing            |
| 8     | New stats created (first time for an IP)             | Small (once/IP)    |

**Diagnosis guide:**

- `[3] > 0` but `[5] = 0`: sends match but recvmsg never finds them.
  Socket pointer mismatch between send and receive paths.
- `[5] > 0` but `[6] = 0`: match found but `record_latency` not reached.
  Possible verifier issue or code path bug.
- `[6] > 0` but `nfs_latency_by_ip` is empty: map update failing silently.
  Check if `BPF_NOEXIST` vs `BPF_ANY` flag is correct.

### List attached kprobes

```bash
kubectl exec $NS $POD $CTR -it -- bpftool prog show | grep -A2 -E "tcp_sendmsg|tcp_recvmsg|blk_mq"
```

### Check host NFS mounts (from inside the container)

The host's `/proc` is mounted at `/host/proc`:

```bash
kubectl exec $NS $POD $CTR -it -- cat /host/proc/1/mounts | grep nfs
```

Note: /host/proc/self/mounts is for in-container mounts, /host/proc/1/mounts is for init, the node's mounts.

## Environment Variables

| Variable                  | Default                      | Description                                      |
|---------------------------|------------------------------|--------------------------------------------------|
| `PORT`                       | `9500`        | Metrics HTTP server port                                  |
| `HOST_PROC_PATH`             | `/host/proc`  | Root of the host's `/proc` (auto-detected if not set)     |
| `NFS_SERVER_IPS`             | (auto-detected from mounts) | Comma-separated NFS server IPs to track |
| `NFS_TARGET_PORTS`           | `2049`        | Comma-separated NFS ports                                 |
| `NFS_PROTOCOLS`              | `tcp,udp`     | Protocols to track                                        |
| `NFS_ENABLE_VOLUME_ID`       | `true`        | Resolve volume IDs from mount info                        |
| `NFS_MOUNT_REFRESH_INTERVAL` | `30s`         | How often to re-scan mounts for new NFS IPs               |
| `OBJSTORE_ENDPOINT_IPS`      | (none)        | Comma-separated object store server IPs                   |
| `OBJSTORE_ENDPOINT_PORT`     | `443`         | Object store target port                                  |

Note: NFS UDP hasn't been implemented. It's assumed we use NFS4 everywhere.

## Collector Architecture

All three collectors use eBPF kprobes:

- **Disk**: `blk_mq_start_request` / `blk_mq_end_request` - measures block I/O latency per device
- **NFS**: `tcp_sendmsg` / `tcp_recvmsg` - measures NFS RPC round-trip latency per server IP
- **Object Store**: `tcp_sendmsg` / `tcp_recvmsg` (kretprobe) - measures HTTP request latency to object store endpoints

Each collector:
1. Loads a pre-compiled eBPF `.o` file via `go:embed`
2. Creates an `ebpf.Collection` with its own independent maps
3. Attaches kprobes to kernel functions
4. On each Prometheus scrape, reads the eBPF maps and emits metrics
