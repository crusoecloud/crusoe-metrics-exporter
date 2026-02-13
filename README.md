# Crusoe Metrics Exporter

A Prometheus-compatible metrics exporter that exposes disk and NFS statistics from a VM. Written in pure Go with no external script dependencies.

## Features

- Native Go implementation (no shell scripts)
- Modular collector architecture
- Prometheus text exposition format
- Health check endpoint
- Error tracking metrics per collector
- Containerized deployment
- Minimal resource footprint

---

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Collectors](#collectors)
- [Project Structure](#project-structure)
- [Build & Run](#build--run)
- [Adding Custom Collectors](#adding-custom-collectors)

---

## Quick Start

### Using Docker Compose (Recommended)

```bash
docker-compose up -d
```

Access metrics at: http://localhost:9500/metrics

### Using Docker

```bash
docker build -t metrics-exporter .

docker run -p 9500:9500 \
  -v /proc:/host/proc:ro \
  --privileged \
  metrics-exporter
```

### Using Make

```bash
make docker-run    # Build and run in Docker
make build         # Build Go binary to build/dist/
make run           # Build and run locally
```

---

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PORT` | `9500` | HTTP server port |
| `DISKSTATS_PATH` | `/host/proc/diskstats` | Path to diskstats file |
| `MOUNTSTATS_PATH` | `/host/proc/self/mountstats` | Path to mountstats file |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`, `fatal`) |

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `/metrics` | Prometheus metrics |
| `/health` | Health check (returns `OK`) |

---

## Collectors

> **Note:** All metrics are prefixed with `crusoe_vm_`. This prefix is defined in `src/collectors/constants.go` as `MetricPrefix`.

### Disk Stats Collector

**Source:** `src/collectors/disk-stats-collector.go`

Collects disk I/O statistics from `/proc/diskstats`. Filters for main disk devices (`vda`, `vdb`, etc.) and excludes partitions.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_disk_reads_completed_total` | Counter | `device` | Total reads completed |
| `crusoe_vm_disk_read_time_ms_total` | Counter | `device` | Total time spent reading (ms) |
| `crusoe_vm_disk_writes_completed_total` | Counter | `device` | Total writes completed |
| `crusoe_vm_disk_write_time_ms_total` | Counter | `device` | Total time spent writing (ms) |
| `crusoe_vm_disk_stats_collection_errors_total` | Counter | - | Collection errors |

### NFS Stats Collector

**Source:** `src/collectors/nfs-stats-collector.go`

Collects NFS RPC statistics from `/proc/self/mountstats`. Extracts volume IDs from mount paths and tracks READ/WRITE operations.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `crusoe_vm_nfs_rpc_count_total` | Counter | `nfs_volume_id`, `nfs_operation` | Total RPC operations |
| `crusoe_vm_nfs_rpc_rtt_ms_total` | Counter | `nfs_volume_id`, `nfs_operation` | Total RTT time (ms) |
| `crusoe_vm_nfs_rpc_exe_ms_total` | Counter | `nfs_volume_id`, `nfs_operation` | Total execution time (ms) |
| `crusoe_vm_nfs_stats_collection_errors_total` | Counter | - | Collection errors |

---

## Project Structure

```
.
├── src/
│   ├── main.go                              # Entry point, HTTP server, collector registration
│   ├── log/                                 # Logging package
│   │   └── log.go                           # Logrus-based logger with level support
│   └── collectors/                          # All collector implementations
│       ├── constants.go                     # Shared constants (MetricPrefix)
│       ├── disk-stats-collector.go          # Disk I/O metrics
│       └── nfs-stats-collector.go           # NFS RPC metrics
├── build/
│   └── dist/                                # Build output directory (generated)
├── go.mod                                   # Go module definition
├── go.sum                                   # Dependency checksums
├── Dockerfile                               # Container build
├── docker-compose.yaml                      # Docker Compose config
├── Makefile                                 # Build automation
├── VERSION                                  # Version file
└── README.md
```

---

## Build & Run

### Prerequisites

- Go 1.23+
- Docker (for containerized deployment)
- Make (optional)

### Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build binary to `build/dist/crusoe-metrics-exporter` |
| `make run` | Build and run locally |
| `make docker-build` | Build Docker image |
| `make docker-run` | Build and run in Docker |
| `make test` | Run tests |
| `make fmt` | Format Go code |
| `make lint` | Run linter |
| `make deps` | Download and tidy dependencies |
| `make clean` | Remove build artifacts and Docker image |

### Manual Build

```bash
go mod download
go build -o build/dist/crusoe-metrics-exporter ./src
./build/dist/crusoe-metrics-exporter
```

---

## Adding Custom Collectors

This section is for contributors who want to add new metrics collectors.

### Step 1: Create Collector File

Create a new file in `src/collectors/` following the naming convention `<name>-collector.go`:

```go
// src/collectors/my-custom-collector.go
package collectors

import (
    "github.com/prometheus/client_golang/prometheus"
)

type MyCustomCollector struct {
    // Configuration fields
    configPath string
    
    // Metric descriptors
    myMetric         *prometheus.Desc
    collectionErrors *prometheus.Desc
}

func NewMyCustomCollector(configPath string) *MyCustomCollector {
    return &MyCustomCollector{
        configPath: configPath,
        myMetric: prometheus.NewDesc(
            MetricPrefix + "my_metric_total",    // MUST use MetricPrefix constant
            "Description of what this measures", // Help text
            []string{"label1", "label2"},        // Label names
            nil,                                 // Constant labels
        ),
        collectionErrors: prometheus.NewDesc(
            MetricPrefix + "my_custom_collection_errors_total",
            "Total errors during collection",
            nil,
            nil,
        ),
    }
}

// Describe implements prometheus.Collector
func (c *MyCustomCollector) Describe(ch chan<- *prometheus.Desc) {
    ch <- c.myMetric
    ch <- c.collectionErrors
}

// Collect implements prometheus.Collector
func (c *MyCustomCollector) Collect(ch chan<- prometheus.Metric) {
    errorCount := 0.0
    
    // Your collection logic here
    // Parse files, call APIs, etc.
    
    value := 42.0 // Example value
    ch <- prometheus.MustNewConstMetric(
        c.myMetric,
        prometheus.CounterValue,  // or GaugeValue
        value,
        "label1_value", "label2_value",
    )
    
    ch <- prometheus.MustNewConstMetric(
        c.collectionErrors,
        prometheus.CounterValue,
        errorCount,
    )
}
```

### Step 2: Register in main.go

Add your collector to `src/main.go`:

```go
import (
    "metrics-exporter/src/collectors"
    // ...
)

func main() {
    // ... existing config ...
    
    // Add your config
    myConfigPath := os.Getenv("MY_CONFIG_PATH")
    if myConfigPath == "" {
        myConfigPath = "/default/path"
    }
    
    // Create and register
    myCollector := collectors.NewMyCustomCollector(myConfigPath)
    prometheus.MustRegister(myCollector)
    
    // ... rest of main ...
}
```

### Best Practices

1. **Metric Prefix (REQUIRED)**
   - **All metrics MUST use the `MetricPrefix` constant** defined in `src/collectors/constants.go`
   - Current prefix: `crusoe_vm_`
   - Example: `MetricPrefix + "my_metric_total"` → `crusoe_vm_my_metric_total`

2. **Naming Conventions**
   - File: `<name>-collector.go` (kebab-case)
   - Struct: `<Name>StatsCollector` (PascalCase)
   - Constructor: `New<Name>StatsCollector()`
   - Metrics: `MetricPrefix + "<subsystem>_<name>_<unit>_total"` for counters

3. **Error Handling**
   - Always include a `collectionErrors` metric
   - Use `log.Errorf()` for critical errors, `log.Warnf()` for recoverable issues
   - Return partial data when possible

4. **Labels**
   - Keep label cardinality low (avoid high-cardinality values like timestamps)
   - Use consistent label names across collectors
   - Document all labels in the metric description

5. **Performance**
   - Use `bufio.Scanner` for file parsing
   - Compile regexes once in the constructor, not in `Collect()`
   - Avoid allocations in hot paths

6. **Testing**
   - Create test files in `src/collectors/` named `<name>-collector_test.go`
   - Test with mock data files
   - Test error conditions

### Collector Interface

All collectors must implement the `prometheus.Collector` interface:

```go
type Collector interface {
    Describe(chan<- *Desc)
    Collect(chan<- Metric)
}
```

- **`Describe`**: Send all metric descriptors to the channel (called once at registration)
- **`Collect`**: Gather current metric values and send to channel (called on each scrape)

---

## Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'crusoe-metrics'
    static_configs:
      - targets: ['localhost:9500']
    scrape_interval: 15s
```

---

## License

MIT
