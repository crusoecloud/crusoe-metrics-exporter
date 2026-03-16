FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies including clang/llvm for eBPF
RUN apk add --no-cache git clang llvm lld linux-headers libbpf-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY src/ ./src/
COPY ebpf/ ./ebpf/

# Determine target architecture for eBPF compilation
# Docker buildx multi-platform builds run in containers with the target architecture
# So uname -m will correctly reflect the target platform
RUN echo "Detecting build architecture..." && \
    echo "TARGETPLATFORM: ${TARGETPLATFORM:-unset}" && \
    echo "TARGETARCH: ${TARGETARCH:-unset}" && \
    # In multi-platform builds, uname -m reflects the target architecture
    TARGETARCH=$(uname -m) && \
    echo "Detected architecture from uname -m: $TARGETARCH" && \
    if [ "$TARGETARCH" = "x86_64" ]; then \
        ARCH_DEFINE=__TARGET_ARCH_x86; \
        echo "Using x86 architecture define"; \
    elif [ "$TARGETARCH" = "aarch64" ]; then \
        ARCH_DEFINE=__TARGET_ARCH_arm64; \
        echo "Using arm64 architecture define"; \
    else \
        echo "Unsupported architecture: $TARGETARCH"; \
        echo "Available environment variables:"; \
        env | grep -E "(TARGET|PLATFORM|ARCH)" || echo "No architecture variables found"; \
        exit 1; \
    fi && \
    echo "Compiling eBPF programs for $TARGETARCH with $ARCH_DEFINE" && \
    clang -g -O2 -target bpf -D$ARCH_DEFINE \
        -I. \
        -c ebpf/objstore_latency.c -o ebpf/objstore_latency.o && \
    clang -g -O2 -target bpf -D$ARCH_DEFINE \
        -I. \
        -c ebpf/nfs_latency.c -o ebpf/nfs_latency.o && \
    clang -g -O2 -target bpf -D$ARCH_DEFINE \
        -I. \
        -c ebpf/disk_latency.c -o ebpf/disk_latency.o && \
    echo "Successfully compiled all eBPF programs for $TARGETARCH"

# Copy eBPF object files into src tree for go:embed (go:embed can't use .. paths)
# Must be relative to the package directory (src/collectors/)
RUN mkdir -p src/collectors/ebpf && \
    cp ebpf/objstore_latency.o src/collectors/ebpf/ && \
    cp ebpf/nfs_latency.o src/collectors/ebpf/ && \
    cp ebpf/disk_latency.o src/collectors/ebpf/

# Build the binary
RUN mkdir -p build/dist && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o build/dist/crusoe-metrics-exporter ./src

# Final stage
FROM alpine:3.19

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/build/dist/crusoe-metrics-exporter .

# Expose the metrics port
EXPOSE 9500

# Set default environment variables
ENV PORT=9500
ENV HOST_PROC_PATH=/host/proc

# Run the exporter
CMD ["./crusoe-metrics-exporter"]