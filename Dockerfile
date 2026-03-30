# Stage 1: Compile eBPF programs natively (no QEMU) for both architectures
# clang -target bpf cross-compiles BPF bytecode without needing the target platform
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS ebpf-builder

WORKDIR /app

RUN apk add --no-cache clang llvm lld linux-headers libbpf-dev

COPY ebpf/ ./ebpf/

RUN chmod +x ebpf/compile.sh && sh ebpf/compile.sh

# Stage 2: Build Go binary natively via cross-compilation (no QEMU)
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

ARG TARGETARCH

WORKDIR /app

RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY src/ ./src/

# Copy the correct eBPF objects for the target architecture into the go:embed path
COPY --from=ebpf-builder /app/ebpf/ ./ebpf/
RUN mkdir -p src/collectors/ebpf && \
    for f in ebpf/*_${TARGETARCH}.o; do \
        base=$(basename "$f" _${TARGETARCH}.o); \
        cp "$f" "src/collectors/ebpf/${base}.o"; \
    done

# Build the binary (cross-compile via GOARCH, no QEMU needed)
RUN mkdir -p build/dist && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -a -installsuffix cgo -o build/dist/crusoe-metrics-exporter ./src

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