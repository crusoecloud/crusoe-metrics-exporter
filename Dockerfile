FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY src/ ./src/

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
ENV DISKSTATS_PATH=/host/proc/diskstats
ENV MOUNTSTATS_PATH=/host/proc/self/mountstats

# Run the exporter
CMD ["./crusoe-metrics-exporter"]