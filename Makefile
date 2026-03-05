.PHONY: build run docker-build docker-run clean test ebpf-compile ebpf-clean

APP_NAME=crusoe-metrics-exporter
DOCKER_IMAGE=metrics-exporter:latest
BUILD_DIR=build/dist

CLANG ?= clang
OBJSTORE_EBPF_SRC = ebpf/objstore_latency.c
OBJSTORE_EBPF_OBJ = src/collectors/ebpf/objstore_latency.o
NFS_EBPF_SRC = ebpf/nfs_latency.c
NFS_EBPF_OBJ = src/collectors/ebpf/nfs_latency.o
DISK_EBPF_SRC = ebpf/disk_latency.c
DISK_EBPF_OBJ = src/collectors/ebpf/disk_latency.o
EBPF_OBJS = $(OBJSTORE_EBPF_OBJ) $(NFS_EBPF_OBJ) $(DISK_EBPF_OBJ)

EBPF_DEBUG ?= 0# If >0, drop some debug crumbs into the eBPF code

ebpf-compile: $(EBPF_OBJS)

$(OBJSTORE_EBPF_OBJ): $(OBJSTORE_EBPF_SRC) ebpf/objstore_latency.h ebpf/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include/bpf -I. \
		-c $(OBJSTORE_EBPF_SRC) -o $(OBJSTORE_EBPF_OBJ)

$(NFS_EBPF_OBJ): $(NFS_EBPF_SRC) ebpf/nfs_latency.h ebpf/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include/bpf -I. \
		-c $(NFS_EBPF_SRC) -o $(NFS_EBPF_OBJ)

$(DISK_EBPF_OBJ): $(DISK_EBPF_SRC) ebpf/disk_latency.h ebpf/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include/bpf -I. \
		-c $(DISK_EBPF_SRC) -o $(DISK_EBPF_OBJ)

ebpf-clean:
	rm -f src/collectors/ebpf/*.o

build: ebpf-compile
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) ./src

run: build
	./$(BUILD_DIR)/$(APP_NAME)

docker-build:
	docker build -t $(DOCKER_IMAGE) .

docker-run: docker-build
	docker run -p 9500:9500 \
		-v /proc:/host/proc:ro \
		--privileged \
		$(DOCKER_IMAGE)

clean: ebpf-clean
	rm -rf build
	docker rmi $(DOCKER_IMAGE) 2>/dev/null || true

test:
	go test -v ./...

deps:
	go mod download
	go mod tidy

fmt:
	go fmt ./...

lint:
	golangci-lint run

help:
	@echo "Available targets:"
	@echo "  build        - Build the Go binary"
	@echo "  run          - Build and run locally"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Build and run in Docker container"
	@echo "  clean        - Remove binary and Docker image"
	@echo "  test         - Run tests"
	@echo "  deps         - Download and tidy dependencies"
	@echo "  fmt          - Format Go code"
	@echo "  lint         - Run linter"
