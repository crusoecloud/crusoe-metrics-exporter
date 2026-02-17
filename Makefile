.PHONY: build build-amd64 build-arm64 build-all run docker-build docker-build-multiarch docker-build-push docker-build-push-amd64 docker-build-push-arm64 docker-manifest-push docker-buildx-setup docker-run clean test deps fmt lint help

APP_NAME=crusoe-metrics-exporter
DOCKER_IMAGE=metrics-exporter:latest
BUILD_DIR=build/dist
PLATFORMS=linux/amd64,linux/arm64

# Build for amd64 (default for backward compatibility)
build: build-amd64

# Build for specific architectures
build-amd64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-amd64 ./src

build-arm64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(APP_NAME)-arm64 ./src

# Build for both architectures
build-all: build-amd64 build-arm64

run: build
	./$(BUILD_DIR)/$(APP_NAME)-amd64

# Single-platform Docker build (backward compatible)
docker-build:
	docker build -t $(DOCKER_IMAGE) .

# Setup Docker buildx for multi-platform builds
docker-buildx-setup:
	@docker buildx version >/dev/null 2>&1 || (echo "Docker buildx not available" && exit 1)
	@docker buildx inspect multiarch-builder >/dev/null 2>&1 || \
		docker buildx create --name multiarch-builder --use
	@docker buildx inspect --bootstrap

# Multi-platform Docker build
docker-build-multiarch: docker-buildx-setup
	docker buildx build \
		--platform $(PLATFORMS) \
		--tag $(DOCKER_IMAGE) \
		--load \
		.

# Multi-platform Docker build and push (requires DOCKER_REGISTRY to be set)
docker-build-push: docker-buildx-setup
	@if [ -z "$(DOCKER_REGISTRY)" ]; then \
		echo "Error: DOCKER_REGISTRY must be set (e.g., make docker-build-push DOCKER_REGISTRY=myregistry.com/myproject)"; \
		exit 1; \
	fi
	docker buildx build \
		--platform $(PLATFORMS) \
		--tag $(DOCKER_REGISTRY)/$(DOCKER_IMAGE) \
		--push \
		.

# Build and push individual architecture images (workaround for QEMU segfaults on ARM Macs)
docker-build-push-arm64: docker-buildx-setup
	@if [ -z "$(DOCKER_REGISTRY)" ]; then \
		echo "Error: DOCKER_REGISTRY must be set"; \
		exit 1; \
	fi
	docker buildx build \
		--platform linux/arm64 \
		--tag $(DOCKER_REGISTRY)/$(DOCKER_IMAGE)-arm64 \
		--push \
		.

docker-build-push-amd64: docker-buildx-setup
	@if [ -z "$(DOCKER_REGISTRY)" ]; then \
		echo "Error: DOCKER_REGISTRY must be set"; \
		exit 1; \
	fi
	docker buildx build \
		--platform linux/amd64 \
		--tag $(DOCKER_REGISTRY)/$(DOCKER_IMAGE)-amd64 \
		--push \
		.

# Create and push multi-arch manifest from separately built images
docker-manifest-push:
	@if [ -z "$(DOCKER_REGISTRY)" ]; then \
		echo "Error: DOCKER_REGISTRY must be set"; \
		exit 1; \
	fi
	docker manifest create $(DOCKER_REGISTRY)/$(DOCKER_IMAGE) \
		--amend $(DOCKER_REGISTRY)/$(DOCKER_IMAGE)-amd64 \
		--amend $(DOCKER_REGISTRY)/$(DOCKER_IMAGE)-arm64
	docker manifest push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE)

docker-run: docker-build
	docker run -p 9500:9500 \
		-v /proc:/host/proc:ro \
		--privileged \
		$(DOCKER_IMAGE)

clean:
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
	@echo "  build                     - Build the Go binary for amd64 (default)"
	@echo "  build-amd64               - Build the Go binary for amd64"
	@echo "  build-arm64               - Build the Go binary for arm64"
	@echo "  build-all                 - Build for both amd64 and arm64"
	@echo "  run                       - Build and run locally"
	@echo "  docker-build              - Build Docker image for current platform"
	@echo "  docker-build-multiarch    - Build multi-platform Docker image (amd64 + arm64)"
	@echo "  docker-build-push         - Build and push multi-platform image (requires DOCKER_REGISTRY)"
	@echo "  docker-build-push-amd64   - Build and push amd64 image only (requires DOCKER_REGISTRY)"
	@echo "  docker-build-push-arm64   - Build and push arm64 image only (requires DOCKER_REGISTRY)"
	@echo "  docker-manifest-push      - Create and push multi-arch manifest (requires DOCKER_REGISTRY)"
	@echo "  docker-buildx-setup       - Setup Docker buildx for multi-platform builds"
	@echo "  docker-run                - Build and run in Docker container"
	@echo "  clean                     - Remove binary and Docker image"
	@echo "  test                      - Run tests"
	@echo "  deps                      - Download and tidy dependencies"
	@echo "  fmt                       - Format Go code"
	@echo "  lint                      - Run linter"
