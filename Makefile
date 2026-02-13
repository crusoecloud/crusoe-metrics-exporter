.PHONY: build run docker-build docker-run clean test

APP_NAME=crusoe-metrics-exporter
DOCKER_IMAGE=metrics-exporter:latest
BUILD_DIR=build/dist

build:
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
	@echo "  build        - Build the Go binary"
	@echo "  run          - Build and run locally"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Build and run in Docker container"
	@echo "  clean        - Remove binary and Docker image"
	@echo "  test         - Run tests"
	@echo "  deps         - Download and tidy dependencies"
	@echo "  fmt          - Format Go code"
	@echo "  lint         - Run linter"
