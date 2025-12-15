.PHONY: build build-static build-all install clean test run fmt vet

BINARY_NAME=gasp
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
LDFLAGS=-ldflags "-X main.version=${VERSION}"
BUILD_DIR=.

build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/gasp

build-static:
	@echo "Building static $(BINARY_NAME) $(VERSION)..."
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/gasp

build-all:
	@echo "Building for multiple architectures..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)_linux_amd64 ./cmd/gasp
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)_linux_arm64 ./cmd/gasp
	@echo "Built binaries:"
	@ls -lh $(BUILD_DIR)/$(BINARY_NAME)_*

install: build
	@echo "Installing $(BINARY_NAME)..."
	sudo install -m 755 $(BINARY_NAME) /usr/local/bin/
	sudo mkdir -p /etc/gasp /var/lib/gasp
	@if [ -f configs/gasp.service ]; then \
		sudo install -m 644 configs/gasp.service /etc/systemd/system/; \
		sudo systemctl daemon-reload; \
		echo "Systemd service installed. Run: sudo systemctl enable --now gasp"; \
	else \
		echo "Note: configs/gasp.service not found, skipping systemd installation"; \
	fi

test:
	@echo "Running tests..."
	go test -v ./...

run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BINARY_NAME)

fmt:
	@echo "Formatting code..."
	gofmt -w .

vet:
	@echo "Vetting code..."
	go vet ./...

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME) $(BINARY_NAME)_*
	go clean
