# apps/verify/Makefile
# Cross-compile depose-verify for darwin/linux amd64+arm64

BINARY_NAME=depose-verify
VERSION?=0.1.0
BUILD_DIR=build
LDFLAGS=-s -w -X main.version=$(VERSION)

# Target platforms
PLATFORMS=darwin-arm64 darwin-amd64 linux-arm64 linux-amd64

.PHONY: all clean $(PLATFORMS)

all: $(PLATFORMS)

darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .

darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .

linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .

linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

build-local:
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) .