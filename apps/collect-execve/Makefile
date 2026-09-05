# apps/collect-execve/Makefile
# Cross-compile depose-collect-execve for linux amd64+arm64.
#
# Linux only, on purpose. The collector compiles on darwin (the
# build-tagged stub in probe/probe_other.go keeps it compiling, and CI
# checks that) but it refuses to start there, because macOS has no
# capture surface DEPOSE can use. Shipping a darwin binary would mean
# handing someone an executable whose only behaviour is to fail, which is
# the "stub that pretends" docs/decisions.md D18 rules out.

BINARY_NAME=depose-collect-execve
VERSION?=0.1.0
BUILD_DIR=build
LDFLAGS=-s -w -X main.version=$(VERSION)

PLATFORMS=linux-arm64 linux-amd64

.PHONY: all clean test build-local $(PLATFORMS)

all: $(PLATFORMS)

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
