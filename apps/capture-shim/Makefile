# apps/capture-shim/Makefile
#
# Cross-compile the capture-shim binary.
# The binary is symlinked under multiple names (terraform, aws, kubectl, etc.)

BINARY  = depose-shim
GO      = go
LDFLAGS = -s -w

# Target platforms
PLATFORMS = darwin-arm64 darwin-amd64 linux-arm64 linux-amd64

# Default shim binary list (docs/shim-installation.md)
SHIM_NAMES = terraform aws gh kubectl psql gcloud railway rm

.PHONY: all clean build-local build-cross install-shims

all: build-local

build-local:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) .

build-cross: $(PLATFORMS)

darwin-arm64:
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-arm64 .

darwin-amd64:
	GOOS=darwin GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-amd64 .

linux-arm64:
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-arm64 .

linux-amd64:
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-amd64 .

# Install shim symlinks in DEPOSE_BIN_DIR (default: ~/.depose/bin)
install-shims: build-local
	@DEPOSE_BIN_DIR=$${DEPOSE_BIN_DIR:-$$HOME/.depose/bin}; \
	mkdir -p $$DEPOSE_BIN_DIR; \
	cp $(BINARY) $$DEPOSE_BIN_DIR/$(BINARY); \
	chmod 755 $$DEPOSE_BIN_DIR/$(BINARY); \
	for name in $(SHIM_NAMES); do \
		ln -sf $$DEPOSE_BIN_DIR/$(BINARY) $$DEPOSE_BIN_DIR/$$name; \
	done; \
	echo "Shims installed to $$DEPOSE_BIN_DIR"; \
	echo "Add to PATH: export PATH=$$DEPOSE_BIN_DIR:\$$PATH"

clean:
	rm -f $(BINARY) $(BINARY)-*
