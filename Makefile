VERSION := 0.1.0
LDFLAGS := -s -w -X main.Version=$(VERSION)
BINS := setup auth relay client ui
OUT := dist

.PHONY: all clean build-all

all: build-all

clean:
	rm -rf $(OUT)

# === Local build ===
build:
	@for bin in $(BINS); do \
		echo "  build phantom-$$bin"; \
		CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(OUT)/phantom-$$bin ./cmd/$$bin; \
	done

# === Cross-compile everything ===
build-all: \
	build-windows-amd64 build-windows-arm64 \
	build-linux-amd64 build-linux-arm64 build-linux-armv7 build-linux-armv6 \
	build-darwin-amd64 build-darwin-arm64 \
	build-freebsd-amd64 build-freebsd-arm64
	@echo ""
	@echo "=== All builds complete ==="
	@ls -lhS $(OUT)/*/ 2>/dev/null || ls -lhS $(OUT)/
	@echo ""

# --- Windows ---
build-windows-amd64:
	@echo "  windows/amd64"
	@mkdir -p $(OUT)/windows-amd64
	@for bin in $(BINS); do \
		GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(OUT)/windows-amd64/phantom-$$bin.exe ./cmd/$$bin; \
	done

build-windows-arm64:
	@echo "  windows/arm64"
	@mkdir -p $(OUT)/windows-arm64
	@for bin in $(BINS); do \
		GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(OUT)/windows-arm64/phantom-$$bin.exe ./cmd/$$bin; \
	done

# --- Linux ---
build-linux-amd64:
	@echo "  linux/amd64"
	@mkdir -p $(OUT)/linux-amd64
	@for bin in $(BINS); do \
		GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(OUT)/linux-amd64/phantom-$$bin ./cmd/$$bin; \
	done

build-linux-arm64:
	@echo "  linux/arm64"
	@mkdir -p $(OUT)/linux-arm64
	@for bin in $(BINS); do \
		GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(OUT)/linux-arm64/phantom-$$bin ./cmd/$$bin; \
	done

build-linux-armv7:
	@echo "  linux/armv7 (Raspberry Pi 3/4)"
	@mkdir -p $(OUT)/linux-armv7
	@for bin in $(BINS); do \
		GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(OUT)/linux-armv7/phantom-$$bin ./cmd/$$bin; \
	done

build-linux-armv6:
	@echo "  linux/armv6 (Raspberry Pi Zero)"
	@mkdir -p $(OUT)/linux-armv6
	@for bin in $(BINS); do \
		GOOS=linux GOARCH=arm GOARM=6 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(OUT)/linux-armv6/phantom-$$bin ./cmd/$$bin; \
	done

# --- macOS ---
build-darwin-amd64:
	@echo "  darwin/amd64 (Intel Mac)"
	@mkdir -p $(OUT)/darwin-amd64
	@for bin in $(BINS); do \
		GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(OUT)/darwin-amd64/phantom-$$bin ./cmd/$$bin; \
	done

build-darwin-arm64:
	@echo "  darwin/arm64 (Apple Silicon)"
	@mkdir -p $(OUT)/darwin-arm64
	@for bin in $(BINS); do \
		GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(OUT)/darwin-arm64/phantom-$$bin ./cmd/$$bin; \
	done

# --- FreeBSD ---
build-freebsd-amd64:
	@echo "  freebsd/amd64"
	@mkdir -p $(OUT)/freebsd-amd64
	@for bin in $(BINS); do \
		GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(OUT)/freebsd-amd64/phantom-$$bin ./cmd/$$bin; \
	done

build-freebsd-arm64:
	@echo "  freebsd/arm64"
	@mkdir -p $(OUT)/freebsd-arm64
	@for bin in $(BINS); do \
		GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" \
			-o $(OUT)/freebsd-arm64/phantom-$$bin ./cmd/$$bin; \
	done

# === Package into release archives ===
release: build-all
	@echo "=== Packaging releases ==="
	@mkdir -p $(OUT)/release
	@for dir in $(OUT)/*/; do \
		name=$$(basename $$dir); \
		if [ "$$name" != "release" ]; then \
			echo "  phantom-$(VERSION)-$$name"; \
			if echo "$$name" | grep -q windows; then \
				(cd $$dir && zip -q ../release/phantom-$(VERSION)-$$name.zip *); \
			else \
				tar -czf $(OUT)/release/phantom-$(VERSION)-$$name.tar.gz -C $$dir .; \
			fi \
		fi \
	done
	@echo ""
	@ls -lhS $(OUT)/release/
	@echo ""
	@echo "=== Release packages ready ==="

# === Tests ===
test:
	go test ./...

docker-test:
	docker compose down -v
	docker compose build --no-cache
	docker compose up -d
	sleep 8
	docker compose run --rm test
