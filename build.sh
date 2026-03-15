#!/bin/bash
# Cross-compile phantom for all platforms
set -e

VERSION="0.1.0"
LDFLAGS="-s -w"
BINS="setup auth relay client ui"
OUT="dist"

rm -rf "$OUT"

platforms=(
    "windows amd64 .exe"
    "windows arm64 .exe"
    "linux amd64 "
    "linux arm64 "
    "linux arm:7 "
    "linux arm:6 "
    "darwin amd64 "
    "darwin arm64 "
    "freebsd amd64 "
    "freebsd arm64 "
)

for platform in "${platforms[@]}"; do
    read -r os arch ext <<< "$platform"

    # Handle arm versions
    goarm=""
    goarch="$arch"
    label="$os-$arch"
    if [[ "$arch" == arm:* ]]; then
        goarm="${arch#arm:}"
        goarch="arm"
        label="$os-armv$goarm"
    fi

    echo "  building $label..."
    dir="$OUT/$label"
    mkdir -p "$dir"

    for bin in $BINS; do
        GOOS=$os GOARCH=$goarch GOARM=$goarm CGO_ENABLED=0 \
            go build -ldflags="$LDFLAGS" -o "$dir/phantom-$bin$ext" ./cmd/$bin
    done
done

echo ""
echo "=== Build complete ==="
echo ""

# Show sizes
for dir in "$OUT"/*/; do
    name=$(basename "$dir")
    total=$(du -sh "$dir" | awk '{print $1}')
    relay_size=$(ls -lh "$dir"phantom-relay* 2>/dev/null | awk '{print $5}')
    printf "  %-20s total: %-6s  relay: %s\n" "$name" "$total" "$relay_size"
done

echo ""
echo "=== Packaging ==="
mkdir -p "$OUT/release"

for dir in "$OUT"/*/; do
    name=$(basename "$dir")
    [ "$name" = "release" ] && continue
    archive="phantom-$VERSION-$name"
    if echo "$name" | grep -q windows; then
        (cd "$dir" && zip -q "../release/$archive.zip" *)
        echo "  $archive.zip"
    else
        tar -czf "$OUT/release/$archive.tar.gz" -C "$dir" .
        echo "  $archive.tar.gz"
    fi
done

echo ""
ls -lhS "$OUT/release/"
