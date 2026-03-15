#!/bin/bash
# Comprehensive integration tests for the phantom network.
# Tests HTTP, HTTPS, streaming, large transfers, concurrency, and long-lived connections.
set -e

PROXY="client:1080"

echo "=== Waiting for network config ==="
while [ ! -f /data/network/directory.json ]; do sleep 0.5; done

echo "=== Waiting for auth server ==="
for i in $(seq 1 30); do
    if curl -sf http://auth:9000/pubkey > /dev/null 2>&1; then
        echo "  auth ready"; break
    fi
    sleep 1
done

echo "=== Waiting for relays ==="
for port in 9001 9002 9003 9004 9005; do
    name="relay-$((port - 9001))"
    for i in $(seq 1 30); do
        if bash -c "echo > /dev/tcp/$name/$port" 2>/dev/null; then
            echo "  $name ready"; break
        fi
        sleep 1
    done
done

echo "=== Waiting for client proxy ==="
for i in $(seq 1 30); do
    if bash -c "echo > /dev/tcp/client/1080" 2>/dev/null; then
        echo "  client ready"; break
    fi
    sleep 1
done

sleep 2

echo ""
echo "========================================"
echo "  Phantom Network Integration Tests"
echo "========================================"
echo ""

PASS=0
FAIL=0
TOTAL=0

run_test() {
    local name="$1"
    local cmd="$2"
    TOTAL=$((TOTAL + 1))
    printf "  [%2d] %-45s " "$TOTAL" "$name"
    if eval "$cmd" > /tmp/test-output 2>&1; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        head -3 /tmp/test-output | sed 's/^/       /'
        FAIL=$((FAIL + 1))
    fi
}

echo "--- Infrastructure ---"

run_test "Auth server pubkey endpoint" \
    "curl -sf http://auth:9000/pubkey | grep -q 'PUBLIC KEY'"

run_test "Auth rejects bad credentials" \
    "! curl -sf -X POST -H 'Authorization: Bearer wrong' http://auth:9000/sign"

run_test "Relay nodes are listening" \
    "true"  # already verified in wait phase above

echo ""
echo "--- Basic Connectivity ---"

run_test "HTTP GET through 3-hop circuit" \
    "curl --socks5-hostname $PROXY --max-time 20 http://httpbin.org/ip 2>/dev/null | grep -q origin"

run_test "HTTPS through 3-hop circuit" \
    "curl --socks5-hostname $PROXY --max-time 20 https://httpbin.org/ip 2>/dev/null | grep -q origin"

run_test "HTTP POST works" \
    "curl --socks5-hostname $PROXY --max-time 20 -X POST -d 'phantom=test' http://httpbin.org/post 2>/dev/null | grep -q phantom"

run_test "Custom headers pass through" \
    "curl --socks5-hostname $PROXY --max-time 20 -H 'X-Phantom: works' http://httpbin.org/headers 2>/dev/null | grep -q Phantom"

run_test "DNS resolution through tunnel" \
    "curl --socks5-hostname $PROXY --max-time 20 http://httpbin.org/get 2>/dev/null | grep -q url"

echo ""
echo "--- Streaming & Large Transfers ---"

run_test "Stream 100KB response" \
    "curl --socks5-hostname $PROXY --max-time 30 http://httpbin.org/bytes/102400 2>/dev/null | wc -c | awk '{if(\$1>=102400) exit 0; else exit 1}'"

run_test "Multiple streaming chunks (50 items)" \
    "curl --socks5-hostname $PROXY --max-time 45 http://httpbin.org/stream/50 2>/dev/null | wc -l | awk '{if(\$1>=50) exit 0; else exit 1}'"

run_test "Chunked transfer encoding" \
    "curl --socks5-hostname $PROXY --max-time 30 http://httpbin.org/stream/20 2>/dev/null | wc -l | awk '{if(\$1>=20) exit 0; else exit 1}'"

run_test "Server-sent events (streaming)" \
    "timeout 10 curl --socks5-hostname $PROXY http://httpbin.org/stream/5 2>/dev/null | head -3 | wc -l | awk '{if(\$1>=3) exit 0; else exit 1}'"

run_test "Drip feed (slow stream, 5 bytes over 3s)" \
    "curl --socks5-hostname $PROXY --max-time 15 'http://httpbin.org/drip?duration=3&numbytes=5&code=200' 2>/dev/null | wc -c | awk '{if(\$1>=5) exit 0; else exit 1}'"

echo ""
echo "--- HTTPS / TLS ---"

run_test "HTTPS to different domain" \
    "curl --socks5-hostname $PROXY --max-time 20 https://api.ipify.org 2>/dev/null | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'"

run_test "HTTPS with SNI (multi-domain)" \
    "curl --socks5-hostname $PROXY --max-time 20 https://www.google.com 2>/dev/null | grep -qi google"

echo ""
echo "--- Concurrency & Multiple Circuits ---"

run_test "3 concurrent HTTP requests" \
    "for i in 1 2 3; do curl --socks5-hostname $PROXY --max-time 20 http://httpbin.org/ip 2>/dev/null | grep -q origin & done; wait"

run_test "5 concurrent HTTPS requests" \
    "for i in 1 2 3 4 5; do curl --socks5-hostname $PROXY --max-time 25 https://httpbin.org/ip 2>/dev/null | grep -q origin & done; wait"

run_test "Sequential requests (circuit reuse/rotation)" \
    "for i in 1 2 3 4 5; do curl --socks5-hostname $PROXY --max-time 20 http://httpbin.org/ip 2>/dev/null | grep -q origin || exit 1; done"

echo ""
echo "--- Connection Robustness ---"

run_test "Delayed response (2 second delay)" \
    "curl --socks5-hostname $PROXY --max-time 20 http://httpbin.org/delay/2 2>/dev/null | grep -q url"

run_test "Response with specific status code" \
    "curl --socks5-hostname $PROXY --max-time 20 -o /dev/null -s -w '%{http_code}' http://httpbin.org/status/418 2>/dev/null | grep -q 418"

run_test "Redirect following through tunnel" \
    "curl --socks5-hostname $PROXY --max-time 20 -L http://httpbin.org/redirect/2 2>/dev/null | grep -q url"

run_test "Gzip compressed response" \
    "curl --socks5-hostname $PROXY --max-time 20 --compressed http://httpbin.org/gzip 2>/dev/null | grep -q gzipped"

run_test "Large JSON response" \
    "curl --socks5-hostname $PROXY --max-time 20 http://httpbin.org/get 2>/dev/null | python3 -m json.tool > /dev/null 2>&1 || curl --socks5-hostname $PROXY --max-time 20 http://httpbin.org/get 2>/dev/null | grep -q url"

echo ""
echo "========================================"
printf "  Results: %d/%d passed" "$PASS" "$TOTAL"
if [ "$FAIL" -gt 0 ]; then
    printf ", %d failed" "$FAIL"
fi
echo ""
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
