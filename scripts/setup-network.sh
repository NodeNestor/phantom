#!/bin/bash
# Generates network config shared via /data volume.
# Runs once before any other container starts.
set -e

echo "=== Generating phantom network ==="
phantom-setup -relays 5 -port 9001 -host 0.0.0.0 -out /data/network

# Patch directory.json to use docker service names instead of 0.0.0.0
sed -i 's|0.0.0.0:9001|relay-0:9001|g' /data/network/directory.json
sed -i 's|0.0.0.0:9002|relay-1:9002|g' /data/network/directory.json
sed -i 's|0.0.0.0:9003|relay-2:9003|g' /data/network/directory.json
sed -i 's|0.0.0.0:9004|relay-3:9004|g' /data/network/directory.json
sed -i 's|0.0.0.0:9005|relay-4:9005|g' /data/network/directory.json

echo "=== Network config generated ==="
cat /data/network/directory.json
echo ""
echo "=== Ready ==="
