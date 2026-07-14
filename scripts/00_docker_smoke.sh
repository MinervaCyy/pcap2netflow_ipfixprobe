#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="pcap2netflow-ipfixprobe:p1b-arm64"

PCAP="$ROOT/tests/data/smoke.pcap"
NATIVE_OUTPUT="$ROOT/tests/output/native_smoke_final.csv"
DOCKER_OUTPUT="$ROOT/tests/output/docker_smoke_telemetry.csv"
DOCKER_LOG="$ROOT/tests/logs/docker_smoke_telemetry.log"
DOCKER_CACHE_STATS="$ROOT/tests/logs/docker_smoke_cache_stats.txt"
TELEMETRY_DIR="$ROOT/tests/telemetry-docker"

for path in "$PCAP" "$NATIVE_OUTPUT"; do
    if [[ ! -f "$path" ]]; then
        echo "ERROR: required file not found: $path" >&2
        exit 1
    fi
done

docker image inspect "$IMAGE" >/dev/null

rm -rf "$TELEMETRY_DIR"
mkdir -p "$TELEMETRY_DIR"
rm -f "$DOCKER_OUTPUT" "$DOCKER_LOG" "$DOCKER_CACHE_STATS"

docker run --rm \
    --device /dev/fuse \
    --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined \
    --entrypoint /bin/bash \
    -v "$ROOT/tests/data:/data/input:ro" \
    -v "$ROOT/tests/output:/data/output" \
    -v "$ROOT/tests/logs:/data/logs" \
    -v "$TELEMETRY_DIR:/telemetry" \
    "$IMAGE" \
    -lc '
        set -euo pipefail
        sed -i "s/^#user_allow_other$/user_allow_other/" /etc/fuse.conf

        /usr/local/bin/ipfixprobe \
            --plugins-path /usr/local/lib/ipfixprobe \
            --telemetry /telemetry \
            -i "pcap;file=/data/input/smoke.pcap" \
            -s "cache;size=17;line=4;active=300;inactive=65" \
            -o "text;file=/data/output/docker_smoke_telemetry.csv" \
            > /data/logs/docker_smoke_telemetry.log 2>&1 &

        pid=$!
        stats_found=0

        for _ in $(seq 1 500); do
            stats_path=/telemetry/pipeline/queues/0/cache-stats
            if [[ -f "$stats_path" ]]; then
                cat "$stats_path" > /data/logs/docker_smoke_cache_stats.txt
                stats_found=1
                break
            fi
            sleep 0.01
        done

        wait "$pid"

        if [[ "$stats_found" -ne 1 ]]; then
            echo "ERROR: Docker cache telemetry was not captured" >&2
            exit 1
        fi
    '

grep -qE '^FlowEndReason:Collision:[[:space:]]+0$' "$DOCKER_CACHE_STATS"
grep -qE '^TotalExportedFlows:[[:space:]]+3$' "$DOCKER_CACHE_STATS"
grep -qE '^SUM[[:space:]]+11[[:space:]]+11[[:space:]]+588[[:space:]]+0' "$DOCKER_LOG"

cmp -s "$NATIVE_OUTPUT" "$DOCKER_OUTPUT"
cmp -s "$ROOT/tests/logs/native_smoke_cache_stats.txt" "$DOCKER_CACHE_STATS"

echo "P1b Docker smoke test passed"
echo "P1c native-vs-container comparison passed"
echo "docker_output=$DOCKER_OUTPUT"
echo "docker_log=$DOCKER_LOG"
echo "docker_cache_stats=$DOCKER_CACHE_STATS"
