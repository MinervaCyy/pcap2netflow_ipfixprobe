#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/.stage/ipfixprobe/usr/local/bin/ipfixprobe"
PLUGINS="$ROOT/.stage/ipfixprobe/usr/local/lib/ipfixprobe"
PCAP="$ROOT/tests/data/smoke.pcap"
OUTPUT="$ROOT/tests/output/native_smoke_final.csv"
RUNTIME_LOG="$ROOT/tests/logs/native_smoke_final.log"
CACHE_STATS="$ROOT/tests/logs/native_smoke_cache_stats.txt"
TELEMETRY="$ROOT/tests/telemetry"

CACHE_SIZE_EXPONENT=17
CACHE_LINE_EXPONENT=4
ACTIVE_TIMEOUT=300
INACTIVE_TIMEOUT=65

for path in "$BIN" "$PCAP"; do
    if [[ ! -e "$path" ]]; then
        echo "ERROR: required path not found: $path" >&2
        exit 1
    fi
done

mkdir -p "$ROOT/tests/output" "$ROOT/tests/logs"
rm -rf "$TELEMETRY"
mkdir -p "$TELEMETRY"
rm -f "$OUTPUT" "$RUNTIME_LOG" "$CACHE_STATS"

"$BIN" \
    --plugins-path "$PLUGINS" \
    --telemetry "$TELEMETRY" \
    -i "pcap;file=$PCAP" \
    -s "cache;size=$CACHE_SIZE_EXPONENT;line=$CACHE_LINE_EXPONENT;active=$ACTIVE_TIMEOUT;inactive=$INACTIVE_TIMEOUT" \
    -o "text;file=$OUTPUT" \
    >"$RUNTIME_LOG" 2>&1 &

pid=$!
stats_found=0

for _ in $(seq 1 500); do
    stats_path="$TELEMETRY/pipeline/queues/0/cache-stats"
    if [[ -f "$stats_path" ]]; then
        cat "$stats_path" >"$CACHE_STATS"
        stats_found=1
        break
    fi
    sleep 0.01
done

wait "$pid"

if [[ "$stats_found" -ne 1 ]]; then
    echo "ERROR: cache telemetry was not captured" >&2
    exit 1
fi

grep -qE '^FlowEndReason:Collision:[[:space:]]+0$' "$CACHE_STATS"
grep -qE '^TotalExportedFlows:[[:space:]]+3$' "$CACHE_STATS"
grep -qE '^SUM[[:space:]]+11[[:space:]]+11[[:space:]]+588[[:space:]]+0' "$RUNTIME_LOG"

records=$(( $(wc -l < "$OUTPUT") - 1 ))
if [[ "$records" -ne 3 ]]; then
    echo "ERROR: expected 3 flow records, found $records" >&2
    exit 1
fi

echo "P1a native smoke test passed"
echo "flow_output=$OUTPUT"
echo "runtime_log=$RUNTIME_LOG"
echo "cache_stats=$CACHE_STATS"
