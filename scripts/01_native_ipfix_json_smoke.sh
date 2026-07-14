#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

IPFIXPROBE="$ROOT/.stage/ipfixprobe/usr/local/bin/ipfixprobe"
IPFIXPROBE_PLUGINS="$ROOT/.stage/ipfixprobe/usr/local/lib/ipfixprobe"

IPFIXCOL2="$ROOT/.stage/ipfixcol2/bin/ipfixcol2"
IPFIXCOL2_PLUGINS="$ROOT/.stage/ipfixcol2/lib/ipfixcol2"

LIBFDS_LIB="$ROOT/.stage/libfds/lib"
LIBFDS_DEFINITIONS="$ROOT/.stage/libfds/etc/libfds"

CONFIG_TEMPLATE="$ROOT/config/ipfixcol2-tcp-json.xml"
FLOW_SCHEMA="$ROOT/schemas/ipfixcol2-biflow-v1.schema.json"
VALIDATOR="$ROOT/scripts/validate_ipfix_json.py"
PCAP="$ROOT/tests/data/smoke.pcap"

mkdir -p "$ROOT/.tmp"
RUN_DIR="$(mktemp -d "$ROOT/.tmp/native-ipfix-json.XXXXXX")"

JSON_DIR="$RUN_DIR/json"
TELEMETRY_DIR="$RUN_DIR/telemetry"
RUNTIME_CONFIG="$RUN_DIR/ipfixcol2.xml"
COLLECTOR_LOG="$RUN_DIR/ipfixcol2.log"
PROBE_LOG="$RUN_DIR/ipfixprobe.log"
CACHE_STATS="$RUN_DIR/cache-stats.txt"
SORTED_JSON="$RUN_DIR/native.sorted.json"
SCHEMA_VALIDATION_LOG="$RUN_DIR/schema-validation.log"
PID_FILE="$RUN_DIR/ipfixcol2.pid"

mkdir -p "$JSON_DIR" "$TELEMETRY_DIR"

required_paths=(
    "$IPFIXPROBE"
    "$IPFIXPROBE_PLUGINS"
    "$IPFIXCOL2"
    "$IPFIXCOL2_PLUGINS"
    "$LIBFDS_LIB/libfds.so.0"
    "$LIBFDS_DEFINITIONS/system/elements/iana.xml"
    "$CONFIG_TEMPLATE"
    "$FLOW_SCHEMA"
    "$VALIDATOR"
    "$PCAP"
)

for required_path in "${required_paths[@]}"; do
    if [[ ! -e "$required_path" ]]; then
        echo "ERROR: required path not found: $required_path" >&2
        exit 1
    fi
done

if find "$JSON_DIR" -mindepth 1 -print -quit | grep -q .; then
    echo "ERROR: JSON output directory is not empty: $JSON_DIR" >&2
    exit 1
fi

python3 - "$CONFIG_TEMPLATE" "$RUNTIME_CONFIG" "$JSON_DIR/" <<'PY_CONFIG'
from pathlib import Path
import sys

template_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
json_dir = sys.argv[3]

text = template_path.read_text(encoding="utf-8")

if text.count("__OUTPUT_DIR__") != 1:
    raise SystemExit(
        "ERROR: collector template must contain exactly one "
        "__OUTPUT_DIR__ placeholder"
    )

output_path.write_text(
    text.replace("__OUTPUT_DIR__", json_dir),
    encoding="utf-8",
)
PY_CONFIG

if awk '$2 == "0100007F:1283" && $4 == "0A" { found=1 }
        END { exit !found }' /proc/net/tcp; then
    echo "ERROR: TCP port 127.0.0.1:4739 is already in use" >&2
    exit 1
fi

collector_pid=""

cleanup() {
    if [[ -n "$collector_pid" ]] &&
       kill -0 "$collector_pid" 2>/dev/null; then
        kill -TERM "$collector_pid" 2>/dev/null || true
        wait "$collector_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

LD_LIBRARY_PATH="$LIBFDS_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$IPFIXCOL2" \
    -c "$RUNTIME_CONFIG" \
    -p "$IPFIXCOL2_PLUGINS" \
    -e "$LIBFDS_DEFINITIONS" \
    -P "$PID_FILE" \
    -vv \
    >"$COLLECTOR_LOG" 2>&1 &

collector_pid=$!
collector_ready=0

for _ in $(seq 1 100); do
    if awk '$2 == "0100007F:1283" && $4 == "0A" { found=1 }
            END { exit !found }' /proc/net/tcp; then
        collector_ready=1
        break
    fi

    if ! kill -0 "$collector_pid" 2>/dev/null; then
        break
    fi

    sleep 0.05
done

if [[ "$collector_ready" -ne 1 ]]; then
    cat "$COLLECTOR_LOG" >&2
    echo "ERROR: collector did not enter LISTEN state" >&2
    exit 1
fi

"$IPFIXPROBE" \
    --plugins-path "$IPFIXPROBE_PLUGINS" \
    --telemetry "$TELEMETRY_DIR" \
    -i "pcap;file=$PCAP" \
    -s "cache;size=17;line=4;active=300;inactive=65" \
    -o "ipfix;host=127.0.0.1;port=4739" \
    >"$PROBE_LOG" 2>&1 &

probe_pid=$!
stats_found=0

for _ in $(seq 1 500); do
    stats_path="$TELEMETRY_DIR/pipeline/queues/0/cache-stats"

    if [[ -f "$stats_path" ]] &&
       grep -q '^TotalExportedFlows:' "$stats_path"; then
        cp "$stats_path" "$CACHE_STATS"
        stats_found=1
        break
    fi

    sleep 0.01
done

wait "$probe_pid"

if [[ "$stats_found" -ne 1 ]]; then
    echo "ERROR: cache telemetry was not captured" >&2
    exit 1
fi

kill -TERM "$collector_pid"
wait "$collector_pid"
collector_pid=""

if grep -iE 'error|failed|drop' "$COLLECTOR_LOG"; then
    echo "ERROR: collector log contains an error indicator" >&2
    exit 1
fi

grep -qE \
    '^FlowEndReason:Collision:[[:space:]]+0$' \
    "$CACHE_STATS"

grep -qE \
    '^TotalExportedFlows:[[:space:]]+3$' \
    "$CACHE_STATS"

grep -qE \
    '^SUM[[:space:]]+11[[:space:]]+11[[:space:]]+588[[:space:]]+0' \
    "$PROBE_LOG"

expected_records="$(
    awk -F: '
        /^TotalExportedFlows:/ {
            value=$2
            gsub(/[[:space:]]/, "", value)
            print value
        }
    ' "$CACHE_STATS"
)"

if [[ -z "$expected_records" ]]; then
    echo "ERROR: TotalExportedFlows was not found" >&2
    exit 1
fi

mapfile -d '' json_files < <(
    find "$JSON_DIR" \
        -maxdepth 1 \
        -type f \
        -name 'flows.*' \
        -print0 |
    sort -z
)

if [[ "${#json_files[@]}" -eq 0 ]]; then
    echo "ERROR: collector produced no JSON files" >&2
    exit 1
fi

cat "${json_files[@]}" | sort >"$SORTED_JSON"

actual_records="$(wc -l <"$SORTED_JSON")"
actual_records="${actual_records//[[:space:]]/}"

if [[ "$actual_records" -ne "$expected_records" ]]; then
    echo "ERROR: JSON record count $actual_records does not match" \
         "TotalExportedFlows $expected_records" >&2
    exit 1
fi

json_hash="$(sha256sum "$SORTED_JSON" | awk '{print $1}')"

"$VALIDATOR" \
    --schema "$FLOW_SCHEMA" \
    --input "$SORTED_JSON" \
    --expect-records "$expected_records" \
    --expect-sha256 "$json_hash" \
    >"$SCHEMA_VALIDATION_LOG"

echo "Native IPFIX-to-JSON smoke test passed"
echo "records=$actual_records"
echo "collision=0"
echo "sha256=$json_hash"
echo "run_dir=$RUN_DIR"
echo "sorted_json=$SORTED_JSON"
echo "probe_log=$PROBE_LOG"
echo "collector_log=$COLLECTOR_LOG"
echo "cache_stats=$CACHE_STATS"
echo "schema_validation_log=$SCHEMA_VALIDATION_LOG"
