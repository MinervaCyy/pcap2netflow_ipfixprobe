#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

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

DEFAULT_PCAP="$ROOT/tests/data/smoke.pcap"
EXPECTED_SMOKE_SHA256="16f87326ebda807198aa59c5e8e87eb79fca150334ceb57ab8f162e1f0567b62"

collector_pid=""
probe_pid=""

cleanup() {
    if [[ -n "$probe_pid" ]] &&
       kill -0 "$probe_pid" 2>/dev/null; then
        kill -TERM "$probe_pid" 2>/dev/null || true
        wait "$probe_pid" 2>/dev/null || true
    fi

    if [[ -n "$collector_pid" ]] &&
       kill -0 "$collector_pid" 2>/dev/null; then
        kill -TERM "$collector_pid" 2>/dev/null || true
        wait "$collector_pid" 2>/dev/null || true
    fi
}

run_once() {
    local pcap="$1"
    local out_dir="$2"

    local json_dir="$out_dir/json"
    local telemetry_dir="$out_dir/telemetry"
    local runtime_config="$out_dir/ipfixcol2.xml"
    local collector_log="$out_dir/ipfixcol2.log"
    local probe_log="$out_dir/ipfixprobe.log"
    local cache_stats="$out_dir/cache-stats.txt"
    local sorted_json="$out_dir/native.sorted.json"
    local pid_file="$out_dir/ipfixcol2.pid"
    local stats_path
    local collector_ready=0
    local stats_found=0
    local probe_start_ns
    local probe_end_ns
    local expected_records
    local actual_records
    local collision_count
    local input_dropped
    local output_dropped
    local json_hash
    local -a json_files

    mkdir -p "$out_dir"

    if find "$out_dir" -mindepth 1 -print -quit | grep -q .; then
        echo "ERROR: run directory is not empty: $out_dir" >&2
        return 1
    fi

    mkdir -p "$json_dir" "$telemetry_dir"

    python3 - "$CONFIG_TEMPLATE" "$runtime_config" "$json_dir/" <<'PY_CONFIG'
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
        return 1
    fi

    LD_LIBRARY_PATH="$LIBFDS_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        "$IPFIXCOL2" \
        -c "$runtime_config" \
        -p "$IPFIXCOL2_PLUGINS" \
        -e "$LIBFDS_DEFINITIONS" \
        -P "$pid_file" \
        -vv \
        >"$collector_log" 2>&1 &

    collector_pid=$!

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
        cat "$collector_log" >&2
        echo "ERROR: collector did not enter LISTEN state" >&2
        return 1
    fi

    probe_start_ns="$(date +%s%N)"

    "$IPFIXPROBE" \
        --plugins-path "$IPFIXPROBE_PLUGINS" \
        --telemetry "$telemetry_dir" \
        -i "pcap;file=$pcap" \
        -s "cache;size=17;line=4;active=300;inactive=65" \
        -o "ipfix;host=127.0.0.1;port=4739" \
        >"$probe_log" 2>&1 &

    probe_pid=$!
    stats_path="$telemetry_dir/pipeline/queues/0/cache-stats"

    while kill -0 "$probe_pid" 2>/dev/null; do
        if [[ -f "$stats_path" ]] &&
           grep -q '^TotalExportedFlows:' "$stats_path"; then
            cp --remove-destination -- "$stats_path" "$cache_stats"
            stats_found=1
        fi

        sleep 0.01
    done

    if ! wait "$probe_pid"; then
        probe_pid=""
        cat "$probe_log" >&2
        echo "ERROR: ipfixprobe execution failed" >&2
        return 1
    fi
    probe_pid=""

    probe_end_ns="$(date +%s%N)"

    if [[ -f "$stats_path" ]] &&
       grep -q '^TotalExportedFlows:' "$stats_path"; then
        cp --remove-destination -- "$stats_path" "$cache_stats"
        stats_found=1
    fi

    if [[ "$stats_found" -ne 1 ]]; then
        echo "ERROR: cache telemetry was not captured" >&2
        return 1
    fi

    sleep 0.25

    kill -TERM "$collector_pid"

    if ! wait "$collector_pid"; then
        collector_pid=""
        cat "$collector_log" >&2
        echo "ERROR: collector did not stop cleanly" >&2
        return 1
    fi
    collector_pid=""

    if grep -iE \
        '(^|[^[:alpha:]])(error|failed|drop)([^[:alpha:]]|$)' \
        "$collector_log"; then
        echo "ERROR: collector log contains an error indicator" >&2
        return 1
    fi

    collision_count="$(
        awk -F: '
            /^FlowEndReason:Collision:/ {
                value=$NF
                gsub(/[[:space:]]/, "", value)
                print value
            }
        ' "$cache_stats"
    )"

    if [[ ! "$collision_count" =~ ^[0-9]+$ ]]; then
        echo "ERROR: collision count is missing or invalid" >&2
        return 1
    fi

    if [[ "$collision_count" -ne 0 ]]; then
        echo "ERROR: non-zero collision count: $collision_count" >&2
        return 1
    fi

    expected_records="$(
        awk -F: '
            /^TotalExportedFlows:/ {
                value=$2
                gsub(/[[:space:]]/, "", value)
                print value
            }
        ' "$cache_stats"
    )"

    if [[ ! "$expected_records" =~ ^[0-9]+$ ]]; then
        echo "ERROR: TotalExportedFlows is missing or invalid" >&2
        return 1
    fi

    input_dropped="$(
        awk '
            /^Input stats:/ {
                section="input"
                next
            }
            /^Output stats:/ {
                section="output"
                next
            }
            section == "input" && $1 == "SUM" {
                print $5
                exit
            }
        ' "$probe_log"
    )"

    if [[ ! "$input_dropped" =~ ^[0-9]+$ ]]; then
        echo "ERROR: input dropped counter is missing or invalid" >&2
        return 1
    fi

    if [[ "$input_dropped" -ne 0 ]]; then
        echo "ERROR: input dropped counter is non-zero: $input_dropped" >&2
        return 1
    fi

    output_dropped="$(
        awk '
            /^Output stats:/ {
                section="output"
                next
            }
            section == "output" && $1 ~ /^[0-9]+$/ {
                total += $5
                found=1
            }
            END {
                if (found) {
                    print total
                }
            }
        ' "$probe_log"
    )"

    if [[ ! "$output_dropped" =~ ^[0-9]+$ ]]; then
        echo "ERROR: output dropped counter is missing or invalid" >&2
        return 1
    fi

    if [[ "$output_dropped" -ne 0 ]]; then
        echo "ERROR: output dropped counter is non-zero: $output_dropped" >&2
        return 1
    fi

    mapfile -d '' json_files < <(
        find "$json_dir" \
            -maxdepth 1 \
            -type f \
            -name 'flows.*' \
            -print0 |
        sort -z
    )

    if [[ "${#json_files[@]}" -eq 0 ]]; then
        echo "ERROR: collector produced no JSON files" >&2
        return 1
    fi

    cat "${json_files[@]}" | sort >"$sorted_json"

    actual_records="$(wc -l <"$sorted_json")"
    actual_records="${actual_records//[[:space:]]/}"

    if [[ "$actual_records" -ne "$expected_records" ]]; then
        echo "ERROR: JSON record count $actual_records does not match" \
             "TotalExportedFlows $expected_records" >&2
        return 1
    fi

    json_hash="$(sha256sum "$sorted_json" | awk '{print $1}')"

    RUN_DIR="$out_dir"
    RUN_SORTED_JSON="$sorted_json"
    RUN_PROBE_LOG="$probe_log"
    RUN_COLLECTOR_LOG="$collector_log"
    RUN_CACHE_STATS="$cache_stats"
    RUN_RECORDS="$actual_records"
    RUN_JSON_HASH="$json_hash"
    RUN_COLLISION_COUNT="$collision_count"
    RUN_INPUT_DROPPED="$input_dropped"
    RUN_OUTPUT_DROPPED="$output_dropped"
    RUN_EXPORT_DURATION_MS="$(((probe_end_ns - probe_start_ns) / 1000000))"
}

validate_native() {
    local pcap="${1:-$DEFAULT_PCAP}"
    local validation_mode
    local first_run_dir
    local second_run_dir=""
    local expected_validation_hash
    local -a required_paths

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
        "$pcap"
    )

    for required_path in "${required_paths[@]}"; do
        if [[ ! -e "$required_path" ]]; then
            echo "ERROR: required path not found: $required_path" >&2
            return 1
        fi
    done

    pcap="$(readlink -f -- "$pcap")"
    DEFAULT_PCAP="$(readlink -f -- "$DEFAULT_PCAP")"

    if [[ "$pcap" == "$DEFAULT_PCAP" ]]; then
        validation_mode="golden"
    else
        validation_mode="invariant"
    fi

    mkdir -p "$ROOT/.tmp"
    first_run_dir="$(mktemp -d "$ROOT/.tmp/native-ipfix-json.XXXXXX")"

    trap cleanup EXIT
    run_once "$pcap" "$first_run_dir"

    NATIVE_MODE="$validation_mode"
    NATIVE_PCAP="$pcap"
    NATIVE_RUN_DIR="$RUN_DIR"
    NATIVE_SORTED_JSON="$RUN_SORTED_JSON"
    NATIVE_PROBE_LOG="$RUN_PROBE_LOG"
    NATIVE_COLLECTOR_LOG="$RUN_COLLECTOR_LOG"
    NATIVE_CACHE_STATS="$RUN_CACHE_STATS"
    NATIVE_RECORDS="$RUN_RECORDS"
    NATIVE_JSON_HASH="$RUN_JSON_HASH"
    NATIVE_COLLISION_COUNT="$RUN_COLLISION_COUNT"
    NATIVE_INPUT_DROPPED="$RUN_INPUT_DROPPED"
    NATIVE_OUTPUT_DROPPED="$RUN_OUTPUT_DROPPED"
    NATIVE_EXPORT_DURATION_MS="$RUN_EXPORT_DURATION_MS"
    NATIVE_REPEAT_RUN_DIR=""
    NATIVE_REPEAT_SORTED_JSON=""
    NATIVE_REPEAT_JSON_HASH=""
    NATIVE_REPEAT_RECORDS=""
    NATIVE_REPEAT_EXPORT_DURATION_MS=""

    if [[ "$validation_mode" == "golden" ]]; then
        if [[ "$NATIVE_RECORDS" -ne 3 ]]; then
            echo "ERROR: expected 3 native JSON records," \
                 "found $NATIVE_RECORDS" >&2
            return 1
        fi

        if ! grep -qE \
            '^SUM[[:space:]]+11[[:space:]]+11[[:space:]]+588[[:space:]]+0' \
            "$NATIVE_PROBE_LOG"; then
            echo "ERROR: golden exporter counters changed" >&2
            return 1
        fi

        expected_validation_hash="$EXPECTED_SMOKE_SHA256"
    else
        second_run_dir="$(mktemp -d "$ROOT/.tmp/native-ipfix-json.XXXXXX")"
        run_once "$pcap" "$second_run_dir"

        NATIVE_REPEAT_RUN_DIR="$RUN_DIR"
        NATIVE_REPEAT_SORTED_JSON="$RUN_SORTED_JSON"
        NATIVE_REPEAT_JSON_HASH="$RUN_JSON_HASH"
        NATIVE_REPEAT_RECORDS="$RUN_RECORDS"
        NATIVE_REPEAT_EXPORT_DURATION_MS="$RUN_EXPORT_DURATION_MS"

        if ! cmp -s -- \
            "$NATIVE_SORTED_JSON" \
            "$NATIVE_REPEAT_SORTED_JSON"; then
            echo "ERROR: invariant native runs produced different sorted JSON" >&2
            echo "first=$NATIVE_SORTED_JSON" >&2
            echo "second=$NATIVE_REPEAT_SORTED_JSON" >&2
            return 1
        fi

        expected_validation_hash="$NATIVE_JSON_HASH"
    fi

    NATIVE_SCHEMA_VALIDATION_LOG="$NATIVE_RUN_DIR/schema-validation.log"

    "$VALIDATOR" \
        --schema "$FLOW_SCHEMA" \
        --input "$NATIVE_SORTED_JSON" \
        --expect-records "$NATIVE_RECORDS" \
        --expect-sha256 "$expected_validation_hash" \
        >"$NATIVE_SCHEMA_VALIDATION_LOG"

    trap - EXIT

    echo "Native IPFIX-to-JSON validation passed"
    echo "mode=$NATIVE_MODE"
    echo "pcap=$NATIVE_PCAP"
    echo "records=$NATIVE_RECORDS"
    echo "collision=$NATIVE_COLLISION_COUNT"
    echo "input_dropped=$NATIVE_INPUT_DROPPED"
    echo "output_dropped=$NATIVE_OUTPUT_DROPPED"
    echo "sha256=$NATIVE_JSON_HASH"
    echo "export_duration_ms=$NATIVE_EXPORT_DURATION_MS"
    echo "run_dir=$NATIVE_RUN_DIR"
    echo "sorted_json=$NATIVE_SORTED_JSON"
    echo "probe_log=$NATIVE_PROBE_LOG"
    echo "collector_log=$NATIVE_COLLECTOR_LOG"
    echo "cache_stats=$NATIVE_CACHE_STATS"
    echo "schema_validation_log=$NATIVE_SCHEMA_VALIDATION_LOG"

    if [[ "$NATIVE_MODE" == "invariant" ]]; then
        echo "repeat_run=byte-identical"
        echo "repeat_records=$NATIVE_REPEAT_RECORDS"
        echo "repeat_sha256=$NATIVE_REPEAT_JSON_HASH"
        echo "repeat_export_duration_ms=$NATIVE_REPEAT_EXPORT_DURATION_MS"
        echo "repeat_run_dir=$NATIVE_REPEAT_RUN_DIR"
        echo "repeat_sorted_json=$NATIVE_REPEAT_SORTED_JSON"
    fi
}

main() {
    if [[ "$#" -gt 1 ]]; then
        echo "Usage: $0 [PCAP_PATH]" >&2
        exit 2
    fi

    validate_native "${1:-$DEFAULT_PCAP}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
