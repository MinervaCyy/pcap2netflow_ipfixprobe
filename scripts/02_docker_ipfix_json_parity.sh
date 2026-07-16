#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

IMAGE="${IMAGE:-pcap2netflow-ipfixprobe:v1.4-dev-arm64}"
EXPECTED_ARCHITECTURE="arm64"
EXPECTED_SMOKE_SHA256="16f87326ebda807198aa59c5e8e87eb79fca150334ceb57ab8f162e1f0567b62"

NATIVE_SCRIPT="$ROOT/scripts/01_native_ipfix_json_smoke.sh"
CONFIG_TEMPLATE="$ROOT/config/ipfixcol2-tcp-json.xml"
FLOW_SCHEMA="$ROOT/schemas/ipfixcol2-biflow-v1.schema.json"
VALIDATOR="$ROOT/scripts/validate_ipfix_json.py"

DEFAULT_PCAP="$ROOT/tests/data/smoke.pcap"

if [[ "$#" -gt 1 ]]; then
    echo "Usage: $0 [PCAP_PATH]" >&2
    exit 2
fi

PCAP="${1:-$DEFAULT_PCAP}"

required_paths=(
    "$NATIVE_SCRIPT"
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

PCAP="$(readlink -f -- "$PCAP")"
DEFAULT_PCAP="$(readlink -f -- "$DEFAULT_PCAP")"

if [[ "$PCAP" == "$DEFAULT_PCAP" ]]; then
    VALIDATION_MODE="golden"
else
    VALIDATION_MODE="invariant"
fi

if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
else
    DOCKER=(sudo docker)
fi

"${DOCKER[@]}" image inspect "$IMAGE" >/dev/null

image_id="$(
    "${DOCKER[@]}" image inspect \
        "$IMAGE" \
        --format '{{.Id}}'
)"

image_architecture="$(
    "${DOCKER[@]}" image inspect \
        "$IMAGE" \
        --format '{{.Architecture}}'
)"

if [[ "$image_architecture" != "$EXPECTED_ARCHITECTURE" ]]; then
    echo "ERROR: expected image architecture $EXPECTED_ARCHITECTURE," \
         "found $image_architecture" >&2
    exit 1
fi

source "$NATIVE_SCRIPT"
validate_native "$PCAP"

native_sorted_json="$NATIVE_SORTED_JSON"
native_hash="$NATIVE_JSON_HASH"

if [[ ! -f "$native_sorted_json" ]]; then
    echo "ERROR: native validation did not produce sorted JSON" >&2
    exit 1
fi

if [[ "$VALIDATION_MODE" == "golden" ]] &&
   [[ "$native_hash" != "$EXPECTED_SMOKE_SHA256" ]]; then
    echo "ERROR: native JSON SHA-256 changed" >&2
    echo "expected=$EXPECTED_SMOKE_SHA256" >&2
    echo "actual=$native_hash" >&2
    exit 1
fi

mkdir -p "$ROOT/.tmp"
RUN_DIR="$(mktemp -d "$ROOT/.tmp/docker-ipfix-json.XXXXXX")"

JSON_DIR="$RUN_DIR/json"
RUNTIME_CONFIG="$RUN_DIR/ipfixcol2.xml"
DOCKER_SORTED_JSON="$RUN_DIR/docker.sorted.json"
PROBE_LOG="$RUN_DIR/ipfixprobe.log"
COLLECTOR_LOG="$RUN_DIR/ipfixcol2.log"
CACHE_STATS="$RUN_DIR/cache-stats.txt"
EXPORT_DURATION="$RUN_DIR/export-duration-ms.txt"
SCHEMA_VALIDATION_LOG="$RUN_DIR/schema-validation.log"

mkdir -p "$JSON_DIR"

if find "$JSON_DIR" -mindepth 1 -print -quit | grep -q .; then
    echo "ERROR: Docker JSON output directory is not empty: $JSON_DIR" >&2
    exit 1
fi

python3 - "$CONFIG_TEMPLATE" "$RUNTIME_CONFIG" <<'PY_CONFIG'
from pathlib import Path
import sys

template_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])

text = template_path.read_text(encoding="utf-8")

if text.count("__OUTPUT_DIR__") != 1:
    raise SystemExit(
        "ERROR: collector template must contain exactly one "
        "__OUTPUT_DIR__ placeholder"
    )

output_path.write_text(
    text.replace("__OUTPUT_DIR__", "/run/ipfix-json/"),
    encoding="utf-8",
)
PY_CONFIG

"${DOCKER[@]}" run --rm \
    --device /dev/fuse \
    --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined \
    -e VALIDATION_MODE="$VALIDATION_MODE" \
    --entrypoint /bin/bash \
    -v "$PCAP:/data/input/input.pcap:ro" \
    -v "$RUNTIME_CONFIG:/config/ipfixcol2.xml:ro" \
    -v "$JSON_DIR:/run/ipfix-json" \
    -v "$RUN_DIR:/data/output" \
    "$IMAGE" \
    -lc '
        set -euo pipefail

        sed -i \
            "s/^#user_allow_other$/user_allow_other/" \
            /etc/fuse.conf

        mkdir -p /tmp/telemetry

        if find /run/ipfix-json \
            -mindepth 1 \
            -print -quit |
            grep -q .; then
            echo "ERROR: container JSON output directory is not empty" >&2
            exit 1
        fi

        /usr/local/bin/ipfixcol2 \
            -c /config/ipfixcol2.xml \
            -P /tmp/ipfixcol2.pid \
            -vv \
            >/tmp/ipfixcol2.log 2>&1 &

        collector_pid=$!

        cleanup() {
            if kill -0 "$collector_pid" 2>/dev/null; then
                kill -TERM "$collector_pid" 2>/dev/null || true
                wait "$collector_pid" 2>/dev/null || true
            fi
        }
        trap cleanup EXIT

        collector_ready=0

        for _ in $(seq 1 100); do
            if awk \
                '\''$2 == "0100007F:1283" && $4 == "0A" {
                    found=1
                }
                END {
                    exit !found
                }'\'' \
                /proc/net/tcp; then
                collector_ready=1
                break
            fi

            if ! kill -0 "$collector_pid" 2>/dev/null; then
                break
            fi

            sleep 0.05
        done

        if [[ "$collector_ready" -ne 1 ]]; then
            cat /tmp/ipfixcol2.log >&2
            echo "ERROR: collector did not enter LISTEN state" >&2
            exit 1
        fi

        probe_start_ns="$(date +%s%N)"

        /usr/local/bin/ipfixprobe \
            --plugins-path /usr/local/lib/ipfixprobe \
            --telemetry /tmp/telemetry \
            -i "pcap;file=/data/input/input.pcap" \
            -s "cache;size=17;line=4;active=300;inactive=65" \
            -o "ipfix;host=127.0.0.1;port=4739" \
            >/tmp/ipfixprobe.log 2>&1 &

        probe_pid=$!
        stats_found=0
        stats_path=/tmp/telemetry/pipeline/queues/0/cache-stats

        while kill -0 "$probe_pid" 2>/dev/null; do
            if [[ -f "$stats_path" ]] &&
               grep -q "^TotalExportedFlows:" "$stats_path" 2>/dev/null &&
               cp --remove-destination -- \
                   "$stats_path" \
                   /tmp/cache-stats.txt 2>/dev/null; then
                stats_found=1
            fi

            sleep 0.01
        done

        if ! wait "$probe_pid"; then
            cat /tmp/ipfixprobe.log >&2
            echo "ERROR: ipfixprobe execution failed" >&2
            exit 1
        fi

        probe_end_ns="$(date +%s%N)"

        if [[ -f "$stats_path" ]] &&
           grep -q "^TotalExportedFlows:" "$stats_path" 2>/dev/null &&
           cp --remove-destination -- \
               "$stats_path" \
               /tmp/cache-stats.txt 2>/dev/null; then
            stats_found=1
        fi

        if [[ "$stats_found" -ne 1 ]]; then
            echo "ERROR: cache telemetry was not captured" >&2
            exit 1
        fi

        expected_records="$(
            awk -F: '\''
                /^TotalExportedFlows:/ {
                    value=$2
                    gsub(/[[:space:]]/, "", value)
                    print value
                }
            '\'' /tmp/cache-stats.txt
        )"

        if [[ ! "$expected_records" =~ ^[0-9]+$ ]]; then
            echo "ERROR: TotalExportedFlows is missing or invalid" >&2
            exit 1
        fi

        json_ready=0
        json_line_count=0

        for _ in $(seq 1 600); do
            json_line_count="$(
                find /run/ipfix-json \
                    -maxdepth 1 \
                    -type f \
                    -name "flows.*" \
                    -exec cat {} + 2>/dev/null |
                wc -l
            )"
            json_line_count="${json_line_count//[[:space:]]/}"

            if [[ "$json_line_count" -eq "$expected_records" ]]; then
                json_ready=1
                break
            fi

            if [[ "$json_line_count" -gt "$expected_records" ]]; then
                echo "ERROR: Docker JSON record count" \
                     "$json_line_count exceeds TotalExportedFlows" \
                     "$expected_records" >&2
                exit 1
            fi

            sleep 0.1
        done

        if [[ "$json_ready" -ne 1 ]]; then
            echo "ERROR: Docker JSON output did not reach" \
                 "TotalExportedFlows $expected_records within 60 seconds;" \
                 "last count=$json_line_count" >&2
            exit 1
        fi

        kill -TERM "$collector_pid"

        if ! wait "$collector_pid"; then
            cat /tmp/ipfixcol2.log >&2
            echo "ERROR: collector did not stop cleanly" >&2
            exit 1
        fi

        trap - EXIT

        if grep -iE \
            "(^|[^[:alpha:]])(error|failed|drop)([^[:alpha:]]|$)" \
            /tmp/ipfixcol2.log; then
            echo "ERROR: collector log contains an error indicator" >&2
            exit 1
        fi

        collision_count="$(
            awk -F: '\''
                /^FlowEndReason:Collision:/ {
                    value=$NF
                    gsub(/[[:space:]]/, "", value)
                    print value
                }
            '\'' /tmp/cache-stats.txt
        )"

        if [[ ! "$collision_count" =~ ^[0-9]+$ ]]; then
            echo "ERROR: collision count is missing or invalid" >&2
            exit 1
        fi

        if [[ "$collision_count" -ne 0 ]]; then
            echo "ERROR: non-zero collision count: $collision_count" >&2
            exit 1
        fi

        if [[ "$VALIDATION_MODE" == "golden" ]]; then
            if [[ "$expected_records" -ne 3 ]]; then
                echo "ERROR: expected 3 Docker flows," \
                     "found $expected_records" >&2
                exit 1
            fi

            grep -qE \
                "^SUM[[:space:]]+11[[:space:]]+11[[:space:]]+588[[:space:]]+0" \
                /tmp/ipfixprobe.log
        fi

        mapfile -d "" json_files < <(
            find /run/ipfix-json \
                -maxdepth 1 \
                -type f \
                -name "flows.*" \
                -print0 |
            sort -z
        )

        if [[ "${#json_files[@]}" -eq 0 ]]; then
            echo "ERROR: collector produced no JSON files" >&2
            exit 1
        fi

        cat "${json_files[@]}" |
            sort \
            >/data/output/docker.sorted.json

        actual_records="$(
            wc -l </data/output/docker.sorted.json
        )"
        actual_records="${actual_records//[[:space:]]/}"

        if [[ "$actual_records" -ne "$expected_records" ]]; then
            echo "ERROR: Docker JSON record count $actual_records" \
                 "does not match TotalExportedFlows" \
                 "$expected_records" >&2
            exit 1
        fi

        export_duration_ms="$(
            expr \
                "$probe_end_ns" \
                - \
                "$probe_start_ns"
        )"
        export_duration_ms="$((export_duration_ms / 1000000))"

        printf "%s\n" \
            "$export_duration_ms" \
            >/data/output/export-duration-ms.txt

        cp /tmp/ipfixprobe.log /data/output/ipfixprobe.log
        cp /tmp/ipfixcol2.log /data/output/ipfixcol2.log
        cp /tmp/cache-stats.txt /data/output/cache-stats.txt
    '

for output_path in \
    "$DOCKER_SORTED_JSON" \
    "$PROBE_LOG" \
    "$COLLECTOR_LOG" \
    "$CACHE_STATS" \
    "$EXPORT_DURATION"; do
    if [[ ! -f "$output_path" ]]; then
        echo "ERROR: expected Docker output not found: $output_path" >&2
        exit 1
    fi
done

if ! docker_input_dropped="$(
    awk '
        /^Input stats:/ {
            in_input=1
            next
        }
        /^Output stats:/ {
            in_input=0
        }
        in_input && $1 == "#" {
            header_count++
            if (!($2 == "packets" &&
                  $3 == "parsed" &&
                  $4 == "bytes" &&
                  $5 == "dropped" &&
                  $6 == "qtime" &&
                  $7 == "status")) {
                bad_header=1
            }
            next
        }
        in_input && $1 == "SUM" {
            sum_count++
            value=$5
        }
        END {
            if (header_count != 1 ||
                bad_header ||
                sum_count != 1 ||
                value !~ /^[0-9]+$/) {
                exit 1
            }
            print value
        }
    ' "$PROBE_LOG"
)"; then
    echo "ERROR: Docker input statistics format is invalid or ambiguous" >&2
    exit 1
fi

if [[ "$docker_input_dropped" -ne 0 ]]; then
    echo "ERROR: Docker input dropped counter is non-zero:" \
         "$docker_input_dropped" >&2
    exit 1
fi

if ! docker_output_dropped="$(
    awk '
        /^Output stats:/ {
            in_output=1
            next
        }
        in_output && $1 == "#" {
            header_count++
            if (!($2 == "biflows" &&
                  $3 == "packets" &&
                  $4 == "bytes" &&
                  $5 == "(L4)" &&
                  $6 == "dropped" &&
                  $7 == "status")) {
                bad_header=1
            }
            next
        }
        in_output && $1 ~ /^[0-9]+$/ {
            row_count++
            if ($5 !~ /^[0-9]+$/) {
                bad_row=1
            } else {
                total += $5
            }
        }
        END {
            if (header_count != 1 ||
                bad_header ||
                row_count < 1 ||
                bad_row) {
                exit 1
            }
            print total + 0
        }
    ' "$PROBE_LOG"
)"; then
    echo "ERROR: Docker output statistics format is invalid or empty" >&2
    exit 1
fi

if [[ "$docker_output_dropped" -ne 0 ]]; then
    echo "ERROR: Docker output dropped counter is non-zero:" \
         "$docker_output_dropped" >&2
    exit 1
fi

docker_export_duration_ms="$(cat "$EXPORT_DURATION")"

if [[ ! "$docker_export_duration_ms" =~ ^[0-9]+$ ]]; then
    echo "ERROR: Docker export duration is missing or invalid" >&2
    exit 1
fi

docker_records="$(wc -l <"$DOCKER_SORTED_JSON")"
docker_records="${docker_records//[[:space:]]/}"

docker_hash="$(
    sha256sum "$DOCKER_SORTED_JSON" |
    awk '{print $1}'
)"

if [[ "$VALIDATION_MODE" == "golden" ]]; then
    if [[ "$docker_records" -ne 3 ]]; then
        echo "ERROR: expected 3 Docker JSON records," \
             "found $docker_records" >&2
        exit 1
    fi

    if [[ "$docker_hash" != "$EXPECTED_SMOKE_SHA256" ]]; then
        echo "ERROR: Docker JSON SHA-256 changed" >&2
        echo "expected=$EXPECTED_SMOKE_SHA256" >&2
        echo "actual=$docker_hash" >&2
        exit 1
    fi
fi

"$VALIDATOR" \
    --schema "$FLOW_SCHEMA" \
    --input "$DOCKER_SORTED_JSON" \
    --expect-records "$docker_records" \
    --expect-sha256 "$docker_hash" \
    >"$SCHEMA_VALIDATION_LOG"

if ! cmp -s "$native_sorted_json" "$DOCKER_SORTED_JSON"; then
    echo "ERROR: native and Docker JSON outputs differ" >&2
    diff -u \
        "$native_sorted_json" \
        "$DOCKER_SORTED_JSON" >&2 || true
    exit 1
fi

echo "Docker IPFIX-to-JSON parity test passed"
echo "mode=$VALIDATION_MODE"
echo "pcap=$PCAP"
echo "records=$docker_records"
echo "collision=0"
echo "input_dropped=$docker_input_dropped"
echo "output_dropped=$docker_output_dropped"
echo "sha256=$docker_hash"
echo "export_duration_ms=$docker_export_duration_ms"
echo "image=$IMAGE"
echo "image_id=$image_id"
echo "architecture=$image_architecture"
echo "native_sorted_json=$native_sorted_json"
echo "docker_sorted_json=$DOCKER_SORTED_JSON"
echo "schema_validation_log=$SCHEMA_VALIDATION_LOG"
echo "run_dir=$RUN_DIR"
echo "native_and_docker=byte-identical"
