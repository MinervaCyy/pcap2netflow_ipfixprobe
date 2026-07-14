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
PCAP="$ROOT/tests/data/smoke.pcap"

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

native_output="$("$NATIVE_SCRIPT")"
printf '%s\n' "$native_output"

native_sorted_json="$(
    printf '%s\n' "$native_output" |
    awk -F= '
        $1 == "sorted_json" {
            print substr($0, index($0, "=") + 1)
        }
    '
)"

native_hash="$(
    printf '%s\n' "$native_output" |
    awk -F= '
        $1 == "sha256" {
            print $2
        }
    '
)"

if [[ -z "$native_sorted_json" ]] ||
   [[ ! -f "$native_sorted_json" ]]; then
    echo "ERROR: native smoke did not provide a valid sorted JSON file" >&2
    exit 1
fi

if [[ "$native_hash" != "$EXPECTED_SMOKE_SHA256" ]]; then
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
    --entrypoint /bin/bash \
    -v "$PCAP:/data/input/smoke.pcap:ro" \
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

        /usr/local/bin/ipfixprobe \
            --plugins-path /usr/local/lib/ipfixprobe \
            --telemetry /tmp/telemetry \
            -i "pcap;file=/data/input/smoke.pcap" \
            -s "cache;size=17;line=4;active=300;inactive=65" \
            -o "ipfix;host=127.0.0.1;port=4739" \
            >/tmp/ipfixprobe.log 2>&1 &

        probe_pid=$!
        stats_found=0

        for _ in $(seq 1 500); do
            stats_path=/tmp/telemetry/pipeline/queues/0/cache-stats

            if [[ -f "$stats_path" ]] &&
               grep -q "^TotalExportedFlows:" "$stats_path"; then
                cp "$stats_path" /tmp/cache-stats.txt
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
        trap - EXIT

        if grep -iE \
            "(^|[^[:alpha:]])(error|failed|drop)([^[:alpha:]]|$)" \
            /tmp/ipfixcol2.log; then
            echo "ERROR: collector log contains an error indicator" >&2
            exit 1
        fi

        grep -qE \
            "^FlowEndReason:Collision:[[:space:]]+0$" \
            /tmp/cache-stats.txt

        grep -qE \
            "^TotalExportedFlows:[[:space:]]+3$" \
            /tmp/cache-stats.txt

        grep -qE \
            "^SUM[[:space:]]+11[[:space:]]+11[[:space:]]+588[[:space:]]+0" \
            /tmp/ipfixprobe.log

        expected_records="$(
            awk -F: '\''
                /^TotalExportedFlows:/ {
                    value=$2
                    gsub(/[[:space:]]/, "", value)
                    print value
                }
            '\'' /tmp/cache-stats.txt
        )"

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

        cp /tmp/ipfixprobe.log /data/output/ipfixprobe.log
        cp /tmp/ipfixcol2.log /data/output/ipfixcol2.log
        cp /tmp/cache-stats.txt /data/output/cache-stats.txt
    '

for output_path in \
    "$DOCKER_SORTED_JSON" \
    "$PROBE_LOG" \
    "$COLLECTOR_LOG" \
    "$CACHE_STATS"; do
    if [[ ! -f "$output_path" ]]; then
        echo "ERROR: expected Docker output not found: $output_path" >&2
        exit 1
    fi
done

docker_records="$(wc -l <"$DOCKER_SORTED_JSON")"
docker_records="${docker_records//[[:space:]]/}"

docker_hash="$(
    sha256sum "$DOCKER_SORTED_JSON" |
    awk '{print $1}'
)"

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
echo "records=$docker_records"
echo "collision=0"
echo "sha256=$docker_hash"
echo "image=$IMAGE"
echo "image_id=$image_id"
echo "architecture=$image_architecture"
echo "native_sorted_json=$native_sorted_json"
echo "docker_sorted_json=$DOCKER_SORTED_JSON"
echo "schema_validation_log=$SCHEMA_VALIDATION_LOG"
echo "run_dir=$RUN_DIR"
echo "native_and_docker=byte-identical"
