#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSIONS="$ROOT/docker/versions.env"
DOCKERFILE="$ROOT/Dockerfile"

IMAGE="${IMAGE:-pcap2netflow-ipfixprobe:v1.4-dev-arm64}"
EXPECTED_ARCHITECTURE="arm64"

if [[ ! -f "$VERSIONS" ]]; then
    echo "ERROR: missing version file: $VERSIONS" >&2
    exit 1
fi

if [[ ! -f "$DOCKERFILE" ]]; then
    echo "ERROR: missing Dockerfile: $DOCKERFILE" >&2
    exit 1
fi

set -a
source "$VERSIONS"
set +a

required_variables=(
    BASE_IMAGE
    BASE_IMAGE_DIGEST
    IPFIXPROBE_REPOSITORY
    IPFIXPROBE_TAG
    IPFIXPROBE_COMMIT
    LIBFDS_REPOSITORY
    LIBFDS_VERSION
    LIBFDS_COMMIT
    IPFIXCOL2_REPOSITORY
    IPFIXCOL2_VERSION
    IPFIXCOL2_COMMIT
    IPFIXCOL2_TCP_PLUGIN_VERSION
    IPFIXCOL2_JSON_PLUGIN_VERSION
)

for variable in "${required_variables[@]}"; do
    if [[ -z "${!variable:-}" ]]; then
        echo "ERROR: required version variable is missing: $variable" >&2
        exit 1
    fi
done

for command in awk grep sed sha256sum uname; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $command" >&2
        exit 1
    fi
done

if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
else
    DOCKER=(sudo docker)
fi

host_architecture="$(uname -m)"

case "$host_architecture" in
    aarch64|arm64)
        ;;
    *)
        echo "ERROR: native ARM64 Docker build requires an ARM64 host;" \
             "found $host_architecture" >&2
        exit 1
        ;;
esac

expected_ipfixprobe_version="${IPFIXPROBE_TAG#v}"

"${DOCKER[@]}" build \
    --pull \
    --platform linux/arm64 \
    --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    --build-arg "BASE_IMAGE_DIGEST=$BASE_IMAGE_DIGEST" \
    --build-arg "IPFIXPROBE_REPOSITORY=$IPFIXPROBE_REPOSITORY" \
    --build-arg "IPFIXPROBE_COMMIT=$IPFIXPROBE_COMMIT" \
    --build-arg "LIBFDS_REPOSITORY=$LIBFDS_REPOSITORY" \
    --build-arg "LIBFDS_COMMIT=$LIBFDS_COMMIT" \
    --build-arg "IPFIXCOL2_REPOSITORY=$IPFIXCOL2_REPOSITORY" \
    --build-arg "IPFIXCOL2_COMMIT=$IPFIXCOL2_COMMIT" \
    --tag "$IMAGE" \
    "$ROOT"

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

image_operating_system="$(
    "${DOCKER[@]}" image inspect \
        "$IMAGE" \
        --format '{{.Os}}'
)"

image_created="$(
    "${DOCKER[@]}" image inspect \
        "$IMAGE" \
        --format '{{.Created}}'
)"

if [[ "$image_architecture" != "$EXPECTED_ARCHITECTURE" ]]; then
    echo "ERROR: expected image architecture $EXPECTED_ARCHITECTURE," \
         "found $image_architecture" >&2
    exit 1
fi

actual_ipfixprobe_version="$(
    "${DOCKER[@]}" run \
        --rm \
        "$IMAGE" \
        --version
)"

if [[ "$actual_ipfixprobe_version" != \
      "$expected_ipfixprobe_version" ]]; then
    echo "ERROR: expected ipfixprobe version" \
         "$expected_ipfixprobe_version," \
         "found $actual_ipfixprobe_version" >&2
    exit 1
fi

runtime_report="$(
    "${DOCKER[@]}" run \
        --rm \
        --entrypoint /bin/bash \
        -e "EXPECTED_LIBFDS_VERSION=$LIBFDS_VERSION" \
        -e "EXPECTED_IPFIXCOL2_VERSION=$IPFIXCOL2_VERSION" \
        -e "EXPECTED_TCP_PLUGIN_VERSION=$IPFIXCOL2_TCP_PLUGIN_VERSION" \
        -e "EXPECTED_JSON_PLUGIN_VERSION=$IPFIXCOL2_JSON_PLUGIN_VERSION" \
        "$IMAGE" \
        -lc '
            set -euo pipefail

            test -f /usr/local/lib/libfds.so.0
            test -f /usr/local/etc/libfds/system/elements/iana.xml
            test -f /usr/local/lib/ipfixcol2/libtcp-input.so
            test -f /usr/local/lib/ipfixcol2/libjson-output.so

            test -f /usr/local/lib/pkgconfig/libfds.pc

            actual_libfds_version="$(
                sed -n \
                    "s/^Version:[[:space:]]*//p" \
                    /usr/local/lib/pkgconfig/libfds.pc |
                head -n1
            )"

            if [[ -z "$actual_libfds_version" ]]; then
                echo "ERROR: libfds version is missing from libfds.pc" >&2
                exit 1
            fi

            if [[ "$actual_libfds_version" != \
                  "$EXPECTED_LIBFDS_VERSION" ]]; then
                echo "ERROR: unexpected libfds version:" \
                     "$actual_libfds_version" >&2
                exit 1
            fi

            /usr/local/bin/ipfixcol2 -V \
                >/tmp/ipfixcol2-version.txt

            if ! grep -qE \
                "^Version:[[:space:]]+$EXPECTED_IPFIXCOL2_VERSION$" \
                /tmp/ipfixcol2-version.txt; then
                cat /tmp/ipfixcol2-version.txt >&2
                echo "ERROR: unexpected ipfixcol2 version" >&2
                exit 1
            fi

            if ! grep -qE \
                "^Compiler:[[:space:]]+GNU 14\." \
                /tmp/ipfixcol2-version.txt; then
                cat /tmp/ipfixcol2-version.txt >&2
                echo "ERROR: ipfixcol2 was not built with GCC 14" >&2
                exit 1
            fi

            /usr/local/bin/ipfixcol2 -L \
                >/tmp/plugin-list-coloured.txt

            sed -E \
                "s/\x1B\[[0-9;]*m//g" \
                /tmp/plugin-list-coloured.txt \
                >/tmp/plugin-list.txt

            plugin_version() {
                local target="$1"

                awk -v target="$target" '\''
                    /^- Name[[:space:]]*:/ {
                        name=$0
                        sub(/^.*:[[:space:]]*/, "", name)
                        active=(name == target)
                        next
                    }

                    active &&
                    /^[[:space:]]*Version[[:space:]]*:/ {
                        version=$0
                        sub(/^.*:[[:space:]]*/, "", version)
                        print version
                        exit
                    }
                '\'' /tmp/plugin-list.txt
            }

            actual_tcp_plugin_version="$(
                plugin_version tcp
            )"

            actual_json_plugin_version="$(
                plugin_version json
            )"

            if [[ "$actual_tcp_plugin_version" != \
                  "$EXPECTED_TCP_PLUGIN_VERSION" ]]; then
                echo "ERROR: unexpected TCP plugin version:" \
                     "${actual_tcp_plugin_version:-missing}" >&2
                exit 1
            fi

            if [[ "$actual_json_plugin_version" != \
                  "$EXPECTED_JSON_PLUGIN_VERSION" ]]; then
                echo "ERROR: unexpected JSON plugin version:" \
                     "${actual_json_plugin_version:-missing}" >&2
                exit 1
            fi

            for binary in \
                /usr/local/bin/ipfixcol2 \
                /usr/local/lib/ipfixcol2/libtcp-input.so \
                /usr/local/lib/ipfixcol2/libjson-output.so; do
                if ldd "$binary" | grep -q "not found"; then
                    echo "ERROR: unresolved dependency in $binary" >&2
                    ldd "$binary" >&2
                    exit 1
                fi
            done

            printf "libfds_version=%s\n" \
                "$actual_libfds_version"
            printf "ipfixcol2_version=%s\n" \
                "$EXPECTED_IPFIXCOL2_VERSION"
            printf "tcp_plugin_version=%s\n" \
                "$actual_tcp_plugin_version"
            printf "json_plugin_version=%s\n" \
                "$actual_json_plugin_version"
            printf "iana_definitions=present\n"
            printf "dynamic_dependencies=resolved\n"
        '
)"

dockerfile_hash="$(
    sha256sum "$DOCKERFILE" |
    awk '{print $1}'
)"

versions_hash="$(
    sha256sum "$VERSIONS" |
    awk '{print $1}'
)"

echo "Docker ARM64 image build passed"
echo "image=$IMAGE"
echo "image_id=$image_id"
echo "architecture=$image_architecture"
echo "operating_system=$image_operating_system"
echo "created=$image_created"
echo "ipfixprobe_commit=$IPFIXPROBE_COMMIT"
echo "ipfixprobe_version=$actual_ipfixprobe_version"
echo "libfds_commit=$LIBFDS_COMMIT"
echo "ipfixcol2_commit=$IPFIXCOL2_COMMIT"
printf '%s\n' "$runtime_report"
echo "dockerfile_sha256=$dockerfile_hash"
echo "versions_env_sha256=$versions_hash"
