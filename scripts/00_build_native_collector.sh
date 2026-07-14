#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSIONS="$ROOT/docker/versions.env"

LIBFDS_SOURCE="$ROOT/third_party/libfds"
LIBFDS_BUILD="$ROOT/.build/libfds"
LIBFDS_STAGE="$ROOT/.stage/libfds"

IPFIXCOL2_SOURCE="$ROOT/third_party/ipfixcol2"
IPFIXCOL2_BUILD="$ROOT/.build/ipfixcol2"
IPFIXCOL2_STAGE="$ROOT/.stage/ipfixcol2"

if [[ ! -f "$VERSIONS" ]]; then
    echo "ERROR: missing version file: $VERSIONS" >&2
    exit 1
fi

set -a
source "$VERSIONS"
set +a

required_variables=(
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

for command in git cmake gcc-14 g++-14 pkg-config make nproc ldd; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $command" >&2
        exit 1
    fi
done

mkdir -p "$ROOT/third_party" "$ROOT/.build" "$ROOT/.stage"

prepare_source() {
    local repository="$1"
    local commit="$2"
    local source_dir="$3"
    local project_name="$4"

    if [[ ! -d "$source_dir/.git" ]]; then
        git clone --filter=blob:none "$repository" "$source_dir"
    fi

    if [[ -n "$(git -C "$source_dir" status --porcelain)" ]]; then
        echo "ERROR: $project_name source tree contains local changes:" >&2
        git -C "$source_dir" status --short >&2
        exit 1
    fi

    git -C "$source_dir" fetch --tags --force
    git -C "$source_dir" checkout --detach "$commit"

    local actual_commit
    actual_commit="$(git -C "$source_dir" rev-parse HEAD)"

    if [[ "$actual_commit" != "$commit" ]]; then
        echo "ERROR: expected $project_name commit $commit," \
             "found $actual_commit" >&2
        exit 1
    fi
}

prepare_source \
    "$LIBFDS_REPOSITORY" \
    "$LIBFDS_COMMIT" \
    "$LIBFDS_SOURCE" \
    "libfds"

prepare_source \
    "$IPFIXCOL2_REPOSITORY" \
    "$IPFIXCOL2_COMMIT" \
    "$IPFIXCOL2_SOURCE" \
    "ipfixcol2"

rm -rf "$LIBFDS_BUILD" "$LIBFDS_STAGE"

cmake \
    -S "$LIBFDS_SOURCE" \
    -B "$LIBFDS_BUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=gcc-14 \
    -DCMAKE_CXX_COMPILER=g++-14 \
    -DCMAKE_INSTALL_PREFIX="$LIBFDS_STAGE" \
    -DENABLE_DOC_DOXYGEN=OFF \
    -DENABLE_TESTS=OFF

cmake --build "$LIBFDS_BUILD" -j"$(nproc)"
cmake --install "$LIBFDS_BUILD"

LIBFDS_PKGCONFIG="$LIBFDS_STAGE/lib/pkgconfig"
LIBFDS_LIBRARY_PATH="$LIBFDS_STAGE/lib"
LIBFDS_DEFINITIONS="$LIBFDS_STAGE/etc/libfds"

for required_path in \
    "$LIBFDS_LIBRARY_PATH/libfds.so.0" \
    "$LIBFDS_PKGCONFIG/libfds.pc" \
    "$LIBFDS_DEFINITIONS/system/elements/iana.xml"; do
    if [[ ! -e "$required_path" ]]; then
        echo "ERROR: expected libfds installation path not found:" \
             "$required_path" >&2
        exit 1
    fi
done

actual_libfds_version="$(
    PKG_CONFIG_PATH="$LIBFDS_PKGCONFIG" \
        pkg-config --modversion libfds
)"

if [[ "$actual_libfds_version" != "$LIBFDS_VERSION" ]]; then
    echo "ERROR: expected libfds version $LIBFDS_VERSION," \
         "found $actual_libfds_version" >&2
    exit 1
fi

rm -rf "$IPFIXCOL2_BUILD" "$IPFIXCOL2_STAGE"

PKG_CONFIG_PATH="$LIBFDS_PKGCONFIG" \
CMAKE_PREFIX_PATH="$LIBFDS_STAGE" \
LD_LIBRARY_PATH="$LIBFDS_LIBRARY_PATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
cmake \
    -S "$IPFIXCOL2_SOURCE" \
    -B "$IPFIXCOL2_BUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=gcc-14 \
    -DCMAKE_CXX_COMPILER=g++-14 \
    -DCMAKE_INSTALL_PREFIX="$IPFIXCOL2_STAGE" \
    -DENABLE_DOC_MANPAGE=OFF \
    -DENABLE_DOC_DOXYGEN=OFF \
    -DENABLE_TESTS=OFF

PKG_CONFIG_PATH="$LIBFDS_PKGCONFIG" \
CMAKE_PREFIX_PATH="$LIBFDS_STAGE" \
LD_LIBRARY_PATH="$LIBFDS_LIBRARY_PATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
cmake --build "$IPFIXCOL2_BUILD" -j"$(nproc)"

cmake --install "$IPFIXCOL2_BUILD"

IPFIXCOL2_BIN="$IPFIXCOL2_STAGE/bin/ipfixcol2"
IPFIXCOL2_PLUGINS="$IPFIXCOL2_STAGE/lib/ipfixcol2"

for required_path in \
    "$IPFIXCOL2_BIN" \
    "$IPFIXCOL2_PLUGINS/libtcp-input.so" \
    "$IPFIXCOL2_PLUGINS/libjson-output.so"; do
    if [[ ! -e "$required_path" ]]; then
        echo "ERROR: expected ipfixcol2 installation path not found:" \
             "$required_path" >&2
        exit 1
    fi
done

version_output="$(
    LD_LIBRARY_PATH="$LIBFDS_LIBRARY_PATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        "$IPFIXCOL2_BIN" -V
)"

actual_ipfixcol2_version="$(
    printf '%s\n' "$version_output" |
    awk -F: '
        /^Version:/ {
            value=$2
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            print value
        }
    '
)"

if [[ "$actual_ipfixcol2_version" != "$IPFIXCOL2_VERSION" ]]; then
    echo "ERROR: expected ipfixcol2 version $IPFIXCOL2_VERSION," \
         "found $actual_ipfixcol2_version" >&2
    exit 1
fi

if ! printf '%s\n' "$version_output" |
    grep -qE '^Compiler:[[:space:]]+GNU 14\.'; then
    echo "ERROR: ipfixcol2 was not built with GCC 14" >&2
    printf '%s\n' "$version_output" >&2
    exit 1
fi

PLUGIN_LIST="$IPFIXCOL2_BUILD/plugin-list.txt"

LD_LIBRARY_PATH="$LIBFDS_LIBRARY_PATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$IPFIXCOL2_BIN" \
    -p "$IPFIXCOL2_PLUGINS" \
    -e "$LIBFDS_DEFINITIONS" \
    -L >"$PLUGIN_LIST"

plugin_version() {
    local target="$1"

    awk -v target="$target" '
        {
            line=$0
            gsub(/\033\[[0-9;]*m/, "", line)
        }

        line ~ /^- Name[[:space:]]*:/ {
            name=line
            sub(/^.*:[[:space:]]*/, "", name)
            active=(name == target)
            next
        }

        active && line ~ /^[[:space:]]*Version[[:space:]]*:/ {
            version=line
            sub(/^.*:[[:space:]]*/, "", version)
            print version
            exit
        }
    ' "$PLUGIN_LIST"
}

actual_tcp_plugin_version="$(plugin_version tcp)"
actual_json_plugin_version="$(plugin_version json)"

if [[ "$actual_tcp_plugin_version" != \
      "$IPFIXCOL2_TCP_PLUGIN_VERSION" ]]; then
    echo "ERROR: expected TCP plugin version" \
         "$IPFIXCOL2_TCP_PLUGIN_VERSION," \
         "found ${actual_tcp_plugin_version:-missing}" >&2
    exit 1
fi

if [[ "$actual_json_plugin_version" != \
      "$IPFIXCOL2_JSON_PLUGIN_VERSION" ]]; then
    echo "ERROR: expected JSON plugin version" \
         "$IPFIXCOL2_JSON_PLUGIN_VERSION," \
         "found ${actual_json_plugin_version:-missing}" >&2
    exit 1
fi

for binary in \
    "$IPFIXCOL2_BIN" \
    "$IPFIXCOL2_PLUGINS/libtcp-input.so" \
    "$IPFIXCOL2_PLUGINS/libjson-output.so"; do
    if LD_LIBRARY_PATH="$LIBFDS_LIBRARY_PATH" \
        ldd "$binary" |
        grep -q 'not found'; then
        echo "ERROR: unresolved dynamic dependency in $binary" >&2
        LD_LIBRARY_PATH="$LIBFDS_LIBRARY_PATH" ldd "$binary" >&2
        exit 1
    fi
done

echo "Native collector build passed"
echo "compiler=gcc-14/g++-14"
echo "libfds_commit=$LIBFDS_COMMIT"
echo "libfds_version=$actual_libfds_version"
echo "ipfixcol2_commit=$IPFIXCOL2_COMMIT"
echo "ipfixcol2_version=$actual_ipfixcol2_version"
echo "tcp_plugin_version=$actual_tcp_plugin_version"
echo "json_plugin_version=$actual_json_plugin_version"
echo "libfds_stage=$LIBFDS_STAGE"
echo "ipfixcol2_stage=$IPFIXCOL2_STAGE"
