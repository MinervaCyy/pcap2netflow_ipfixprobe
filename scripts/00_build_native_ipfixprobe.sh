#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSIONS="$ROOT/docker/versions.env"
SOURCE_DIR="$ROOT/third_party/ipfixprobe"
BUILD_DIR="$ROOT/build/ipfixprobe-native"
STAGE_DIR="$ROOT/.stage/ipfixprobe"

if [[ ! -f "$VERSIONS" ]]; then
    echo "ERROR: missing version file: $VERSIONS" >&2
    exit 1
fi

set -a
source "$VERSIONS"
set +a

for cmd in git cmake gcc-14 g++-14; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $cmd" >&2
        exit 1
    fi
done

mkdir -p "$ROOT/third_party"

if [[ ! -d "$SOURCE_DIR/.git" ]]; then
    git clone --filter=blob:none "$IPFIXPROBE_REPOSITORY" "$SOURCE_DIR"
fi

git -C "$SOURCE_DIR" fetch --tags --force
git -C "$SOURCE_DIR" checkout --detach "$IPFIXPROBE_COMMIT"

actual_commit="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
if [[ "$actual_commit" != "$IPFIXPROBE_COMMIT" ]]; then
    echo "ERROR: expected commit $IPFIXPROBE_COMMIT, found $actual_commit" >&2
    exit 1
fi

cmake \
    -S "$SOURCE_DIR" \
    -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=gcc-14 \
    -DCMAKE_CXX_COMPILER=g++-14 \
    -DENABLE_INPUT_PCAP=ON

cmake --build "$BUILD_DIR" -j"$(nproc)"

rm -rf "$STAGE_DIR"
DESTDIR="$STAGE_DIR" cmake --install "$BUILD_DIR"

BIN="$STAGE_DIR/usr/local/bin/ipfixprobe"
PLUGINS="$STAGE_DIR/usr/local/lib/ipfixprobe"

version="$("$BIN" --plugins-path "$PLUGINS" --version)"
if [[ "$version" != "5.7.0" ]]; then
    echo "ERROR: unexpected ipfixprobe version: $version" >&2
    exit 1
fi

"$BIN" --plugins-path "$PLUGINS" --help pcap >/dev/null
"$BIN" --plugins-path "$PLUGINS" --help text >/dev/null
"$BIN" --plugins-path "$PLUGINS" --help cache >/dev/null

echo "Native ipfixprobe build passed"
echo "commit=$actual_commit"
echo "version=$version"
echo "binary=$BIN"
echo "plugins=$PLUGINS"
