#!/usr/bin/env bash
set -euo pipefail

exec /usr/local/bin/ipfixprobe \
    --plugins-path /usr/local/lib/ipfixprobe \
    "$@"
