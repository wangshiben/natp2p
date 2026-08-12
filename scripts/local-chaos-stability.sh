#!/usr/bin/env bash

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STABILITY_SCRIPT=$ROOT_DIR/test/runtimeScript/local-chaos-stability.sh

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  source "$STABILITY_SCRIPT"
else
  exec bash "$STABILITY_SCRIPT" "$@"
fi
