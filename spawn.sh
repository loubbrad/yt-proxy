#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec uv run --project "$SCRIPT_DIR" python "$SCRIPT_DIR/spawn.py" "$@"
