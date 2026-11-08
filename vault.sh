#!/bin/sh
# KeePassAI vault gate - macOS / Linux wrapper. Usage: /path/to/vault.sh <command> ...
set -e
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PY="${KEEPASSAI_PYTHON:-${KEEPASSAI_HOME:-$HOME/.keepassai}/venv/bin/python}"
[ -x "$PY" ] || { echo "ERROR: Python not found: $PY (see INSTALL.md)" >&2; exit 3; }
exec "$PY" -I "$DIR/vault.py" "$@"
