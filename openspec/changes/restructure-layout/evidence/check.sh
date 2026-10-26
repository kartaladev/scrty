#!/usr/bin/env bash
# check.sh [tests|api|coverage|all]... [-- FRESH_DIR]
#
# Compares the working tree's D13 inventory with evidence/baseline through rename-map.tsv.
# Without "-- FRESH_DIR" it first captures a fresh inventory with capture.sh into a temporary
# directory (printed, and kept for inspection). Exits 1 if any entry is unaccounted for.
#
# Needs apidiff: set APIDIFF, or put it on PATH (see README.md for the install line).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export APIDIFF=${APIDIFF:-$(command -v apidiff || true)}
[ -x "$APIDIFF" ] || { echo "apidiff not found: set APIDIFF (see README.md)" >&2; exit 2; }
export EMPTY_EXPORT=${EMPTY_EXPORT:-$here/empty.export}

checks=() fresh=
while [ $# -gt 0 ]; do
	case "$1" in
	--) fresh=${2:?missing FRESH_DIR}; shift 2 ;;
	*) checks+=("$1"); shift ;;
	esac
done
if [ -z "$fresh" ]; then
	fresh=$(mktemp -d "${TMPDIR:-/tmp}/restructure-evidence.XXXXXX")
	echo "capturing a fresh inventory into $fresh"
	"$here/capture.sh" "$fresh"
fi
exec python3 "$here/check.py" "$here" "$fresh" "${checks[@]}"
