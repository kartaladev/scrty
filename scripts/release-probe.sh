#!/usr/bin/env bash
# Proves a released version resolves from outside the repository, through the
# public proxy and checksum database, the way a consumer's build sees it.
#
# Usage: release-probe.sh vX.Y.Z[-prerelease]
#
# Optional environment:
#   PROBE_RETRIES         attempts per module, 1 to 60 (default 10)
#   PROBE_RETRY_DELAY     seconds between attempts, 0 to 300 (default 30)
#   RELEASE_MODULES_FILE  the module list, one "<dir> <import path>" per line
#                         (default: release-modules.txt at the repository root)
set -euo pipefail

readonly scrty="github.com/kartaladev/scrty"

die() {
	echo "probe: $*" >&2
	exit 2
}

# is_uint reports whether $1 is a plain non-negative decimal without a leading zero.
is_uint() {
	[[ "$1" =~ ^(0|[1-9][0-9]*)$ ]]
}

# --- input: validated before any network call -------------------------------

[ "$#" -eq 1 ] || die "usage: release-probe.sh vX.Y.Z"
version="$1"
semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z-]+)*)?$'
[[ "$version" =~ $semver ]] || die "version '$version' is not vX.Y.Z with an optional prerelease"

retries="${PROBE_RETRIES:-10}"
is_uint "$retries" && [ "$retries" -ge 1 ] && [ "$retries" -le 60 ] ||
	die "PROBE_RETRIES '$retries' must be a whole number from 1 to 60"
delay="${PROBE_RETRY_DELAY:-30}"
is_uint "$delay" && [ "$delay" -le 300 ] ||
	die "PROBE_RETRY_DELAY '$delay' must be a whole number from 0 to 300"

root="$(cd "$(dirname "$0")/.." && pwd)"
modules_file="${RELEASE_MODULES_FILE:-$root/release-modules.txt}"
[ -f "$modules_file" ] || die "module list '$modules_file' not found"

dirs=()
imports=("$scrty/session")
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
	lineno=$((lineno + 1))
	[ -n "${line//[[:space:]]/}" ] || continue
	read -r d pkg extra <<<"$line"
	if [ -z "${d:-}" ] || [ -z "${pkg:-}" ] || [ -n "${extra:-}" ] ||
		[[ ! "$d" =~ ^[a-z0-9][A-Za-z0-9._/-]*$ ]] || [[ "$d" == *..* ]] ||
		[[ "$pkg" != "$scrty/$d" && "$pkg" != "$scrty/$d/"* ]]; then
		die "$modules_file line $lineno is malformed: '$line' (want '<dir> <import path under $scrty/<dir>>')"
	fi
	dirs+=("$d")
	imports+=("$pkg")
done <"$modules_file"
[ "${#dirs[@]}" -gt 0 ] || die "module list '$modules_file' names no modules"

command -v go >/dev/null 2>&1 || die "go is not on PATH"

# --- environment: what a consumer's build sees ------------------------------

# GOENV=off: settings saved with `go env -w` (GOPRIVATE, GONOSUMDB, GOFLAGS, ...)
# would otherwise refill what is unset here, and let the probe pass without
# the public proxy and checksum database vouching for every module.
unset GOFLAGS GONOSUMDB GONOSUMCHECK GOPRIVATE GOINSECURE GONOPROXY GOVCS
export GOENV=off GOTOOLCHAIN=local GOWORK=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org

tmp_base="${TMPDIR:-/tmp}"
tmp_base="${tmp_base%/}"
dir="$(mktemp -d "$tmp_base/release-probe.XXXXXX")"

cleanup() {
	# Never remove anything that is not the directory made above. The module
	# cache is written read-only, so make it writable first.
	case "$dir" in
	"$tmp_base"/release-probe.?*)
		chmod -R u+w "$dir" 2>/dev/null || true
		rm -rf -- "$dir"
		;;
	*) echo "probe: refusing to remove '$dir'" >&2 ;;
	esac
}
trap cleanup EXIT

# A private module cache and GOPATH: a copy cached on the runner would let the
# probe pass without the proxy serving the version.
export GOPATH="$dir/gopath" GOMODCACHE="$dir/gopath/pkg/mod"

go env GOPROXY GOSUMDB GONOSUMDB GOPRIVATE GOFLAGS GOWORK GOMODCACHE

mkdir "$dir/probe"
cd "$dir/probe"
go mod init probe.example >/dev/null 2>&1 || die "go mod init failed"

fetch() {
	local mod="$1" n=1
	until go get "$mod@$version"; do
		if [ "$n" -ge "$retries" ]; then
			echo "probe: $mod@$version did not resolve" >&2
			echo "probe: release $version failed; fix it with a new version, never by moving a tag (RELEASING.md)" >&2
			return 1
		fi
		n=$((n + 1))
		sleep "$delay"
	done
}

fetch "$scrty"
for d in "${dirs[@]}"; do
	fetch "$scrty/$d"
done

{
	echo 'package main'
	echo 'import ('
	for p in "${imports[@]}"; do
		echo "	_ \"$p\""
	done
	echo ')'
	echo 'func main() {}'
} >main.go

go build -mod=mod ./... || die "probe program importing every published module did not build at $version; fix it with a new version, never by moving a tag (RELEASING.md)"
echo "probe: $version resolves for every published module"
