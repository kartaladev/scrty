#!/usr/bin/env bash
# Usage: ci-needs-check.sh <workflow-file> <aggregate-job-id>
#
# Fails when the aggregate job's `needs` omits any other job id in the
# workflow, so a job added later cannot be left out of the aggregate result.
# Reads the workflow with yq (mikefarah, v4), preinstalled on ubuntu-latest.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: ci-needs-check.sh <workflow-file> <aggregate-job-id>" >&2
  exit 2
fi

workflow=$1
aggregate=$2

all=$(AGG="$aggregate" yq '.jobs | keys | .[]' "$workflow")

if ! grep -Fxq -- "$aggregate" <<<"$all"; then
  echo "ci-needs-check: no job $aggregate in $workflow" >&2
  exit 1
fi
needed=$(AGG="$aggregate" yq '.jobs[strenv(AGG)].needs | ((select(kind == "seq") | .[]), (select(kind == "scalar" and tag != "!!null")))' "$workflow")

status=0
while IFS= read -r id; do
  [ -z "$id" ] && continue
  [ "$id" = "$aggregate" ] && continue
  if ! grep -Fxq -- "$id" <<<"$needed"; then
    echo "ci-needs-check: $aggregate does not need: $id" >&2
    status=1
  fi
done <<<"$all"
exit "$status"
