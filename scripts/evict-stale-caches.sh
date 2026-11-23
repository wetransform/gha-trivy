#!/usr/bin/env bash
#
# Delete outdated scanner database caches of the repository.
#
# Caches are scoped to the ref they were saved for (e.g. one per pull request), so outdated
# copies of the databases pile up across refs until GitHub evicts them. This removes caches
# whose key starts with the given prefix and sorts before the current key (keys are expected
# to sort by age). Caches with a newer key, saved by a run that started later, are kept.
#
# A run can only restore caches of its own ref and of the default branch. By default an outdated
# cache is therefore only deleted if the cache with the current key exists for the same ref or
# for the default branch, so no ref loses the cache it would fall back to.
# With `--any-ref` an outdated cache is deleted as soon as the current key exists for any ref.
# Use this for caches that are only ever restored by their exact key.
#
# Cleaning up is optional: if the caches cannot be listed or deleted (e.g. the token lacks the
# `actions: write` permission or the gh CLI is missing), a notice is printed and nothing else is done.
#
# Usage: evict-stale-caches.sh <key-prefix> <current-key> [--any-ref]
# Environment:
#   GH_TOKEN          - token with `actions: write` permission
#   GITHUB_REPOSITORY - repository to clean up
#   DEFAULT_REF       - ref of the default branch, e.g. refs/heads/main (optional)

set -euo pipefail

# compare keys byte-wise, independent of the runner's locale
export LC_ALL=C

PREFIX="${1:-}"
CURRENT="${2:-}"
MODE="${3:-}"

if [ -z "$PREFIX" ] || [ -z "$CURRENT" ]; then
  echo "Key prefix and current key are required" >&2
  exit 1
fi

if ! command -v gh > /dev/null; then
  echo "::notice::Skipping cleanup of outdated caches: gh CLI not available"
  exit 0
fi

if ! CACHES=$(gh cache list --repo "$GITHUB_REPOSITORY" --key "$PREFIX" --limit 100 \
  --json id,key,ref --jq '.[] | [.id, .key, .ref] | @tsv'); then
  echo "::notice::Skipping cleanup of outdated caches: could not list caches (e.g. missing 'actions: write' permission)"
  exit 0
fi

# refs for which the cache with the current key exists
CURRENT_REFS=$(awk -F'\t' -v key="$CURRENT" '$2 == key { print $3 }' <<< "$CACHES")

if [ -z "$CURRENT_REFS" ]; then
  echo "No cache with key $CURRENT found, not deleting any caches"
  exit 0
fi

has_current() {
  grep -Fxq -- "$1" <<< "$CURRENT_REFS"
}

while IFS=$'\t' read -r ID KEY REF; do
  # only keys starting with the prefix that are older than the current key
  if [ -z "$ID" ] || [ "${KEY#"$PREFIX"}" = "$KEY" ] || [[ ! "$KEY" < "$CURRENT" ]]; then
    continue
  fi
  if [ "$MODE" = "--any-ref" ] || has_current "$REF" \
    || { [ -n "${DEFAULT_REF:-}" ] && has_current "$DEFAULT_REF"; }; then
    echo "Deleting outdated cache $KEY of $REF ($ID)"
    if ! gh cache delete "$ID" --repo "$GITHUB_REPOSITORY"; then
      # most likely a read-only token (e.g. pull request from a fork), further attempts would fail as well
      echo "::notice::Stopping cleanup of outdated caches: could not delete cache (e.g. missing 'actions: write' permission)"
      break
    fi
  fi
done <<< "$CACHES"
