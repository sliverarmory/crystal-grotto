#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail

readonly UPSTREAM_URL="https://tradecraftgarden.org/download/cpsrc20260716.tgz"
readonly UPSTREAM_SHA256="d93563767130adc525f80bfabdecbbe7f803595356f0aec7cf1669490e529855"
readonly UPSTREAM_DIRECTORY="cpsrc"

usage() {
  printf 'Usage: %s DESTINATION\n' "${0##*/}" >&2
  printf 'Fetch, verify, extract, and build the pinned Crystal Palace source.\n' >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

destination=$1
if [[ -z "$destination" || "$destination" == "/" ]]; then
  printf 'Refusing unsafe destination: %q\n' "$destination" >&2
  exit 2
fi

for command_name in curl tar ant; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$command_name" >&2
    exit 1
  fi
done

if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  printf 'Required SHA-256 utility not found (need sha256sum or shasum).\n' >&2
  exit 1
fi

mkdir -p "$destination"
destination=$(cd "$destination" && pwd -P)

if [[ -e "$destination/$UPSTREAM_DIRECTORY" ]]; then
  printf 'Refusing to overwrite existing path: %s\n' "$destination/$UPSTREAM_DIRECTORY" >&2
  exit 1
fi

archive=$(mktemp "$destination/.cpsrc20260716.tgz.XXXXXX")
cleanup() {
  rm -f "$archive"
}
trap cleanup EXIT

printf 'Downloading %s\n' "$UPSTREAM_URL"
curl \
  --proto '=https' \
  --tlsv1.2 \
  --fail \
  --location \
  --connect-timeout 15 \
  --max-time 120 \
  --retry 3 \
  --retry-delay 2 \
  --retry-all-errors \
  --silent \
  --show-error \
  --output "$archive" \
  "$UPSTREAM_URL"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256=$(sha256sum "$archive" | awk '{print $1}')
else
  actual_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
fi

if [[ "$actual_sha256" != "$UPSTREAM_SHA256" ]]; then
  printf 'SHA-256 mismatch: expected %s, got %s\n' "$UPSTREAM_SHA256" "$actual_sha256" >&2
  exit 1
fi

printf 'Verified Crystal Palace source archive (%s).\n' "$UPSTREAM_SHA256"
tar -xzf "$archive" -C "$destination"

if [[ ! -f "$destination/$UPSTREAM_DIRECTORY/build.xml" ]]; then
  printf 'Pinned archive did not contain %s/build.xml\n' "$UPSTREAM_DIRECTORY" >&2
  exit 1
fi

(
  cd "$destination/$UPSTREAM_DIRECTORY"
  ant clean all
)

jar_path="$destination/$UPSTREAM_DIRECTORY/build/crystalpalace.jar"
if [[ ! -f "$jar_path" ]]; then
  printf 'Crystal Palace build did not produce %s\n' "$jar_path" >&2
  exit 1
fi

printf 'Crystal Palace JAR: %s\n' "$jar_path"
