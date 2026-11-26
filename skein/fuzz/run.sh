#!/usr/bin/env bash
# Usage: fuzz/run.sh build | list | all [secs] | replay <target> <file> | <target> [secs] [libFuzzer flags...]
# Read-only seed directories per target come from fuzz/seeds (lines "<target> <dir relative to fuzz/>").
set -euo pipefail
caller=$PWD
cd "$(dirname "$0")"
RUSTUP_TOOLCHAIN=$(sed -n 's/^channel *= *"\(.*\)"$/\1/p' rust-toolchain.toml)
export RUSTUP_TOOLCHAIN
export CARGO_TARGET_DIR="$PWD/target"

from_caller() {
  case $1 in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$caller" "$1" ;;
  esac
}

seeds() {
  [ -f seeds ] || return 0
  awk -v t="$1" '$1 == t { print $2 }' seeds | while read -r dir; do
    [ -d "$dir" ] && echo "$dir"
  done
}

fuzz() {
  local target=$1 secs=$2
  shift 2
  mkdir -p "work/$target" "corpus/$target" "artifacts/$target"
  local extra=()
  while read -r dir; do
    [ -n "$dir" ] && extra+=("$dir")
  done < <(seeds "$target")
  cargo fuzz run --fuzz-dir "$PWD" -s none "$target" "work/$target" "corpus/$target" ${extra[@]+"${extra[@]}"} -- \
    -max_total_time="$secs" -rss_limit_mb=2048 -timeout=10 -max_len=65536 \
    -artifact_prefix="artifacts/$target/" -print_final_stats=1 "$@"
}

case "${1:-}" in
  "") echo "usage: $0 build | list | all [secs] | replay <target> <file> | <target> [secs]" >&2; exit 2 ;;
  build) cargo fuzz build --fuzz-dir "$PWD" -s none ;;
  list) cargo fuzz list --fuzz-dir "$PWD" ;;
  replay)
    [ $# -eq 3 ] || { echo "usage: $0 replay <target> <file>" >&2; exit 2; }
    cargo fuzz run --fuzz-dir "$PWD" -s none "$2" "$(from_caller "$3")"
    ;;
  all)
    secs=${2:-60}
    cargo fuzz build --fuzz-dir "$PWD" -s none
    failed=0
    for target in $(cargo fuzz list --fuzz-dir "$PWD"); do
      fuzz "$target" "$secs" || { echo "fuzz target $target failed" >&2; failed=1; }
    done
    exit "$failed"
    ;;
  *)
    target=$1
    secs=${2:-60}
    shift $(($# < 2 ? $# : 2))
    fuzz "$target" "$secs" "$@"
    ;;
esac
