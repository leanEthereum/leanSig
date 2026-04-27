#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_BASE="${1:-$ROOT_DIR/target/demo-perf}"
THREAD_DIR="$OUT_BASE/threaded"
SCALAR_DIR="$OUT_BASE/scalar"

run_bench() {
  local label="$1"
  local target_dir="$2"
  shift 2

  printf '\n[%s]\n' "$label"
  printf 'target dir: %s\n' "$target_dir"
  mkdir -p "$target_dir"

  (
    cd "$ROOT_DIR"
    CARGO_TARGET_DIR="$target_dir" cargo bench "$@" --bench demo_perf -- --noplot
  )
}

run_bench "native threaded (default features)" "$THREAD_DIR"
run_bench "native scalar (no rayon)" "$SCALAR_DIR" --no-default-features

printf '\nCriterion outputs were written to:\n'
printf '  %s\n' "$THREAD_DIR"
printf '  %s\n' "$SCALAR_DIR"

if python3 -c 'import tabulate' >/dev/null 2>&1; then
  printf '\nThreaded summary:\n'
  python3 "$ROOT_DIR/benchmark-mean.py" "$THREAD_DIR"
  printf '\nScalar summary:\n'
  python3 "$ROOT_DIR/benchmark-mean.py" "$SCALAR_DIR"
else
  printf '\nInstall python tabulate to render summaries with benchmark-mean.py:\n'
  printf '  python3 -m pip install tabulate\n'
fi
