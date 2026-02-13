#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"

execs=50000
trials=3
max_slowdown_pct=20
update_baseline=false
keep=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --execs)
      execs="${2:?missing N}"
      shift 2
      ;;
    --trials)
      trials="${2:?missing N}"
      shift 2
      ;;
    --max-slowdown-pct)
      max_slowdown_pct="${2:?missing percent}"
      shift 2
      ;;
    --update-baseline)
      update_baseline=true
      shift
      ;;
    --keep)
      keep=true
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Usage: bench_grammar_regression.sh [--execs N] [--trials N] [--max-slowdown-pct P] [--update-baseline] [--keep]

Deterministic-ish local performance feedback loop for gosentry grammar fuzzing:
- builds a libFuzzer harness archive from test/gosentry/examples/grammar_json (build-only)
- builds golibafl (Rust) linked against that archive
- runs golibafl in --use-grammar mode for exactly N executions (requires max_execs support)
- prints GOLIBAFL_BENCH_RESULT and compares to a per-machine baseline

Baseline location:
  $XDG_CACHE_HOME/gosentry/bench/grammar_json.execs_per_sec.txt
  (or $HOME/.cache/... if XDG_CACHE_HOME is unset)

Typical flow:
  1) On master:     bash misc/gosentry/scripts/bench_grammar_regression.sh --update-baseline
  2) On your branch: bash misc/gosentry/scripts/bench_grammar_regression.sh
EOF
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -x "${ROOT_DIR}/bin/go" ]]; then
  echo "missing gosentry binary: ${ROOT_DIR}/bin/go" >&2
  echo "build it with: (cd src && ./make.bash) or bash misc/gosentry/scripts/quickcheck.sh" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "missing cargo (Rust toolchain required)" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "missing python3 (required for grammarinator)" >&2
  exit 1
fi

if ! python3 -c 'import grammarinator' >/dev/null 2>&1; then
  echo "missing python module 'grammarinator' (install with: python3 -m pip install --user grammarinator)" >&2
  exit 1
fi

tmp_dir="$(mktemp -d /tmp/gosentry-bench-grammar.XXXXXX)"
if [[ "${keep}" != "true" ]]; then
  cleanup() {
    rm -rf "${tmp_dir}"
  }
  trap cleanup EXIT
fi

export GOCACHE="${tmp_dir}/gocache"
mkdir -p "${GOCACHE}"

example_dir="${ROOT_DIR}/test/gosentry/examples/grammar_json"
harness_out="${tmp_dir}/libharness.a"

cd "${example_dir}"
CGO_ENABLED=1 GOSENTRY_LIBAFL_BUILD_ONLY=1 GOSENTRY_LIBAFL_HARNESS_OUT="${harness_out}" \
  "${ROOT_DIR}/bin/go" test -fuzz=FuzzGrammarJSON --use-libafl --focus-on-new-code=false --catch-races=false --catch-leaks=false .

if [[ ! -f "${harness_out}" ]]; then
  echo "missing harness archive after build-only: ${harness_out}" >&2
  exit 1
fi

cd "${ROOT_DIR}/golibafl"
HARNESS_LIB="${harness_out}" cargo build --release >/dev/null

runner="${ROOT_DIR}/golibafl/target/release/golibafl"
if [[ ! -x "${runner}" ]]; then
  echo "missing golibafl binary: ${runner}" >&2
  exit 1
fi

grammar_file="${example_dir}/testdata/JSON.g4"
seed_text="null"

values_file="${tmp_dir}/values.txt"
for ((i=1; i<=trials; i++)); do
  in_dir="${tmp_dir}/input-${i}"
  out_dir="${tmp_dir}/output-${i}"
  cfg="${tmp_dir}/cfg-${i}.jsonc"
  log="${tmp_dir}/run-${i}.log"

  rm -rf "${in_dir}" "${out_dir}"
  mkdir -p "${in_dir}" "${out_dir}"
  printf '%s' "${seed_text}" > "${in_dir}/seed0"

  cat > "${cfg}" <<EOF
{
  "cores": "0",
  "tui_monitor": false,
  "debug_output": false,
  "catch_hangs": false,
  "initial_generated_inputs": 0,
  "max_execs": ${execs}
}
EOF

  set +e
  LIBAFL_RAND_SEED=0 LIBAFL_SEED_DIR="${in_dir}" "${runner}" fuzz --config "${cfg}" -j 0 -i "${in_dir}" -o "${out_dir}" \
    --use-grammar --grammar "${grammar_file}" --start-rule json \
    >/dev/null 2> "${log}"
  status=$?
  set -e

  if [[ "${status}" -ne 0 ]]; then
    echo "bench run failed (trial ${i}, exit ${status}). log: ${log}" >&2
    exit 1
  fi

  bench_line="$(rg -n \"^GOLIBAFL_BENCH_RESULT\" \"${log}\" | tail -n 1 || true)"
  if [[ -z "${bench_line}" ]]; then
    echo "missing GOLIBAFL_BENCH_RESULT in log (trial ${i}): ${log}" >&2
    exit 1
  fi

  execs_per_sec="$(printf '%s\n' "${bench_line}" | sed -E 's/.*execs_per_sec=([0-9.]+).*/\\1/')"
  if [[ -z "${execs_per_sec}" || "${execs_per_sec}" == "${bench_line}" ]]; then
    echo "failed to parse execs_per_sec from: ${bench_line}" >&2
    exit 1
  fi

  echo "${execs_per_sec}" >> "${values_file}"
done

median="$(sort -n "${values_file}" | awk -v n="${trials}" 'NR==int((n+1)/2){print}')"
echo "bench: grammar_json execs_per_sec=${median} (execs=${execs} trials=${trials})"

baseline_dir="${XDG_CACHE_HOME:-$HOME/.cache}/gosentry/bench"
baseline_file="${baseline_dir}/grammar_json.execs_per_sec.txt"
mkdir -p "${baseline_dir}"

if [[ "${update_baseline}" == "true" ]]; then
  printf '%s\n' "${median}" > "${baseline_file}"
  echo "baseline updated: ${baseline_file}"
  exit 0
fi

if [[ ! -f "${baseline_file}" ]]; then
  printf '%s\n' "${median}" > "${baseline_file}"
  echo "baseline created: ${baseline_file}"
  exit 0
fi

baseline="$(cat "${baseline_file}" | tr -d '[:space:]')"
min_ok="$(awk -v b="${baseline}" -v p="${max_slowdown_pct}" 'BEGIN{printf "%.3f", b*(1.0-p/100.0)}')"

awk -v cur="${median}" -v min="${min_ok}" 'BEGIN{exit !(cur < min)}' && {
  echo "regression: execs_per_sec ${median} < min ${min_ok} (baseline=${baseline}, max_slowdown_pct=${max_slowdown_pct})" >&2
  exit 1
}

echo "ok: execs_per_sec ${median} >= min ${min_ok} (baseline=${baseline}, max_slowdown_pct=${max_slowdown_pct})"
