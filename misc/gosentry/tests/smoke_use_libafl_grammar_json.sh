#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/misc/gosentry/tests/smoke_use_libafl_common.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
export GOCACHE="${tmp_dir}/gocache"

cd "${ROOT_DIR}/test/gosentry/examples/grammar_json"
in_dir="$(libafl_input_dir FuzzGrammarJSON)"
mkdir -p "${in_dir}"

output="${tmp_dir}/output.txt"
set +e
GOSENTRY_VERBOSE_AFL=1 CGO_ENABLED=1 timeout 5m "${ROOT_DIR}/bin/go" test -fuzz=FuzzGrammarJSON --use-libafl --use-grammar --grammar=testdata/JSON.json --focus-on-new-code=false --catch-races=false --catch-leaks=false . 2>&1 | tee "${output}"
status="${PIPESTATUS[0]}"
set -e

if [[ "${status}" -ne 124 && "${status}" -ne 143 ]]; then
  echo "expected fuzz run to be terminated by timeout (exit 124/143), got ${status}"
  exit 1
fi

if grep -Eq "${GOSENTRY_LIBAFL_CRASH_RE}" "${output}"; then
  echo "unexpected crash summary in output"
  exit 1
fi

if grep -q "invalid JSON" "${output}"; then
  echo "grammar fuzzing produced invalid JSON"
  exit 1
fi

if ! grep -q "golibafl: nautilus enabled" "${output}"; then
  echo "expected golibafl to enable nautilus"
  exit 1
fi

if ! grep -q "GOLIBAFL_MUTATED_INPUT" "${output}"; then
  echo "expected mutated inputs to be printed (GOLIBAFL_MUTATED_INPUT)"
  exit 1
fi
