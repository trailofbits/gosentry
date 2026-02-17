#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/misc/gosentry/tests/smoke_use_libafl_common.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
export GOCACHE="${tmp_dir}/gocache"
export LIBAFL_RAND_SEED=1

output="${tmp_dir}/output.txt"
run_expect_crash grammar_json_cmplog_i2s FuzzGrammarJSONCmpLogI2S 5m "${output}" \
  --use-grammar --grammar=testdata/JSON_CMPLOG_I2S.json

if ! grep -q "GOSENTRY_NAUTILUS_CMPLOG_I2S_OK" "${output}"; then
  echo "expected panic marker to be printed (GOSENTRY_NAUTILUS_CMPLOG_I2S_OK)"
  exit 1
fi

