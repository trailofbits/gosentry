#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/misc/gosentry/tests/smoke_use_libafl_common.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
export GOCACHE="${tmp_dir}/gocache"

cd "${ROOT_DIR}/test/gosentry/examples/overflow"
in_dir="$(libafl_input_dir FuzzUint8Overflow)"
mkdir -p "${in_dir}"
# Trigger gosentry's uint8 overflow check quickly and deterministically.
printf '\xFF\x01' > "${in_dir}/seed-crash"

run_expect_crash overflow FuzzUint8Overflow 5m "${tmp_dir}/output.txt"

grep -Fq "integer overflow in uint8 addition operation" "${tmp_dir}/output.txt"
