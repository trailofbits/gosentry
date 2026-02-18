#!/usr/bin/env bash
#
# Common helpers for the gosentry --use-libafl smoke tests.
#
# Expected environment:
# - ROOT_DIR: repo root
# - GOCACHE: set by the caller (typically to a temp dir)

GOSENTRY_LIBAFL_CRASH_RE='Found [1-9][0-9]* (pre-existing )?crashing input\(s\)\.'

run_expect_crash() {
  local example_dir="${1}"
  local fuzz_name="${2}"
  local timeout_dur="${3}"
  local output_file="${4}"
  shift 4

  cd "${ROOT_DIR}/test/gosentry/examples/${example_dir}"
  set +e
  CGO_ENABLED=1 timeout "${timeout_dur}" "${ROOT_DIR}/bin/go" test -fuzz="${fuzz_name}" --use-libafl --focus-on-new-code=false --catch-races=false --catch-leaks=false "$@" 2>&1 | tee "${output_file}"
  local status="${PIPESTATUS[0]}"
  set -e

  if [[ "${status}" -eq 0 ]]; then
    echo "expected fuzz run to fail (panic/crash), but it exited 0"
    exit 1
  fi

  local in_dir out_dir crashes_dir
  in_dir="$(libafl_input_dir "${fuzz_name}")"
  out_dir="$(dirname "${in_dir}")"
  crashes_dir="${out_dir}/crashes"

  if [[ "${status}" -eq 124 || "${status}" -eq 137 || "${status}" -eq 143 ]]; then
    echo "expected fuzz run to stop on crash, but it timed out (exit ${status})"
    echo "output file: ${output_file}"
    echo "crashes dir: ${crashes_dir}"
    exit 1
  fi

  if ! grep -Eq "${GOSENTRY_LIBAFL_CRASH_RE}" "${output_file}"; then
    echo "expected output to contain: Found N crashing input(s)."
    echo "output file: ${output_file}"
    echo "crashes dir: ${crashes_dir}"
    exit 1
  fi

  if [[ ! -d "${crashes_dir}" ]] || ! find "${crashes_dir}" -maxdepth 1 -type f ! -name '.*' -print -quit | grep -q .; then
    echo "expected crashes dir to contain at least one crash input: ${crashes_dir}"
    exit 1
  fi
}

libafl_input_dir() {
  local fuzz_pattern="${1}"

  local pkg dir
  pkg="$("${ROOT_DIR}/bin/go" list -f '{{.ImportPath}}')"
  dir="$("${ROOT_DIR}/bin/go" list -f '{{.Dir}}')"

  local root
  root="$("${ROOT_DIR}/bin/go" list -f '{{.Root}}')"
  if [[ -z "${root}" ]]; then
    root="${dir}"
  fi

  local base
  base="$(basename "${root}")"
  if [[ -z "${base}" || "${base}" == "." || "${base}" == "/" ]]; then
    base="project"
  fi

  local root_hash
  root_hash="$(printf '%s' "${root}" | sha256sum | awk '{print $1}')"
  local project_key="${base}-${root_hash:0:24}"

  local harness_key
  if [[ "${fuzz_pattern}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    harness_key="${fuzz_pattern}"
  elif [[ "${fuzz_pattern}" =~ ^\\^([A-Za-z_][A-Za-z0-9_]*)\\$$ ]]; then
    harness_key="${BASH_REMATCH[1]}"
  else
    local pat_hash
    pat_hash="$(printf '%s' "${fuzz_pattern}" | sha256sum | awk '{print $1}')"
    harness_key="pattern-${pat_hash:0:24}"
  fi

  echo "${GOCACHE}/fuzz/${pkg}/libafl/${project_key}/${harness_key}/input"
}
