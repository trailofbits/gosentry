#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"

duration="10s"
keep=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--timeout|--duration)
      duration="${2:?missing duration (example: 10s)}"
      shift 2
      ;;
    --keep)
      keep=true
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Usage: bench_libafl_reverse.sh [--duration 10s] [--keep]

Runs a short LibAFL fuzz campaign on test/gosentry/examples/reverse and prints
queue/crash corpus counts from the on-disk LibAFL output directory.
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

workdir="$(mktemp -d /tmp/gosentry-bench-libafl-reverse.XXXXXX)"
if [[ "${keep}" != "true" ]]; then
  cleanup() {
    rm -rf "${workdir}"
  }
  trap cleanup EXIT
fi

export ROOT_DIR
export GOCACHE="${workdir}/gocache"
mkdir -p "${GOCACHE}"

source "${ROOT_DIR}/misc/gosentry/tests/smoke_use_libafl_common.sh"

cd "${ROOT_DIR}/test/gosentry/examples/reverse"

echo "workdir: ${workdir}"
echo "gocache: ${GOCACHE}"
echo "running: go test -fuzz=FuzzReverse (timeout=${duration})"

set +e
CGO_ENABLED=1 timeout "${duration}" "${ROOT_DIR}/bin/go" test -fuzz=FuzzReverse --use-libafl --focus-on-new-code=false --catch-races=false --catch-leaks=false . 2>&1 | tee "${workdir}/out.log"
set -e

in_dir="$(libafl_input_dir FuzzReverse)"
out_dir="$(dirname "${in_dir}")"

queue_dir="${out_dir}/queue"
crashes_dir="${out_dir}/crashes"

queue_n=0
if [[ -d "${queue_dir}" ]]; then
  queue_n="$(find "${queue_dir}" -maxdepth 1 -type f ! -name '.*' | wc -l | tr -d '[:space:]')"
fi

crashes_n=0
if [[ -d "${crashes_dir}" ]]; then
  crashes_n="$(find "${crashes_dir}" -maxdepth 1 -type f ! -name '.*' | wc -l | tr -d '[:space:]')"
fi

echo
echo "libafl output dir: ${out_dir}"
echo "queue files: ${queue_n}"
echo "crash files: ${crashes_n}"
echo "log: ${workdir}/out.log"
