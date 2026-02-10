#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
export GOCACHE="${tmp_dir}/gocache"

mod_dir="${tmp_dir}/leaks_only"
mkdir -p "${mod_dir}"

cat > "${mod_dir}/go.mod" <<'EOF'
module example.com/gosentry_catch_leaks_smoke

go 1.22
EOF

cat > "${mod_dir}/leaks_test.go" <<'EOF'
package leaksonly

import (
	"sync"
	"testing"
)

// Intentional goroutine leak for --catch-leaks smoke testing.
var leakOnce sync.Once

func FuzzCatchLeaks(f *testing.F) {
	f.Add([]byte{0})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Small input-dependent branching so the corpus grows beyond the initial seed.
		if len(data) > 0 {
			_ = data[0] & 7
		}

		// Leak one goroutine per process (avoid unbounded growth during fuzzing).
		leakOnce.Do(func() {
			ch := make(chan struct{})
			go func() {
				<-ch
			}()
		})
	})
}
EOF

cd "${mod_dir}"

set +e
CGO_ENABLED=1 timeout 10m "${ROOT_DIR}/bin/go" test -fuzz=FuzzCatchLeaks --use-libafl --focus-on-new-code=false --catch-races=false --catch-leaks=true . 2>&1 | tee "${tmp_dir}/output.txt"
status="${PIPESTATUS[0]}"
set -e

if [[ "${status}" -eq 0 ]]; then
  echo "expected fuzz run to fail due to detected goroutine leak, but it exited 0"
  exit 1
fi

if [[ "${status}" -eq 124 ]]; then
  echo "expected goroutine leak to be detected, but fuzz run timed out"
  exit 1
fi

if ! grep -Fq "catch-leaks: detected goroutine leak on" "${tmp_dir}/output.txt"; then
  echo "expected output to contain: catch-leaks: detected goroutine leak on ..."
  exit 1
fi

if grep -Eq 'Found [1-9][0-9]* (pre-existing )?crashing input\\(s\\)\\.' "${tmp_dir}/output.txt"; then
  echo "expected leak-only failure (no crashing inputs), but a crashing input was reported"
  exit 1
fi

detected_line="$(grep -F "catch-leaks: detected goroutine leak on" "${tmp_dir}/output.txt" | head -n 1 || true)"
copied_path=""
if [[ -n "${detected_line}" ]]; then
  copied_path="${detected_line##* (copied to }"
  copied_path="${copied_path%)}"
fi
if [[ -z "${copied_path}" ]]; then
  echo "expected output to include copied seed path"
  exit 1
fi

if [[ ! -f "${copied_path}" ]]; then
  echo "expected copied seed to exist at: ${copied_path}"
  exit 1
fi

