#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
export GOCACHE="${tmp_dir}/gocache"

mod_dir="${tmp_dir}/race_only"
mkdir -p "${mod_dir}"

cat > "${mod_dir}/go.mod" <<'EOF'
module example.com/gosentry_catch_races_smoke

go 1.22
EOF

cat > "${mod_dir}/race_test.go" <<'EOF'
package raceonly

import "testing"

// Intentional data race for --catch-races smoke testing.
// This must not crash/panic without the race detector.
var shared int

func FuzzCatchRaces(f *testing.F) {
	f.Add([]byte{0})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Small input-dependent branching so the corpus grows beyond the initial seed.
		if len(data) > 0 {
			switch data[0] & 7 {
			case 0:
				shared += 1
			case 1:
				shared += 2
			case 2:
				shared += 3
			case 3:
				shared += 4
			case 4:
				shared += 5
			case 5:
				shared += 6
			case 6:
				shared += 7
			case 7:
				shared += 8
			}
		}

		// Two goroutines writing shared without synchronization => race.
		start := make(chan struct{})
		done := make(chan struct{}, 2)
		go func() {
			<-start
			for i := 0; i < 1000; i++ {
				shared++
			}
			done <- struct{}{}
		}()
		go func() {
			<-start
			for i := 0; i < 1000; i++ {
				shared++
			}
			done <- struct{}{}
		}()
		close(start)
		<-done
		<-done
	})
}
EOF

cd "${mod_dir}"

set +e
CGO_ENABLED=1 timeout 10m "${ROOT_DIR}/bin/go" test -fuzz=FuzzCatchRaces --use-libafl --focus-on-new-code=false --catch-races=true . 2>&1 | tee "${tmp_dir}/output.txt"
status="${PIPESTATUS[0]}"
set -e

if [[ "${status}" -eq 0 ]]; then
  echo "expected fuzz run to fail due to detected data race, but it exited 0"
  exit 1
fi

if [[ "${status}" -eq 124 ]]; then
  echo "expected data race to be detected, but fuzz run timed out"
  exit 1
fi

if ! grep -Fq "catch-races: detected data race on" "${tmp_dir}/output.txt"; then
  echo "expected output to contain: catch-races: detected data race on ..."
  exit 1
fi

if grep -Eq 'Found [1-9][0-9]* (pre-existing )?crashing input\\(s\\)\\.' "${tmp_dir}/output.txt"; then
  echo "expected race-only failure (no crashing inputs), but a crashing input was reported"
  exit 1
fi

detected_line="$(grep -F "catch-races: detected data race on" "${tmp_dir}/output.txt" | head -n 1 || true)"
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
