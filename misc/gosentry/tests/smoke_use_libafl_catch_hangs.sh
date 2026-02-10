#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/misc/gosentry/tests/smoke_use_libafl_common.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
export GOCACHE="${tmp_dir}/gocache"

GOSENTRY_LIBAFL_HANG_RE='Found [1-9][0-9]* hanging input\(s\)\.'

mod_dir="${tmp_dir}/hang_only"
mkdir -p "${mod_dir}"

cat > "${mod_dir}/go.mod" <<'EOF'
module example.com/gosentry_catch_hangs_smoke

go 1.22
EOF

cat > "${mod_dir}/hang_test.go" <<'EOF'
package hangonly

import "testing"

// Intentional hang for LibAFL timeout -> hang confirmation smoke testing.
func FuzzCatchHangs(f *testing.F) {
	f.Add([]byte{0})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Prevent "unused" warnings and keep a tiny bit of input dependency.
		if len(data) > 0 {
			_ = data[0] & 7
		}

		// Hang forever.
		select {}
	})
}
EOF

cfg_path="${tmp_dir}/libafl-config.jsonc"
cat >"${cfg_path}" <<'EOF'
{
  // Keep it single-client and fast in CI.
  "cores": "0",
  "exec_timeout_ms": 100,

  // Catch/confirm hangs (this is what we are testing).
  "catch_hangs": true,
  "hang_timeout_ms": 1500,
  "hang_confirm_runs": 2,

  // Stop the campaign once a hang is confirmed.
  "stop_all_fuzzers_on_panic": true
}
EOF

cd "${mod_dir}"

in_dir="$(libafl_input_dir FuzzCatchHangs)"
mkdir -p "${in_dir}"
printf 'H' > "${in_dir}/seed-hang"

set +e
CGO_ENABLED=1 timeout 10m "${ROOT_DIR}/bin/go" test -fuzz=FuzzCatchHangs --use-libafl --focus-on-new-code=false --catch-races=false --catch-leaks=false --libafl-config="${cfg_path}" . 2>&1 | tee "${tmp_dir}/output.txt"
status="${PIPESTATUS[0]}"
set -e

if [[ "${status}" -eq 0 ]]; then
  echo "expected fuzz run to fail due to confirmed hang, but it exited 0"
  exit 1
fi

if [[ "${status}" -eq 124 ]]; then
  echo "expected hang to be detected, but fuzz run timed out"
  exit 1
fi

out_dir="$(dirname "${in_dir}")"
hangs_dir="${out_dir}/hangs"
crashes_dir="${out_dir}/crashes"

if ! grep -Eq "${GOSENTRY_LIBAFL_HANG_RE}" "${tmp_dir}/output.txt"; then
  # Some multi-client runs can get wedged after finding an objective, before
  # printing the final hang summary. Accept the presence of on-disk hang
  # inputs as success, but still verify crash-free behavior below.
  if [[ -d "${hangs_dir}" ]] && find "${hangs_dir}" -maxdepth 1 -type f ! -name '.*' -print -quit | grep -q .; then
    :
  else
    echo "expected output to contain: Found N hanging input(s)."
    echo "and expected hangs dir to contain hang inputs: ${hangs_dir}"
    exit 1
  fi
fi

if [[ ! -d "${hangs_dir}" ]] || ! find "${hangs_dir}" -maxdepth 1 -type f ! -name '.*' -print -quit | grep -q .; then
  echo "expected hangs dir to contain hang inputs: ${hangs_dir}"
  exit 1
fi

if [[ -d "${crashes_dir}" ]] && find "${crashes_dir}" -maxdepth 1 -type f ! -name '.*' -print -quit | grep -q .; then
  echo "expected hang-only failure (no crashing inputs), but a crashing input was found in: ${crashes_dir}"
  exit 1
fi
