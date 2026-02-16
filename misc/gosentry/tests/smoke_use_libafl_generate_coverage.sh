#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/misc/gosentry/tests/smoke_use_libafl_common.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
export GOCACHE="${tmp_dir}/gocache"

mod_dir="${tmp_dir}/cov_smoke"
mkdir -p "${mod_dir}"

cat > "${mod_dir}/go.mod" <<'EOF'
module example.com/gosentry_generate_coverage_smoke

go 1.25
EOF

cat > "${mod_dir}/logic.go" <<'EOF'
package covsmoke

func Transform(data []byte) int {
	if len(data) > 4096 {
		data = data[:4096]
	}

	n := 0
	for _, b := range data {
		if b%2 == 0 {
			n += int(b)
		} else {
			n -= int(b)
		}
	}
	if len(data) > 0 && data[0] == 'A' {
		n += 100
	}
	return n
}
EOF

cat > "${mod_dir}/cov_test.go" <<'EOF'
package covsmoke

import "testing"

func FuzzCoverVanilla(f *testing.F) {
	f.Add([]byte("abc"))
	f.Add([]byte("AAA"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Transform(data)
	})
}

func FuzzCoverGrammar(f *testing.F) {
	f.Add([]byte("abc"))
	f.Add([]byte("AAA"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Transform(data)
	})
}
EOF

cat > "${mod_dir}/grammar.json" <<'EOF'
[
  ["Start", "A"],
  ["Start", "B"],
  ["Start", "C"],
  ["Start", "AB"],
  ["Start", "BA"],
  ["Start", "CAB"]
]
EOF

cd "${mod_dir}"

run_and_check_generate_coverage() {
	local fuzz_name="${1}"
	local fuzz_args=("${@:2}")

	local in_dir out_dir queue_dir
	in_dir="$(libafl_input_dir "${fuzz_name}")"
	out_dir="$(dirname "${in_dir}")"
	queue_dir="${out_dir}/queue"
	mkdir -p "${in_dir}"
	printf 'seed-%s' "${fuzz_name}" > "${in_dir}/seed"

	local fuzz_output="${tmp_dir}/${fuzz_name}.fuzz.out"
	CGO_ENABLED=1 "${ROOT_DIR}/bin/go" test -fuzz="${fuzz_name}" --use-libafl --focus-on-new-code=false --catch-races=false --catch-leaks=false "${fuzz_args[@]}" . >"${fuzz_output}" 2>&1 &
	local fuzz_pid="$!"

	local max_wait_s=300
	local deadline_s=$((SECONDS + max_wait_s))
	while true; do
		if [[ -d "${queue_dir}" ]] && find "${queue_dir}" -type f ! -name '.*' -print -quit | grep -q .; then
			break
		fi
		if ! kill -0 "${fuzz_pid}" 2>/dev/null; then
			wait "${fuzz_pid}" || true
			echo "fuzz run exited before the queue corpus was populated: ${queue_dir}"
			tail -n 200 "${fuzz_output}" || true
			exit 1
		fi
		if [[ "${SECONDS}" -ge "${deadline_s}" ]]; then
			echo "timed out waiting for the queue corpus to be populated: ${queue_dir}"
			tail -n 200 "${fuzz_output}" || true
			kill -TERM "${fuzz_pid}" 2>/dev/null || true
			wait "${fuzz_pid}" || true
			exit 1
		fi
		sleep 1
	done

	# Stop fuzzing once we have a queue corpus to replay for coverage.
	kill -TERM "${fuzz_pid}" 2>/dev/null || true
	wait "${fuzz_pid}" || true

	if grep -Eq "${GOSENTRY_LIBAFL_CRASH_RE}" "${fuzz_output}"; then
		echo "unexpected crash summary in output"
		tail -n 200 "${fuzz_output}" || true
		exit 1
	fi
	if [[ " ${fuzz_args[*]} " == *" --use-grammar "* ]] && ! grep -q "golibafl: nautilus enabled" "${fuzz_output}"; then
		echo "expected golibafl to enable nautilus"
		tail -n 200 "${fuzz_output}" || true
		exit 1
	fi

	local gen_output="${tmp_dir}/${fuzz_name}.cov.out"
	"${ROOT_DIR}/bin/go" test -fuzz="${fuzz_name}" --generate-coverage . 2>&1 | tee "${gen_output}"

	local cov_dir profile html
	cov_dir="${out_dir}/coverage"
	profile="${cov_dir}/cover.out"
	html="${cov_dir}/cover.html"

	if [[ ! -s "${profile}" ]]; then
		echo "expected coverage profile to exist and be non-empty: ${profile}"
		exit 1
	fi
	if [[ ! -s "${html}" ]]; then
		echo "expected coverage html to exist and be non-empty: ${html}"
		exit 1
	fi
	if [[ "$(wc -l < "${profile}")" -le 1 ]]; then
		echo "expected coverage profile to include at least one statement: ${profile}"
		exit 1
	fi
	if ! grep -q "logic.go" "${profile}"; then
		echo "expected coverage profile to include logic.go statements: ${profile}"
		exit 1
	fi
	if ! grep -qi "<html" "${html}"; then
		echo "expected coverage html to include <html>: ${html}"
		exit 1
	fi

	"${ROOT_DIR}/bin/go" tool cover -func="${profile}" | awk '
		/^total:/ {
			gsub(/%/, "", $3);
			found=1
			if ($3 <= 0.0) {
				exit 1
			}
		}
		END {
			if (!found) {
				exit 1
			}
		}
	' || {
		echo "expected total coverage to be > 0% for ${profile}"
		exit 1
	}
}

run_and_check_generate_coverage FuzzCoverVanilla

GOSENTRY_VERBOSE_AFL=1 run_and_check_generate_coverage FuzzCoverGrammar --use-grammar --grammar=grammar.json
