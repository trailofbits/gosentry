#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/misc/gosentry/tests/smoke_use_libafl_common.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
export GOCACHE="${tmp_dir}/gocache"
export PATH="${ROOT_DIR}/bin:${PATH}"

repo_dir="${tmp_dir}/focus-on-new-code-repo"
mkdir -p "${repo_dir}"
cd "${repo_dir}"

git init -q
git config user.email "gosentry@example.com"
git config user.name "gosentry"

cat > old.go <<'EOF'
package focus

//go:noinline
func Old(b byte) int {
	if b == 0 {
		return 1
	}
	return int(b) + 1
}
EOF

git add old.go
GIT_AUTHOR_DATE="2000-01-01T00:00:00Z" \
  GIT_COMMITTER_DATE="2000-01-01T00:00:00Z" \
  git commit -qm "old"
old_time="$(git show -s --format=%ct HEAD)"

cat > go.mod <<'EOF'
module example.com/focus

go 1.25
EOF

cat > new.go <<'EOF'
package focus

//go:noinline
func New(b byte) int {
	if b == 255 {
		return 0
	}
	return int(b) - 1
}
EOF

cat > focus_test.go <<'EOF'
package focus

import "testing"

func FuzzFocus(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{1})
	f.Add([]byte{255})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		_ = Old(data[0])
		_ = New(data[0])
		if data[0] == 255 {
			panic("focus-on-new-code-crash")
		}
	})
}
EOF

git add go.mod new.go focus_test.go
GIT_AUTHOR_DATE="2001-01-01T00:00:00Z" \
  GIT_COMMITTER_DATE="2001-01-01T00:00:00Z" \
  git commit -qm "new"
head_time="$(git show -s --format=%ct HEAD)"

in_dir="$(libafl_input_dir FuzzFocus)"
out_dir="$(dirname "${in_dir}")"
map_path="${out_dir}/git_recency_map.bin"
if [[ -e "${map_path}" ]]; then
  echo "expected git recency mapping to not exist yet: ${map_path}"
  exit 1
fi

output_file="${tmp_dir}/output.txt"

set +e
CGO_ENABLED=1 timeout 10m "${ROOT_DIR}/bin/go" test -fuzz=FuzzFocus --use-libafl --focus-on-new-code=true --catch-races=false 2>&1 | tee "${output_file}"
status="${PIPESTATUS[0]}"
set -e

if [[ "${status}" -eq 0 ]]; then
  echo "expected fuzz run to fail (panic/crash), but it exited 0"
  exit 1
fi
if ! grep -Eq "${GOSENTRY_LIBAFL_CRASH_RE}" "${output_file}"; then
  echo "expected output to contain: Found N crashing input(s)."
  exit 1
fi
if [[ ! -s "${map_path}" ]]; then
  echo "expected git recency mapping to be created: ${map_path}"
  exit 1
fi

export EXPECTED_HEAD_TIME="${head_time}"
export EXPECTED_OLD_TIME="${old_time}"
export EXPECTED_NEW_TIME="${head_time}"
python3 - "${map_path}" <<'PY'
import os
import struct
import sys

path = sys.argv[1]
data = open(path, "rb").read()
if len(data) < 16:
    raise SystemExit(f"mapping file too small: {len(data)} bytes")

head_time, n = struct.unpack_from("<QQ", data, 0)
expected_head = int(os.environ["EXPECTED_HEAD_TIME"])
expected_old = int(os.environ["EXPECTED_OLD_TIME"])
expected_new = int(os.environ["EXPECTED_NEW_TIME"])

if head_time != expected_head:
    raise SystemExit(f"unexpected head_time: got {head_time}, want {expected_head}")
if n == 0:
    raise SystemExit("expected mapping to contain at least one counter")
if len(data) != 16 + n * 8:
    raise SystemExit(
        f"unexpected mapping size: got {len(data)} bytes, want {16 + n * 8} bytes (n={n})"
    )

timestamps = struct.unpack_from("<" + "Q" * n, data, 16)
if all(t == 0 for t in timestamps):
    raise SystemExit("expected mapping timestamps to include at least one non-zero entry")
if expected_old not in timestamps:
    raise SystemExit(f"expected mapping to include old timestamp {expected_old}")
if expected_new not in timestamps:
    raise SystemExit(f"expected mapping to include new timestamp {expected_new}")
if expected_old >= expected_new:
    raise SystemExit(f"expected old timestamp < new timestamp, got old={expected_old} new={expected_new}")
PY
