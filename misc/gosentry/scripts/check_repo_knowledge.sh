#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "${ROOT_DIR}"

base=""
if [[ "${1:-}" == "--base" ]]; then
  base="${2:-}"
  shift 2
fi
if [[ $# -gt 0 ]]; then
  echo "usage: $0 [--base <commit-ish>]" >&2
  exit 2
fi

require_file() {
  local path="${1}"
  if [[ ! -f "${path}" ]]; then
    echo "missing required file: ${path}" >&2
    exit 1
  fi
}

require_file "README.md"
require_file "AGENTS.md"
require_file "docs/gosentry/index.md"
require_file "docs/gosentry/architecture.md"
require_file "docs/gosentry/dev-loop.md"
require_file "docs/gosentry/benchmarks.md"
require_file "misc/gosentry/USE_LIBAFL.md"

if ! grep -q "docs/gosentry/index.md" "AGENTS.md"; then
  echo "AGENTS.md should link to docs/gosentry/index.md (keep AGENTS.md as a map, not a manual)" >&2
  exit 1
fi
if ! grep -q "docs/gosentry/index.md" "README.md"; then
  echo "README.md should link to docs/gosentry/index.md (dev docs entrypoint)" >&2
  exit 1
fi

agents_lines="$(wc -l < AGENTS.md | tr -d '[:space:]')"
if [[ "${agents_lines}" -gt 120 ]]; then
  echo "AGENTS.md is too long (${agents_lines} lines); keep it as a map and move detail into docs/gosentry/*" >&2
  exit 1
fi

for doc in \
  "docs/gosentry/architecture.md" \
  "docs/gosentry/dev-loop.md" \
  "docs/gosentry/benchmarks.md"
do
  if ! grep -q "${doc}" "docs/gosentry/index.md"; then
    echo "docs/gosentry/index.md should link to ${doc}" >&2
    exit 1
  fi
done

if [[ -z "${base}" ]]; then
  exit 0
fi
if [[ "${base}" == "0000000000000000000000000000000000000000" ]]; then
  exit 0
fi
if ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
  echo "invalid --base commit-ish: ${base}" >&2
  exit 2
fi

changed_files="$(git diff --name-only "${base}...HEAD")"

libafl_testflag_pattern='^[+-][^+-].*(testUseLibAFL|"use-libafl"|testFocusOnNewCode|"focus-on-new-code"|testCatchRaces|"catch-races"|testCatchLeaks|"catch-leaks"|testGenerateCoverage|"generate-coverage"|testUseGrammar|"use-grammar"|grammarFilesFlag|testGrammar|"grammar"|testLibAFLConfig|"libafl-config")'

# testflag.go also carries upstream Go flags like -vet. Only require a LibAFL
# doc update when the diff touches gosentry's LibAFL-specific flags or parsing.
if git --no-pager diff --no-ext-diff --no-color --unified=0 "${base}...HEAD" -- src/cmd/go/internal/test/testflag.go | grep -Eq "${libafl_testflag_pattern}"; then
  if ! echo "${changed_files}" | grep -qx "misc/gosentry/USE_LIBAFL.md"; then
    cat >&2 <<'EOF'
docs sync check failed:
- LibAFL-related lines in src/cmd/go/internal/test/testflag.go changed
- but misc/gosentry/USE_LIBAFL.md was not updated

Rule: if LibAFL `go test` flags change, update the canonical LibAFL doc.
EOF
    exit 1
  fi
fi

if git --no-pager diff --no-ext-diff --no-color "${base}...HEAD" -- src/cmd/compile/internal/base/flag.go | grep -Eq "(OverflowDetect|TruncationDetect|panic-on-call|PanicOnCall)"; then
  if ! echo "${changed_files}" | grep -qx "README.md"; then
    cat >&2 <<'EOF'
docs sync check failed:
- compiler flags for gosentry changed (src/cmd/compile/internal/base/flag.go)
- but README.md was not updated

Rule: if user-visible compiler flags/behavior change, update README.md.
EOF
    exit 1
  fi
fi
