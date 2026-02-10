#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  cat <<'EOF'
Usage: bench_focus_on_new_code_geth.sh [--trials N] [--warmup SECONDS] [--timeout SECONDS] [--workdir DIR] [--keep]

Benchmarks gosentry's --focus-on-new-code=true on a shallow clone of go-ethereum (geth).

This simulates a "new bug in a big repo":
  - It makes geth look "old" to git by committing the whole repo with an old
    timestamp.
  - Then it adds one new commit with a single crashing line (marked RECENT_BUG).
  - The fuzzer's job is to find an input that hits that crash.

It runs two modes and compares time-to-first-crash:
  - baseline: normal fuzzing (no "new code" bias)
  - git-aware: --focus-on-new-code=true, which uses git history to treat lines
    from the recent commit as "new" and prioritize inputs that reach them.

The "harness" is the compiled Go fuzz test turned into a native library
(`libharness.a`). The `golibafl` binary is the LibAFL runner that links that
library and performs fuzzing.

To keep the comparison fair and stable, the script does a short warmup run
before introducing the crash to build an initial corpus, then filters that
corpus to remove any inputs that already crash. It also precomputes a git
"recency map" once (so it doesn't have to re-scan git history in every trial),
then runs N paired trials (baseline vs git-aware) with the same seeds and reports
the median time-to-first-crash (capped at the timeout).

Workflow:
  1) clone geth to /tmp
  2) add a fuzz target in package rlp (committed with an old date)
  3) warmup: fuzz baseline (no crash) for --warmup seconds
  4) commit a single-line crash marked "RECENT_BUG"
  5) build the LibAFL harness + golibafl runner
  6) precompute the git recency mapping (git-aware) once
  7) run N paired trials: baseline vs git-aware; report median time-to-first-crash
EOF
}

trials=3
warmup_s=5
timeout_s=60
workdir=""
keep=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--trials)
      trials="${2:?missing N}"
      shift 2
      ;;
    -w|--warmup)
      warmup_s="${2:?missing seconds}"
      shift 2
      ;;
    -t|--timeout)
      timeout_s="${2:?missing seconds}"
      shift 2
      ;;
    --workdir)
      workdir="${2:?missing dir}"
      shift 2
      ;;
    --keep)
      keep=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1"
      usage
      exit 2
      ;;
  esac
done

GOSENTRY_GO="${ROOT_DIR}/bin/go"
GOLIBAFL_DIR="${ROOT_DIR}/golibafl"

if [[ ! -x "${GOSENTRY_GO}" ]]; then
  echo "missing gosentry binary: ${GOSENTRY_GO}"
  echo "build it with: (cd src && ./make.bash)"
  exit 1
fi

if [[ -z "${workdir}" ]]; then
  workdir="$(mktemp -d /tmp/gosentry-bench-focus-on-new-code-geth.XXXXXX)"
fi

if [[ "${keep}" != "true" ]]; then
  cleanup() {
    # Go's module cache can be made read-only; make it writable so the temp dir
    # can be removed cleanly.
    chmod -R u+w "${workdir}" 2>/dev/null || true
    rm -rf "${workdir}"
  }
  trap cleanup EXIT
fi

repo_dir="${workdir}/go-ethereum"
cache_dir="${workdir}/cache"
mkdir -p "${cache_dir}/gocache" "${cache_dir}/gomodcache"

export GOCACHE="${cache_dir}/gocache"
export GOMODCACHE="${cache_dir}/gomodcache"
export CGO_ENABLED=1

echo "workdir: ${workdir}"
echo "cloning geth..."
git clone --depth 1 https://github.com/ethereum/go-ethereum.git "${repo_dir}"

cd "${repo_dir}"
git config user.email "gosentry-bench@example.com"
git config user.name "gosentry-bench"

cat > rlp/gosentry_focus_new_code_fuzz_test.go <<'EOF'
package rlp

import "testing"

func FuzzGosentryFocusNewCode(f *testing.F) {
	f.Add([]byte("GETH\x00\x00\x00\x00"))
	seed, _ := EncodeToBytes(uint32(0))
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		GosentryFocusNewCodeTarget(data)
	})
}
EOF

cat > rlp/gosentry_focus_new_code_target.go <<'EOF'
package rlp

import (
	"encoding/binary"
	"math/bits"
)

var gosentryFocusNewCodeSink uint32

// A small-ish amount of deterministic "old code" work to generate a rich corpus and
// distract baseline scheduling (mirrors the reth benchmark's intent).
func gosentryFocusNewCodeState(data []byte) uint64 {
	if len(data) == 0 {
		return 0
	}

	var s uint64 = 0x9e3779b97f4a7c15

	// Exercise raw RLP parsing on multiple offsets to generate lots of coverage
	// variation without requiring hard-to-solve constraints.
	for off := 0; off < 4 && off < len(data); off++ {
		k, content, rest, err := Split(data[off:])
		if err != nil {
			s ^= uint64(off+1) * 0x100000001b3
			continue
		}

		s ^= uint64(k) << (off * 3)
		s ^= uint64(len(content))<<16 ^ uint64(len(rest))<<1
		if len(content) > 0 {
			s = bits.RotateLeft64(s, int(content[0]%63+1)) ^ 0x9e3779b97f4a7c15
		} else {
			s = bits.RotateLeft64(s, 13) ^ 0x9e3779b97f4a7c15
		}

		// If it's a list, iterate a few elements to create more state/coverage.
		if k == List {
			b := content
			for i := 0; i < 8 && len(b) > 0; i++ {
				kk, cc, rr, e := Split(b)
				if e != nil {
					s ^= uint64(i+1)<<32 ^ 0x27d4eb2f165667c5
					break
				}
				s ^= uint64(kk) << (i * 2)
				if len(cc) > 0 {
					s ^= uint64(cc[0])<<8 ^ uint64(cc[len(cc)-1])
				}
				b = rr
			}
		}
	}

	// Mix in a fast, branchy splitter for an integer.
	for off := 0; off < 4 && off < len(data); off++ {
		x, _, err := SplitUint64(data[off:])
		if err == nil {
			s ^= bits.RotateLeft64(x, 13) ^ 0x517cc1b727220a95
		} else {
			s ^= 0x94d049bb133111eb
		}
	}

	return s
}

func gosentryFocusNewCodeDenom(data []byte, state uint64) uint32 {
	// Avoid overflowing arithmetic: keep denom in 14 bits. denom==0 iff
	// (mixed&0x1fff)==0x11b (i.e. 0x211b truncated to 13 bits).
	const rawOff = 512
	if len(data) < rawOff+4 {
		return 1
	}
	raw := binary.LittleEndian.Uint32(data[rawOff : rawOff+4])
	mixed := raw ^ bits.RotateLeft32(uint32(state), 7) ^ bits.RotateLeft32(uint32(state>>32), -3)
	return (mixed & 0x1fff) ^ 0x11b
}

func GosentryFocusNewCodeTarget(data []byte) {
	if len(data) < 4 {
		return
	}
	state := gosentryFocusNewCodeState(data)
	// Prefix gate: keep the "interesting" path rare-ish, but make sure the same
	// line gets hit by lots of non-crashing inputs (so git-aware scheduling has
	// a signal to boost).
	if data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == 'H' {
		// Keep this path on a moderately long input so mutations aren't dominated
		// by constantly breaking the prefix.
		if len(data) >= 516 {
			gosentryFocusNewCodeRecentLine(data, state)
		}
	}
}
EOF

cat > rlp/gosentry_focus_new_code_recent_bug.go <<'EOF'
package rlp

//go:noinline
func gosentryFocusNewCodeRecentLine(data []byte, state uint64) {
	gosentryFocusNewCodeSink ^= gosentryFocusNewCodeDenom(data, state) + 1 // GOSENTRY_PLACEHOLDER
}
EOF

# Create an "old baseline snapshot" of the whole repo so `git blame` considers
# everything old except the single RECENT_BUG change committed later.
git checkout --orphan gosentry-bench >/dev/null 2>&1 || true
git add -A
GIT_AUTHOR_DATE="2000-01-01T00:00:00Z" GIT_COMMITTER_DATE="2000-01-01T00:00:00Z" \
  git commit -qm "gosentry bench: baseline snapshot (old)"

build_harness() {
  local out_dir="${1}"
  mkdir -p "${out_dir}"
  "${GOSENTRY_GO}" test ./rlp -c -fuzz=FuzzGosentryFocusNewCode --use-libafl --focus-on-new-code=false --catch-races=false --catch-leaks=false -o "${out_dir}/libharness.a"
}

build_golibafl() {
  local harness_lib="${1}"
  local out_bin="${2}"
  (cd "${GOLIBAFL_DIR}" && HARNESS_LIB="${harness_lib}" cargo build --release >/dev/null)
  cp "${GOLIBAFL_DIR}/target/release/golibafl" "${out_bin}"
  chmod +x "${out_bin}"
}

warmup_in="${workdir}/warmup/input"
warmup_out="${workdir}/warmup/out"
mkdir -p "${warmup_in}" "${warmup_out}"
python3 - <<PY
from pathlib import Path

in_dir = Path(${warmup_in@Q})
in_dir.mkdir(parents=True, exist_ok=True)

def prng_bytes(n: int, seed: int) -> bytes:
    x = seed & 0xFFFFFFFF
    b = bytearray()
    for _ in range(n):
        x = (1103515245 * x + 12345) & 0xFFFFFFFF
        b.append((x >> 16) & 0xFF)
    return bytes(b)

# Multiple seeds reduce variance; they will be deduped/minimized by warmup.
for i in range(4):
    (in_dir / f"seed_recent_path_{i}").write_bytes(b"GETH" + prng_bytes(4096 - 4, 0x12345678 + i))
    (in_dir / f"seed_other_{i}").write_bytes(b"NOPE" + prng_bytes(4096 - 4, 0x87654321 + i))
PY

harness_no_bug="${workdir}/harness-no-bug"
build_harness "${harness_no_bug}"

golibafl_no_bug="${workdir}/golibafl-no-bug"
build_golibafl "${harness_no_bug}/libharness.a" "${golibafl_no_bug}"

echo "warmup: ${warmup_s}s - baseline, no crash"
set +e
LIBAFL_RAND_SEED=0 LIBAFL_SEED_DIR="${warmup_in}" GOLIBAFL_FOCUS_ON_NEW_CODE=false \
  timeout --signal=INT --kill-after=5s "${warmup_s}" \
  "${golibafl_no_bug}" fuzz -j 0 -i "${warmup_in}" -o "${warmup_out}" \
  >"${workdir}/warmup.log" 2>&1
set -e

warmup_queue_dir="$(find "${warmup_out}/queue" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n 1 || true)"
warmup_crash_file="$(find "${warmup_out}/crashes" -maxdepth 1 -type f -not -name '.*' -print -quit 2>/dev/null || true)"
if [[ -n "${warmup_crash_file}" ]]; then
  echo "warmup produced a crash (${warmup_crash_file}); warmup should be no-crash; warmup log:"
  tail -n 200 "${workdir}/warmup.log" || true
  exit 1
fi

warmup_queue_file="$(find "${warmup_out}/queue" -mindepth 1 -maxdepth 2 -type f -not -name '.*' -print -quit 2>/dev/null || true)"
if [[ -z "${warmup_queue_file}" ]]; then
  echo "warmup did not produce a queue corpus file; warmup log:"
  tail -n 200 "${workdir}/warmup.log" || true
  exit 1
fi
warmup_queue_dir="$(dirname "${warmup_queue_file}")"
echo "warmup corpus: ${warmup_queue_dir}"

echo "committing RECENT_BUG (single-line crash)..."
python3 - <<'PY'
from pathlib import Path

p = Path("rlp/gosentry_focus_new_code_recent_bug.go")
text = p.read_text()
lines = text.splitlines(True)
for i, line in enumerate(lines):
    if "GOSENTRY_PLACEHOLDER" not in line:
        continue
    indent = line[: len(line) - len(line.lstrip())]
    lines[i] = indent + "gosentryFocusNewCodeSink ^= uint32(0x12345678) / gosentryFocusNewCodeDenom(data, state) // RECENT_BUG\n"
    break
else:
    raise SystemExit("RECENT_BUG placeholder line not found")
p.write_text("".join(lines))
PY
git add rlp/gosentry_focus_new_code_recent_bug.go
git commit -qm "RECENT_BUG"

harness_bug="${workdir}/harness-bug"
build_harness "${harness_bug}"

golibafl_bug="${workdir}/golibafl-bug"
build_golibafl "${harness_bug}/libharness.a" "${golibafl_bug}"

echo "filtering warmup corpus: removing inputs that already trigger RECENT_BUG..."
set +e
removed=0
kept=0
for f in "${warmup_queue_dir}"/*; do
  if [[ ! -f "${f}" ]] || [[ "$(basename "${f}")" == .* ]]; then
    continue
  fi
  "${golibafl_bug}" run --input "${f}" >/dev/null 2>&1
  st="$?"
  if [[ "${st}" -ne 0 ]]; then
    rm -f -- "${f}"
    removed=$(( removed + 1 ))
  else
    kept=$(( kept + 1 ))
  fi
done
set -e
echo "warmup corpus filter: removed=${removed} kept=${kept}"
if [[ "${kept}" -eq 0 ]]; then
  echo "warmup corpus became empty after filtering"
  exit 1
fi

git_map="${workdir}/git_recency_map.bin"
target_dir="${repo_dir}/rlp"

precompute_git_recency_map() {
  if [[ -s "${git_map}" ]]; then
    return 0
  fi

  echo "precomputing git recency mapping (one-time; not counted in trials)..."
  local out_dir="${workdir}/git_map_pregen"
  rm -rf "${out_dir}"
  mkdir -p "${out_dir}"

  HARNESS_LIB="${harness_bug}/libharness.a" \
    GOLIBAFL_FOCUS_ON_NEW_CODE=true \
    GOLIBAFL_TARGET_DIR="${target_dir}" \
    LIBAFL_GIT_RECENCY_MAPPING_PATH="${git_map}" \
    setsid "${golibafl_bug}" fuzz -j 0 -i "${warmup_queue_dir}" -o "${out_dir}" \
    >"${out_dir}/run.log" 2>&1 &
  local pid="$!"

  local deadline=$(( $(date +%s) + 600 )) # 10 minutes should be plenty on a local clone.
  while [[ ! -s "${git_map}" ]]; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      wait "${pid}" || true
      echo "failed to generate git recency mapping; log tail:" >&2
      tail -n 200 "${out_dir}/run.log" >&2 || true
      exit 1
    fi
    if [[ "$(date +%s)" -ge "${deadline}" ]]; then
      kill -INT -- "-${pid}" 2>/dev/null || true
      sleep 1
      kill -KILL -- "-${pid}" 2>/dev/null || true
      wait "${pid}" || true
      echo "timed out generating git recency mapping; log tail:" >&2
      tail -n 200 "${out_dir}/run.log" >&2 || true
      exit 1
    fi
    sleep 0.1
  done

  # Wait for the file size to stabilize (avoid killing while it's still writing).
  local last_size=0
  local stable=0
  while [[ "${stable}" -lt 5 ]]; do
    local size
    size="$(wc -c < "${git_map}" 2>/dev/null || echo 0)"
    if [[ "${size}" -ge 16 && "${size}" -eq "${last_size}" ]]; then
      stable=$(( stable + 1 ))
    else
      stable=0
      last_size="${size}"
    fi
    sleep 0.1
  done

  kill -INT "${pid}" 2>/dev/null || true
  for _ in {1..50}; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if kill -0 "${pid}" 2>/dev/null; then
    kill -INT -- "-${pid}" 2>/dev/null || true
    sleep 1
    kill -KILL -- "-${pid}" 2>/dev/null || true
  fi
  wait "${pid}" || true

  echo "git recency map: ${git_map} (${last_size} bytes)"
}

run_until_crash_ms() {
  local label="${1}"
  local out_dir="${2}"
  local focus="${3}"
  local seed="${4}"

  rm -rf "${out_dir}"
  mkdir -p "${out_dir}"

  local start_ns
  start_ns="$(date +%s%N)"

  # Run the fuzzer in its own process group so timeouts can reliably kill the
  # whole tree (broker/clients), not just the parent PID.
  if [[ "${focus}" == "true" ]]; then
    LIBAFL_RAND_SEED="${seed}" \
      HARNESS_LIB="${harness_bug}/libharness.a" \
      GOLIBAFL_FOCUS_ON_NEW_CODE=true \
      GOLIBAFL_TARGET_DIR="${target_dir}" \
      LIBAFL_GIT_RECENCY_MAPPING_PATH="${git_map}" \
      setsid "${golibafl_bug}" fuzz -j 0 -i "${warmup_queue_dir}" -o "${out_dir}" \
      >"${out_dir}/run.log" 2>&1 &
  else
    LIBAFL_RAND_SEED="${seed}" \
      GOLIBAFL_FOCUS_ON_NEW_CODE=false \
      setsid "${golibafl_bug}" fuzz -j 0 -i "${warmup_queue_dir}" -o "${out_dir}" \
      >"${out_dir}/run.log" 2>&1 &
  fi
  local pid="$!"

  local deadline=$(( $(date +%s) + timeout_s ))
  local crash_file=""
  local status="running"
  while true; do
    if [[ -d "${out_dir}/crashes" ]]; then
      crash_file="$(find "${out_dir}/crashes" -maxdepth 1 -type f -not -name '.*' -print -quit 2>/dev/null || true)"
      if [[ -n "${crash_file}" ]]; then
        status="crash"
        break
      fi
    fi

    if ! kill -0 "${pid}" 2>/dev/null; then
      wait "${pid}" || true
      if [[ -d "${out_dir}/crashes" ]]; then
        crash_file="$(find "${out_dir}/crashes" -maxdepth 1 -type f -not -name '.*' -print -quit 2>/dev/null || true)"
        if [[ -n "${crash_file}" ]]; then
          status="crash"
          break
        fi
      fi
      status="error"
      break
    fi

    if [[ "$(date +%s)" -ge "${deadline}" ]]; then
      status="timeout"
      break
    fi

    sleep 0.05
  done

  local end_ns
  end_ns="$(date +%s%N)"
  local dur_ms=$(( (end_ns - start_ns) / 1000000 ))

  if [[ "${status}" == "crash" ]]; then
    # Prefer a clean stop so golibafl can finalize crash artifacts, but do not
    # hang forever if it keeps running.
    local stop_deadline=$(( $(date +%s) + 10 ))
    while kill -0 "${pid}" 2>/dev/null && [[ "$(date +%s)" -lt "${stop_deadline}" ]]; do
      sleep 0.05
    done
    if kill -0 "${pid}" 2>/dev/null; then
      kill -INT "${pid}" 2>/dev/null || true
      sleep 1
      if kill -0 "${pid}" 2>/dev/null; then
        kill -INT -- "-${pid}" 2>/dev/null || true
        sleep 1
        kill -KILL -- "-${pid}" 2>/dev/null || true
      fi
    fi
    wait "${pid}" || true
    echo "crash ${dur_ms}"
    return 0
  fi

  if [[ "${status}" == "timeout" ]]; then
    kill -INT "${pid}" 2>/dev/null || true
    for _ in {1..50}; do
      if ! kill -0 "${pid}" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "${pid}" 2>/dev/null; then
      kill -INT -- "-${pid}" 2>/dev/null || true
      sleep 1
      kill -KILL -- "-${pid}" 2>/dev/null || true
    fi
    wait "${pid}" || true
    echo "${label}: timeout (${timeout_s}s); log tail:" >&2
    tail -n 50 "${out_dir}/run.log" >&2 || true
    echo "timeout $(( timeout_s * 1000 ))"
    return 0
  fi

  wait "${pid}" || true
  echo "${label}: exited without a crash; log tail:" >&2
  tail -n 100 "${out_dir}/run.log" >&2 || true
  echo "error ${dur_ms}"
  return 0
}

baseline_status=()
baseline_ms=()
gitaware_status=()
gitaware_ms=()

precompute_git_recency_map

python3 - <<PY
import struct
import time

p = "${git_map}"
with open(p, "rb") as f:
    head_time, n = struct.unpack("<QQ", f.read(16))
    nonzero = 0
    min_nz = None
    max_t = 0
    for _ in range(n):
        b = f.read(8)
        if not b:
            break
        (t,) = struct.unpack("<Q", b)
        if t:
            nonzero += 1
            max_t = max(max_t, t)
            min_nz = t if min_nz is None else min(min_nz, t)

def _fmt(ts):
    if not ts:
        return "n/a"
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))

print(f"git recency map stats: entries={n} nonzero={nonzero} head_time={head_time} ({_fmt(head_time)}) max={max_t} ({_fmt(max_t)}) min_nonzero={min_nz} ({_fmt(min_nz)})")
PY

mkdir -p "${workdir}/trials"
for i in $(seq 1 "${trials}"); do
  echo "trial ${i}/${trials}: baseline"
  read -r b_status b_ms < <(run_until_crash_ms "baseline_${i}" "${workdir}/trials/baseline_${i}" "false" "${i}")
  baseline_status+=("${b_status}")
  baseline_ms+=("${b_ms}")
  echo "  baseline_${i}: ${b_status} (${b_ms}ms)"

  echo "trial ${i}/${trials}: git-aware (--focus-on-new-code=true)"
  read -r g_status g_ms < <(run_until_crash_ms "gitaware_${i}" "${workdir}/trials/gitaware_${i}" "true" "${i}")
  gitaware_status+=("${g_status}")
  gitaware_ms+=("${g_ms}")
  echo "  gitaware_${i}: ${g_status} (${g_ms}ms)"
done

python3 - <<PY
import statistics

timeout_ms = ${timeout_s} * 1000

baseline_status = """${baseline_status[*]}""".split()
baseline_ms = list(map(int, """${baseline_ms[*]}""".split()))
gitaware_status = """${gitaware_status[*]}""".split()
gitaware_ms = list(map(int, """${gitaware_ms[*]}""".split()))

if len(baseline_status) != len(baseline_ms):
    raise SystemExit(f"internal error: baseline status={len(baseline_status)} ms={len(baseline_ms)}")
if len(gitaware_status) != len(gitaware_ms):
    raise SystemExit(f"internal error: git-aware status={len(gitaware_status)} ms={len(gitaware_ms)}")
if len(baseline_ms) != len(gitaware_ms):
    raise SystemExit(f"internal error: baseline trials={len(baseline_ms)} git-aware trials={len(gitaware_ms)}")

def summarize(label: str, st: list[str], ms: list[int]):
    pairs = list(zip(st, ms))
    crashes = [m for (s, m) in pairs if s == "crash"]
    timeouts = sum(1 for (s, _m) in pairs if s == "timeout")
    errors = sum(1 for (s, _m) in pairs if s == "error")
    ok = len(crashes)
    capped = [m if s == "crash" else timeout_ms for (s, m) in pairs]

    print(f"{label} results:")
    for i, (s, m) in enumerate(pairs, 1):
        if s == "timeout":
            print(f"  trial {i}: timeout ({timeout_ms}ms)")
        elif s == "error":
            print(f"  trial {i}: error ({m}ms)")
        else:
            print(f"  trial {i}: crash ({m}ms)")

    med = statistics.median(capped) if capped else None
    print(f"{label} crashes: {ok}/{len(pairs)} (timeouts={timeouts}, errors={errors})")
    if med is None:
        print(f"{label} median (capped to timeout): N/A")
    else:
        print(f"{label} median (capped to timeout): {med/1000.0:.3f}s")
    print("")
    return med

b_med_ms = summarize("baseline", baseline_status, baseline_ms)
g_med_ms = summarize("git-aware", gitaware_status, gitaware_ms)

print("")
if b_med_ms is not None and g_med_ms is not None and g_med_ms > 0:
    print(f"speedup (baseline/git-aware): {b_med_ms/g_med_ms:.2f}x")
else:
    print("speedup (baseline/git-aware): N/A")
PY
