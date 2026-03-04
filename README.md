# gosentry

[![integration tests](https://github.com/kevin-valerio/gosentry/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/kevin-valerio/gosentry/actions/workflows/go.yml)

gosentry is a security-focused fork of the Go toolchain, integrating numerous features for state-of-the-art fuzzing campaigns on Go codebases. If you were using `go test -fuzz` before, you should use gosentry as a replacement.
It comes with various fuzzing improvements and bug detectors that are not present natively in the Go toolchain. See TLDR; below.

**TLDR (features and options)**:

- Fuzz `struct` inputs directly (no custom parser needed). Add seeds with `f.Add(Input{N: 7, S: "hi"})` then `f.Fuzz(func(t *testing.T, in Input) { ... })`.
- Panic on integer overflow and detect arithmetic issues
- Fuzz with LibAFL for state-of-the-art fuzzing techniques like path constraints solving
- Generate/mutate inputs from a grammar to avoid useless mutations. Mutation generates valid maths operation like `X + Y - Z` can become `X / U + Z - 14` instead of `X + Yè - Z`
- Panic on selected functions (like critcal errors loggers) and crash when it's called 
- Focus the fuzzer on recently changed lines AND on new coverage to target new commits mainly
- Catch data races at fuzz-time
- Catch Go leaks at fuzz-time
- Catch stuck executions with timeouts at fuzz-time
- Generate a HTML coverage report from a fuzz campaign corpus with one CLI

## Table of Contents

- [Build](#build)
  - [Feature 1: Struct-aware fuzzing (fuzz structs as inputs)](#feature-1-struct-aware-fuzzing-fuzz-structs-as-inputs)
  - [Feature 2: Integer overflow and truncation issues detection](#feature-2-integer-overflow-and-truncation-issues-detection)
  - [Feature 3: Panic on selected functions](#feature-3-panic-on-selected-functions)
  - [Feature 4: LibAFL state-of-the-art fuzzing](#feature-4-libafl-state-of-the-art-fuzzing)
  - [Feature 5: Git-blame-oriented fuzzing (experimental)](#feature-5-git-blame-oriented-fuzzing-experimental)
  - [Feature 6: Detect race conditions, goroutine leaks, and hangs at fuzz-time](#feature-6-detect-race-conditions-goroutine-leaks-and-hangs-at-fuzz-time)
  - [Feature 7: Grammar-based fuzzing (Nautilus)](#feature-7-grammar-based-fuzzing-nautilus)
  - [Feature 8: Generate fuzzing coverage reports from campaign](#feature-8-generate-go-coverage-reports-from-fuzzing-campaign)
- [Trophies](#trophies)
- [Credits](#credits)

## Build
```bash
cd src && ./make.bash # Produces `../bin/go`. See `GOFLAGS` below.
```
 
> [!TIP]
> Contributor docs:  read `docs/gosentry/index.md` for a code map, recommended dev loop, CI entrypoints and benchmark scripts.


## Feature 1: Struct-aware fuzzing (fuzz structs as inputs)

#### Overview

Go’s native fuzzing (`go test -fuzz=...`) only supports a small set of scalar types as fuzz parameters (`[]byte`, `string`, numbers, ...). In gosentry, you can also fuzz **composite types** built from those scalars: structs, arrays, slices, and pointers.
This is useful when your code naturally takes structured inputs and you don’t want to build a custom encoder/decoder just to seed and mutate the corpus. 
See `test/gosentry/examples/multiargs` and `test/gosentry/examples/composite` for examples.

#### Simple example

```go
type Input struct {
	Data []byte
	S    string
	N    int
	OK   bool
}

func FuzzStructInput(f *testing.F) {
	// Seed the initial corpus with a Go struct (gosentry feature).
	f.Add(Input{Data: []byte("A"), S: "B", N: 7, OK: true})

	f.Fuzz(func(t *testing.T, in Input) {
		if in.OK && in.N == 1337 && in.S == "BOOMMOOB" && bytes.Equal(in.Data, []byte("A")) {
			t.Fatalf("boom")
		}
	})
}
```

<details>
<summary><strong>How struct seeds (<code>f.Add</code>) and struct fuzzing work (the glue made)</strong></summary>

Go’s native fuzzer cannot fuzz a `struct` value directly (it only knows how to mutate a small list of scalar types). gosentry adds a small glue layer: when your fuzz target uses composite types (like `Input`), gosentry fuzzes a single `[]byte` behind the scenes. On every execution, it **decodes** those bytes into your struct (field-by-field, recursively for slices/arrays/pointers) and then calls your `f.Fuzz` callback with the decoded value. The same **encoding** is used for seeds, so `f.Add(Input{...})` becomes an encoded `[]byte` corpus entry that the fuzzer can reuse and mutate like any other seed.

Fuzzers (including LibAFL) mutate raw bytes, so we want a decoder that can turn **any** byte slice into "some" struct value and keep going. JSON/`gob` would reject most random inputs (bad for coverage), and they also don’t populate unexported fields, while fuzzing often benefits from breaking invariants. This custom format is small, fast, deterministic, and tolerant to malformed data.

Under the hood, this uses gosentry’s own simple binary format (not `gob`, not JSON). The code lives in `src/testing/libafl.go`:
- Encode: `libaflMarshalInputs` / `libaflAppendValue`
- Decode: `libaflUnmarshalArgs` / `libaflDecodeValue`

Encoding rules (high level):
- `bool`: 1 byte (`0` or `1`)
- Integers: little-endian bytes (`int`/`uint` are 8 bytes)
- Floats: IEEE-754 bits in little-endian (`float32` = 4 bytes, `float64` = 8 bytes)
- `string`: `uvarint(len)` then raw string bytes
- `[]byte`: `uvarint(len)` then raw bytes
- Other slices: `uvarint(len)` then each element encoded
- Structs: fields encoded in declaration order
- Pointers: 1 byte (`0` = nil, `1` = present) then the pointed value
 
 
</details>

## Feature 2: Integer overflow and truncation issues detection

#### Overview

This work is inspired from the previously developed [go-panikint](https://github.com/trailofbits/go-panikint). It adds overflow/underflow detection for integer arithmetic operations and (optionnally) type truncation detection for integer conversions. When overflow or truncation is detected, a panic with a detailed error message is triggered, including the specific operation type and integer types involved.

_Arithmetic operations_: Handles addition `+`, subtraction `-`, multiplication `*`, and division `/` for both signed and unsigned integer types. For signed integers, covers `int8`, `int16`, `int32`. For unsigned integers, covers `uint8`, `uint16`, `uint32`, `uint64`. The division case specifically detects the `MIN_INT / -1` overflow condition for signed integers. `int64` and `uintptr` are not checked for arithmetic operations.

_Type truncation detection_: Detects potentially lossy integer type conversions. Covers all integer types: `int8`, `int16`, `int32`, `int64`, `uint8`, `uint16`, `uint32`, `uint64`. Excludes `uintptr` due to platform-dependent usage. This is disabled by default.

Overflow detection is enabled by default. To disable it, add `GOFLAGS='-gcflags=-overflowdetect=false'` before your `./make.bash`. You can also enable truncation issues checker with: `-gcflags=-truncationdetect=true`

#### How it works

This feature patches the compiler SSA generation so that integer arithmetic operations and integer conversions get extra runtime checks that call into the runtime to panic with a detailed error message when a bug is detected. Checks are applied using source-location-based filtering so user code is instrumented while standard library files and dependencies (module cache and `vendor/`) are skipped.

You can read the associated blog post about it [**here**](https://blog.trailofbits.com/2025/12/31/detect-gos-silent-arithmetic-bugs-with-go-panikint/).

#### Suppressing false positives

Add a marker on the same line as the operation or the line immediately above to suppress a specific report:

- Overflow/underflow: `overflow_false_positive`
- Truncation: `truncation_false_positive`

Example:

```go
// overflow_false_positive
intentionalOverflow := a + b
// truncation_false_positive
x := uint8(big)
sum2 := a + b // overflow_false_positive
x2 := uint8(big) // truncation_false_positive
```

Sometimes this might not work, that's because Go is in-lining the function. If `// overflow_false_poistive` isn't enough, add `//go:noinline` before the signature of your function.

## Feature 3: Panic on selected functions

When fuzzing targets, we may be interested in triggering a panic when certain functions are called. For example, some software may emit `log.error` messages instead of panicking, even though such conditions often indicate states that security researchers would want to detect during fuzzing.
However, these errors are usually handled internally (e.g., through retry or pause mechanisms, or by printing messages to logs), which makes them largely invisible to fuzzers. The objective of this feature is to address this issue.

#### How to use

Compile gosentry, then use the `--panic-on` flag.

```bash
./bin/go test -fuzz=FuzzHarness --use-libafl --focus-on-new-code=false --catch-races=false --catch-leaks=false --panic-on="test_go_panicon.(*Logger).Warning,test_go_panicon.(*Logger).Error"
```

The example above would panic when either `(*Logger).Warning` or `(*Logger).Error` is called (comma-separated list).

<details>
<summary><strong>How panic on selected functions feature works</strong></summary>

```text
┌───────────────────────────────────────────────────────────────────────────┐
│ 1) gosentry `go test`                                                      │
│    - parses + validates `-panic-on=...` against packages being built      │
│    - forwards patterns to the compiler via `-panic-on-call=...`           │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 2) `cmd/compile`                                                          │
│    - prevents inlining of matching calls so the call stays visible        │
│    - SSA pass inserts a call to `runtime.panicOnCall(...)`                │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 3) `runtime.panicOnCall`                                                  │
│    - panics with: "panic-on-call: func-name"                              │
└───────────────────────────────────────────────────────────────────────────┘
```

In practice, this makes any matched call site behave like a crash/panic for fuzzers (note: only static call sites can be trapped).
</details>

## Feature 4: LibAFL state-of-the-art fuzzing

LibAFL performs *way* better than the traditional Go fuzzer. When fuzzing (`go test -fuzz=...`), gosentry uses [LibAFL](https://github.com/AFLplusplus/LibAFL) **by default** (runner in `golibafl/`).
 
When using LibAFL (default), you must explicitly choose whether to enable git-aware scheduling: `--focus-on-new-code=true|false`. More documentation in [this Markdown file.](misc/gosentry/USE_LIBAFL.md)
You can also pass an optional JSONC config file for LibAFL (including grammar fuzzing options), see [here.](misc/gosentry/libafl.config.jsonc)

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=false --catch-leaks=false --libafl-config=path/to/libafl.jsonc # optional --libafl-config
```

Coverage report generation from a LibAFL campaign corpus is documented in [Feature 8](#feature-8-generate-go-coverage-reports-from-fuzzing-campaign).

Grammar-based fuzzing (Nautilus) is documented in [Feature 7](#feature-7-grammar-based-fuzzing-nautilus).

<details>
<summary><strong>How Go + LibAFL are wired together</strong></summary>

```text
┌───────────────────────────────────────────────────────────────────────────┐
│ 1) gosentry `go test`                                                      │
│    - captures  `testing.F.Fuzz(...)` callback                             │
│    - generates  extra source file: `_libaflmain.go`                       │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 2) Generated bridge: `_libaflmain.go`                                     │
│    - provides libFuzzer-style C ABI entrypoints:                          │
│        LLVMFuzzerInitialize                                               │
│        LLVMFuzzerTestOneInput                                             │
│    - adapts bytes -> Go types -> calls the captured fuzz callback         │
└───────────────┬───────────────────────────────────────────────────────────┘ 
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 3) `libharness.a` (static archive on disk) contains:                      │
│      - compiled objects for all test package (+ dependencies)             │
│      - generated `_testmain.go` + `_libaflmain.go`                        │
│      - LLVMFuzzerInitialize                                               │
│      - LLVMFuzzerTestOneInput                                             │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 4) `golibafl/` (Rust + LibAFL)                                            │
│    env: HARNESS_LIB=/path/to/libharness.a                                 │
│    fuzz loop: mutate input -> LLVMFuzzerTestOneInput(data) -> observe     │
└───────────────────────────────────────────────────────────────────────────┘
```

In `--use-libafl` mode, gosentry builds `libharness.a` and the Rust `golibafl` runner drives it in-process via the libFuzzer entrypoints. Note: `HARNESS_LIB` can point to any harness archive name (for example `libharness_race.a` used by `--catch-races`).
</details>

<details>
<summary><strong>How coverage instrumentation works (LibAFL + Go target)</strong></summary>

In `--use-libafl` mode, gosentry compiles the Go harness with coverage instrumentation enabled. This adds small counters to the code that change when different parts of your program run. When the harness starts inside `golibafl`, the Go runtime exposes these counters to LibAFL. LibAFL reads them after each input to see what code ran, and uses that coverage to guide the next mutations.

</details>



##### Limitations
Let's talk about the motivation behind using LibAFL. Fuzzing with `go test -fuzz` is _far_ behind the state-of-the-art fuzzing techniques. A good example for this is AFL++'s CMPLOG/Redqueen. Those features allow fuzzers to solve certain constraints. Let's assume the following snippet
```go
if input == "IMARANDOMSTRINGJUSTCMPLOGMEMAN" {
	panic("this string is illegal")
}
```
SOTA fuzzers like AFL++ or LibAFL would find the panic instantly in that case. However, Go native fuzzer wouldn't. That is a massive gap that restrains coverage exploration by a **lot**.

The benchmark below show those limits. Note that those benchmarks can be **reproduced** and improved via the [gosentry-bench-libafl repository](https://github.com/kevin-valerio/gosentry-bench-libafl/tree/main).

##### Benchmark 1:

The chart below is the evolution of the number of lines covered while fuzzing Google's [UUID](https://github.com/google/uuid) using LibAFL vs go native fuzzer.
![BENCH1](misc/gosentry/5min_uuid_parsebytes_FuzzParseBytes.png "BENCH1")

##### Benchmark 2:

The chart below is the evolution of the number of lines covered while fuzzing [go-ethereum](https://github.com/ethereum/go-ethereum) using LibAFL vs go native fuzzer.
![BENCH2](misc/gosentry/go-ethereum-30min.png "BENCH1")



#### Example
You can test it on some fuzzing harnesses in `test/gosentry/examples/`.

```bash
cd test/gosentry/examples/reverse
../../../../bin/go test -fuzz=FuzzReverse --focus-on-new-code=false --catch-races=false --catch-leaks=false
```

Stop the fuzz campaign with Ctrl+C.

##### LibAFL output directory (campaign identity / corpus reuse)

gosentry stores LibAFL’s campaign state (corpus, crashes, etc.) under Go’s fuzz cache root (roughly `$(go env GOCACHE)/fuzz`), in a deterministic directory derived from the **same package + same fuzz target** (and the same project root).

This means that stopping (Ctrl+C) and restarting the same fuzz campaign will, by default, continue from the previous LibAFL `queue/` corpus.

The path is printed at the end of the run:

```text
libafl output dir: /full/path/to/.../fuzz/<pkg import path>/libafl/<project>/<harness>
```

Notes:
- `<harness>` is the fuzz target name when `-fuzz` is a simple identifier like `FuzzXxx` (or `^FuzzXxx$`), otherwise it’s `pattern-<hash>`.
- Coverage generation (`--generate-coverage`) uses the same rule to find the right `queue/` corpus, so it must be run from the same package with the same `-fuzz=...`.

## Feature 5: Git-blame-oriented fuzzing (experimental)

#### Overview

Coverage-guided fuzzing is great at exploring new paths, but it treats all covered code as equally interesting. When fuzzing large codebases, you may want to bias the fuzzer toward recently modified code, where regressions and bugs are more likely to be introduced. In LibAFL mode, gosentry can use `git blame` to prefer inputs that execute recently changed lines (while keeping coverage guidance as the primary signal).

This work is based on previous work from [LibAFL-git-aware](https://github.com/kevin-valerio/LibAFL-git-aware). All the technical in-depth details are documented there.

#### How to use

Enable git-aware scheduling with `--focus-on-new-code=true`:

```bash
./bin/go test -fuzz=FuzzHarness --use-libafl --focus-on-new-code=true --catch-races=false --catch-leaks=false
```

This mode needs `git` (to run `git blame`) and `go tool addr2line` to map coverage counters back to source `file:line`.

<details>
<summary><strong>How git-blame-oriented fuzzing works</strong></summary>

```text
┌───────────────────────────────────────────────────────────────────────────┐
│ 1) gosentry `go test -fuzz`                                                │
│    - builds `libharness.a` (contains `go.o` + `.go.fuzzcntrs`)            │
│    - runs `golibafl` with `GOLIBAFL_FOCUS_ON_NEW_CODE=1`                  │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 2) `golibafl` generates a cached "git recency map"                         │
│    - maps coverage counters -> (file:line) via `go tool addr2line`        │
│    - runs `git blame` to get a timestamp per line                         │
│    - stores timestamps in `git_recency_map.bin`                           │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 3) LibAFL scheduler uses the recency map                                  │
│    - coverage decides what enters the corpus                              │
│    - among the corpus, prioritize inputs that hit newer lines             │
└───────────────────────────────────────────────────────────────────────────┘
```
</details>

<details>
<summary><strong>How gosentry builds <code>git_recency_map.bin</code></strong></summary>

`.go.fuzzcntrs` is the linker section that holds Go's libFuzzer-style **8-bit coverage counters** (enabled by `-gcflags=all=-d=libfuzzer`); each byte is "how many times this instrumented spot was hit". When `--focus-on-new-code=true`, `golibafl` generates `git_recency_map.bin` by:
  1. Extracting `go.o` from `libharness.a`.
  2. Reading the `.go.fuzzcntrs` section size to get the counter count `N`.
  3. Scanning `.text` relocations that reference `.go.fuzzcntrs` symbols to recover the address for each counter index.
  4. Resolving each address to `file:line` using `go tool addr2line`.
  5. Running `git blame --line-porcelain` to get `committer-time` per line.
  6. Writing `git_recency_map.bin` as `u64 head_time` + `u64 N` + `N * u64 timestamps` (little-endian). Unmapped entries use timestamp `0`.

</details>

<details>
<summary><strong>Benchmark 1 (go-ethereum / geth): baseline vs git-aware</strong></summary>

Executed with `misc/gosentry/bench_focus_on_new_code_geth.sh --trials 5 --warmup 600 --timeout 200`.

```text
  gitaware_5: crash (7122ms)
baseline results:
  trial 1: crash (107747ms)
  trial 2: crash (146415ms)
  trial 3: crash (37902ms)
  trial 4: crash (154034ms)
  trial 5: timeout (200000ms)
baseline crashes: 4/5 (timeouts=1, errors=0)
baseline median (capped to timeout): 146.415s

git-aware results:
  trial 1: timeout (200000ms)
  trial 2: crash (87432ms)
  trial 3: crash (61733ms)
  trial 4: crash (157540ms)
  trial 5: crash (7122ms)
git-aware crashes: 4/5 (timeouts=1, errors=0)
git-aware median (capped to timeout): 87.432s
```
</details>

## Feature 6: Detect race conditions, goroutine leaks, and hangs (timeouts) at fuzz-time

##### Catching confirmed hangs (LibAFL timeouts)

When fuzzing with LibAFL, a harness execution can **timeout** (for example because of a deadlock / goroutines stuck waiting, or an extremely slow path).

To reduce false positives, gosentry treats a timeout as a hang candidate and confirms it by replaying the timed-out input a few times with a larger timeout. On a confirmed hang, gosentry writes the input to `<libafl output dir>/hangs/` and stops the fuzz campaign (treats it like a bug/crash).

Before exiting, `golibafl` attempts to minimize the crashing/hanging input (best-effort; hangs are capped to ~60s total).

Note: hang confirmation also runs during initial corpus import/generation, so targets that time out on every input can still be detected deterministically.

This is configured via `--libafl-config`:
- `catch_hangs` (default: `true`)
- `hang_timeout_ms` (default: `10000`)
- `hang_confirm_runs` (default: `3`)

##### Catching data races (`--catch-races`)

gosentry can run a separate `-race` replay loop that watches the LibAFL `queue/` directory and replays newly discovered seeds with `GORACE=halt_on_error=1`.

The replay loop builds a separate `-race` harness archive for replay-only (no fuzz coverage instrumentation).

When a data race is detected during replay, gosentry prints the full race detector report before the `catch-races:` summary and repro command.

Note: Go’s race detector only detects data races **inside a single harness execution** (races between goroutines in the same process accessing the same memory without proper synchronization). `--catch-races` will miss races if the seed does not trigger the racy concurrency, and it does not detect cross-process races.

<details>
<summary><strong>How data race mode works</strong></summary>

This mode starts a small monitor inside `go test` (same parent process), and it runs for the whole fuzz campaign.

- When: before the main LibAFL fuzzing process is started, gosentry builds the replay harness + runner.
- Monitoring: before fuzzing starts, gosentry snapshots the initial contents of `<libafl output dir>/queue/` into a `seen` set. A goroutine then polls `<libafl output dir>/queue/` every ~1s and only replays newly created seeds (skips dotfiles and `*.metadata`).

```text
Legend: output/... = <libafl output dir>/...

┌───────────────────────────────────────────────────────────────────────────┐
│ 1) Main LibAFL fuzzing run                                                 │
│    - `golibafl` writes new seeds to `output/queue/`                        │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 2) `--catch-races` sidecar setup                                           │
│    - builds replay harness: `libharness_race.a` (`go test -race ...`)      │
│    - builds replay runner: `golibafl-race` (linked against race harness)   │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 3) Replay loop                                                             │
│    - polls `output/queue/` for new seeds                                   │
│    - runs: `GORACE=halt_on_error=1 golibafl-race run --input <seed>`       │
│      (2 workers × 3 repeats per seed)                                      │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 4) On "DATA RACE"                                                          │
│    - prints the race detector report                                       │
│    - copies seed to `output/races/`                                        │
│    - stops the fuzz campaign (treat as bug/crash)                          │
└───────────────────────────────────────────────────────────────────────────┘
```
</details>

##### Catching goroutine leaks (`--catch-leaks`)

gosentry can also run a `goleak` replay loop that watches the LibAFL `queue/` directory and replays newly discovered seeds with `go.uber.org/goleak` enabled.

On a detected goroutine leak, gosentry prints the exact seed path and copies it into `<libafl output dir>/leaks/`.

Note: `goleak` is for **goroutine leaks**, not memory leaks.

<details>
<summary><strong>How goroutine leaks mode works</strong></summary>

This mode also starts a small monitor inside `go test` (same parent process), and it runs for the whole fuzz campaign.
- Monitoring: a goroutine polls `<libafl output dir>/queue/` every ~1s and replays each new seed with `GOSENTRY_LIBAFL_CATCH_LEAKS=1` (enables `go.uber.org/goleak` after each execution).

```text
Legend: output/... = <libafl output dir>/...

┌───────────────────────────────────────────────────────────────────────────┐
│ 1) Main LibAFL fuzzing run                                                 │
│    - `golibafl` writes new seeds to `output/queue/`                        │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 2) `--catch-leaks` sidecar setup                                           │
│    - builds replay runner: `golibafl-leak` (linked against the harness)    │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 3) Replay loop                                                             │
│    - polls `output/queue/` for new seeds                                   │
│    - runs: `GOSENTRY_LIBAFL_CATCH_LEAKS=1 golibafl-leak run --input <seed>`│
│      (enables `go.uber.org/goleak` checks after each execution)            │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 4) On "catch-leaks: detected goroutine leak"                               │
│    - copies seed to `output/leaks/`                                        │
│    - stops the fuzz campaign (treat as bug/crash)                          │
└───────────────────────────────────────────────────────────────────────────┘
```
</details>


#### How to use

Enable goroutine leak catching with `--catch-leaks=true` or race catching with `--catch-races=true`

```bash
./bin/go test -fuzz=FuzzHarness --use-libafl --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

## Feature 7: Grammar-based fuzzing (Nautilus)

#### Overview

Byte-level fuzzing is great, but parsers and file formats often need structured inputs. With `--use-grammar`, gosentry uses LibAFL’s Nautilus grammar mutator to generate and mutate inputs that conform to a user-provided grammar (JSON format), and feeds them to your regular Go fuzz harness (`testing.F.Fuzz`).

In grammar mode, LibAFL still runs the normal coverage-guided loop (pick a corpus seed → mutate → execute → keep inputs that increase coverage). The runner adds Nautilus mutation (seed → grammar tree → mutate → unparse) plus (by default) a CMPLOG-guided, I2S-like stage that rewrites Nautilus **leaf terminals** based on runtime comparisons. This keeps inputs grammar-valid (it does not run the raw byte-level havoc/token stages in grammar mode). You can disable the CMPLOG/I2S stage in `--libafl-config` via `nautilus_cmplog_i2s=false` (byte-level fuzzing still keeps CMPLOG/I2S always on).

> [!NOTE]
> Grammar mode is usually slower than byte-level fuzzing. It is a trade-off: more structure vs fewer executions per second.

For best results, use a one-arg fuzz callback that takes either a byte slice (`[]byte`) or a `string`:

```go
f.Fuzz(func(t *testing.T, data []byte) { /* parse data */ })
// or:
f.Fuzz(func(t *testing.T, s string) { /* parse s */ })
```

Grammar mode works best with a single input argument (`[]byte` or `string`). Multi-arg fuzz callbacks cause gosentry to decode the underlying byte buffer into separate values, so the original grammar-generated text won’t stay intact.

> [!NOTE]
> Grammar mode still generates **bytes/strings**. If you need structured inputs (or you’re doing differential fuzzing), your harness is where you convert `data` into domain values (parse/unmarshal). (Outside of grammar mode, gosentry can also fuzz composite Go > types by decoding them from bytes; see [Feature 1](#feature-1-struct-aware-fuzzing-fuzz-structs-as-inputs).)

You can tune Nautilus via `--libafl-config` (only used with `--use-grammar`): `nautilus_max_len` and `nautilus_cmplog_i2s` (see `misc/gosentry/libafl.config.jsonc`).

<details>
<summary><strong>Benchmark: Nautilus grammar CMPLOG/I2S stage (on vs off)</strong></summary>

Executed on Feb 17, 2026 using the repo’s JSON grammar example (`test/gosentry/examples/grammar_json`, `FuzzGrammarJSON`, grammar `testdata/JSON.json`).

Results (LibAFL `UserStats`):

| mode | `nautilus_cmplog_i2s` | run time | executions | exec/sec | edges |
|---|---:|---:|---:|---:|---:|
| on | `true` | 1m-5s | 103818 | 1.586k | 388/8008 (4%) |
| off | `false` | 1m-0s | 256659 | 4.251k | 388/8008 (4%) |

Note: `edges` is LibAFL’s coverage map edges, not Go source lines.

</details>

Set `GOSENTRY_VERBOSE_AFL=1` to print a few generated inputs. Set `GOSENTRY_VERBOSE_AFL_ALL_INPUTS=1` to print **every** grammar-mode execution as `GOLIBAFL_MUTATED_INPUT "..."` (very noisy).

#### Grammar authoring helpers

If you need to create a new Nautilus JSON grammar for your own target format/protocol, gosentry ships:

- An LLM-ready prompt: [misc/gosentry/nautilus/prompt.md](misc/gosentry/nautilus/prompt.md)
- A small set of example grammars: [misc/gosentry/nautilus/examples/](misc/gosentry/nautilus/examples/)

<details>
<summary><strong>Go fuzz harness example (JSON)</strong></summary>

```go
func FuzzGrammarJSON(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()

		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			t.Fatalf("invalid JSON: trailing data")
		}
	})
}
```

Differential fuzzing harness sketch (two parsers):

```go
f.Fuzz(func(t *testing.T, data []byte) {
	gotA, errA := ParseA(data)
	gotB, errB := ParseB(data)
	if (errA == nil) != (errB == nil) {
		t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
	}
	_ = gotA
	_ = gotB
})
```

</details>

<details>
<summary><strong>Example: grammar fuzzing a "real input language" (no custom encoder)</strong></summary>

This example fuzzes a tiny arithmetic expression evaluator by generating **valid expressions** from a grammar. There’s no ad-hoc “struct to bytes” encoding: the fuzzer produces the same kind of input your code would normally parse.

Harness (1-arg `string` input works best in grammar mode):

```go
func FuzzExprEval(f *testing.F) {
	f.Add("1+2")
	f.Add("(3*4)-5")

	f.Fuzz(func(t *testing.T, expr string) {
		// Parse+eval your language/protocol.
    // You can be **sure** that `expr` will always be a valid math operation. Just decode/parse/unmarshall it afterwards. 
		_, _ = Eval(expr)
	})
}
```

Grammar sketch (Nautilus JSON format):

```json
[
  ["Expr", "{Term}"],
  ["Expr", "{Term}+{Expr}"],
  ["Expr", "{Term}-{Expr}"],
  ["Term", "{Factor}"],
  ["Term", "{Factor}*{Term}"],
  ["Factor", "{Num}"],
  ["Factor", "({Expr})"],
  ["Num", "0"],
  ["Num", "1"],
  ["Num", "2"],
  ["Num", "3"]
]
```

</details>

<details>
<summary><strong>Nautilus JSON grammar example (small JSON subset)</strong></summary>

This is the file format expected by `--grammar=...`:
- The grammar is a JSON array of rules: `["NonTerm", "RHS"]`.
- Nonterminal names must start with a capital letter (`Value`, `Object`, ...).
- Use `{NonTerm}` in the RHS to reference another rule.
- `{` and `}` are reserved for nonterminal references; to emit literal braces, use `\\{` and `\\}` in the RHS string.

```json
[
  ["Json", "{Value}"],
  ["Value", "null"],
  ["Value", "{String}"],
  ["String", "\"{Chars}\""],
  ["Chars", ""],
  ["Chars", "{Char}{Chars}"],
  ["Char", "a"],
  ["Char", "b"]
]
```

</details> 

<details>
<summary><strong>How grammar fuzzing works in gosentry</strong></summary>

```text
Legend: output/... = <libafl output dir>/...

┌───────────────────────────────────────────────────────────────────────────┐
│ 0) gosentry `go test -fuzz=FuzzXxx` (LibAFL + --use-grammar)               │
│    - captures your `testing.F.Fuzz` callback + its parameter types          │
│    - builds `libharness.a` (libFuzzer-style entrypoints for LibAFL)         │
│    - runs `golibafl fuzz ... --use-grammar --grammar ...`                   │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 1) `golibafl` (Rust + LibAFL) fuzzes the Go harness in-process              │
│    - loads `libharness.a` via `HARNESS_LIB=...`                             │
│    - observers: edges + time (+ cmplog for comparisons)                     │
│    - feedback/objective: coverage/time/crash (and optional hang handling)   │
│    - scheduler selects a corpus seed (coverage-guided)                      │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 2) Nautilus (in-process, per client)                                       │
│    - loads the JSON grammar into a Nautilus context                         │
│    - fuzz loop stage: parse seed -> mutate tree -> unparse to bytes         │
│    - if the seed is not parseable: fall back to generation-from-scratch     │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 3) Grammar mode stages                                                     │
│    - initial corpus: if input dir empty, call `generate` N times            │
│    - fuzz loop: corpus seed -> grammar mutate -> exec harness               │
│    - new coverage inputs are added to the on-disk corpus (`output/queue/`)  │
└───────────────────────────────────────────────────────────────────────────┘
```

</details>

Limitations (current glue):
- Grammar mode works best with a single input argument; multi-arg fuzz targets will decode the underlying byte buffer into separate values.
- No grammar recombination/crossover between two corpus seeds yet (mutation is single-seed).

## Feature 8: Generate Go coverage reports from fuzzing campaign

After (or while) running a LibAFL fuzz campaign, gosentry can generate a Go coverage report by replaying the current LibAFL **queue corpus** (no fuzzing).

```bash
# Same package + same fuzz target as your fuzz campaign:
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

This replays inputs from `<libafl output dir>/queue/` and writes over.out and cover.html 

## Trophies

Those bugs were found by doing differential-fuzzing campaign using gosentry's grammar fuzzing feature.

#### Optimism

- [Kona and op-node can disagree on brotli channels](https://github.com/ethereum-optimism/optimism/issues/19333)
- [Unknown batch type panics and causes denial of service in kona-protocol](https://github.com/ethereum-optimism/optimism/issues/19334)
- [Kona frame parsing mismatch against op-node and OP Stack Specs](https://github.com/ethereum-optimism/optimism/issues/19335)

#### REVM

- [Failed deposit in op-revm stopping with `OutOfFunds` doesn't bump nonce, leading to state root mismatch against other clients](https://github.com/bluealloy/revm/issues/3458)

## Credits
- [golibafl](https://github.com/srlabs/golibafl/)
- [Nautilus](https://github.com/nautilus-fuzz/nautilus/)
- [LibAFL](https://github.com/AFLplusplus/LibAFL)
- [goleak](https://github.com/uber-go/goleak)
- [go](https://github.com/golang/go)
- [go-panikint](https://github.com/trailofbits/go-panikint)