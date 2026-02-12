# gosentry

[![integration tests](https://github.com/kevin-valerio/gosentry/actions/workflows/go.yml/badge.svg?branch=master)](https://github.com/kevin-valerio/gosentry/actions/workflows/go.yml)

gosentry is a security-focused fork of the Go toolchain. In a _very_ simple phrasing, it's copy of the Go compiler that finds bugs. If you are a security researcher auditing Go codebases, you should probably use this tool and consider it as a great swiss-knife.

For now, it focuses on the following features:

- Integrating [go-panikint](https://github.com/trailofbits/go-panikint): instrumentation that panics on **integer overflow/underflow** (and **optionally on truncating integer conversions**).
- Integrating [LibAFL](https://github.com/AFLplusplus/LibAFL) fuzzer: run Go fuzzing harnesses with **LibAFL** for better fuzzing performances.
- Proposing **Grammar-based fuzzing** (ANTLRv4 via [Grammarinator](https://github.com/renatahodovan/grammarinator)): generate structured inputs from a grammar ([Feature 6](#feature-6-grammar-based-fuzzing-grammarinator)).
- Panicking on [user-provided function call](https://github.com/kevin-valerio/gosentry?tab=readme-ov-file#feature-2-panic-on-selected-functions): catching targeted bugs when certains functions are called (eg., `myapp.(*Logger).Error`).
- Git-blame-oriented fuzzing (based on [this work](https://github.com/kevin-valerio/LibAFL-git-aware)): when fuzzing with LibAFL mode, you can orientate the fuzzer towards **recently added/edited lines**.
- Detect **race conditions**, **goroutine leaks**, and **confirmed hangs** at fuzz-time: when fuzzing with LibAFL, gosentry can replay newly found seeds (or timed-out executions) and treat findings like bugs.

It especially has **two** objectives:
- Being easy to use and UX-friendly (_we're tired of complex tools_),
- Helping to find bugs in Go codebases via built-in security implementations.

## Table of Contents

- [Build](#build)
  - [Feature 1: Integer overflow and truncation issues detection](#feature-1-integer-overflow-and-truncation-issues-detection)
  - [Feature 2: Panic on selected functions](#feature-2-panic-on-selected-functions)
  - [Feature 3: LibAFL state-of-the-art fuzzing](#feature-3-libafl-state-of-the-art-fuzzing)
  - [Feature 4: Git-blame-oriented fuzzing (experimental)](#feature-4-git-blame-oriented-fuzzing-experimental)
  - [Feature 5: Detect race conditions, goroutine leaks, and hangs at fuzz-time](#feature-5-detect-race-conditions-goroutine-leaks-and-hangs-at-fuzz-time)
  - [Feature 6: Grammar-based fuzzing (Grammarinator)](#feature-6-grammar-based-fuzzing-grammarinator)
- [Credits](#credits)

## Build
```bash
cd src && ./make.bash # This produces `./bin/go`. See `GOFLAGS` below.
```

## Feature 1: Integer overflow and truncation issues detection

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

## Feature 2: Panic on selected functions

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

## Feature 3: LibAFL state-of-the-art fuzzing

LibAFL performs *way* better than the traditional Go fuzzer. When fuzzing (`go test -fuzz=...`), gosentry uses [LibAFL](https://github.com/AFLplusplus/LibAFL) **by default** (runner in `golibafl/`).

When using LibAFL (default), you must explicitly choose whether to enable git-aware scheduling: `--focus-on-new-code=true|false`.

You must also explicitly choose whether to enable data race catching: `--catch-races=true|false` (see Feature 5).

You must also explicitly choose whether to enable goroutine leak catching: `--catch-leaks=true|false` (see Feature 5).

To opt out:
- `--use-libafl=false`: use Go's native fuzzing engine instead of LibAFL.

More documentation in [this Markdown file.](misc/gosentry/USE_LIBAFL.md)

You can also pass an optional config. file for LibAFL, see [here.](misc/gosentry/libafl.config.jsonc)

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=false --catch-leaks=false --libafl-config=path/to/libafl.jsonc # optional --libafl-config
```

Grammar-based fuzzing (Grammarinator) is documented in [Feature 6](#feature-6-grammar-based-fuzzing-grammarinator).

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

## Feature 4: Git-blame-oriented fuzzing (experimental)

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

## Feature 5: Detect race conditions, goroutine leaks, and hangs (timeouts) at fuzz-time

##### Catching confirmed hangs (LibAFL timeouts)

When fuzzing with LibAFL, a harness execution can **timeout** (for example because of a deadlock / goroutines stuck waiting, or an extremely slow path).

To reduce false positives, gosentry treats a timeout as a hang candidate and confirms it by replaying the timed-out input a few times with a larger timeout. On a confirmed hang, gosentry writes the input to `output/hangs/` and stops the fuzz campaign (treats it like a bug/crash).

Note: hang confirmation also runs during initial corpus import/generation, so targets that time out on every input can still be detected deterministically.

This is configured via `--libafl-config`:
- `catch_hangs` (default: `true`)
- `hang_timeout_ms` (default: `10000`)
- `hang_confirm_runs` (default: `3`)

##### Catching data races (`--catch-races`)

gosentry can run a separate `-race` replay loop that watches the LibAFL `queue/` directory and replays newly discovered seeds with `GORACE=halt_on_error=1`.

The replay loop builds a separate `-race` harness archive for replay-only (no fuzz coverage instrumentation).

Note: Go’s race detector only detects data races **inside a single harness execution** (races between goroutines in the same process accessing the same memory without proper synchronization). `--catch-races` will miss races if the seed does not trigger the racy concurrency, and it does not detect cross-process races.

<details>
<summary><strong>How data race mode works</strong></summary>

This mode starts a small monitor inside `go test` (same parent process), and it runs for the whole fuzz campaign.

- When: before the main LibAFL fuzzing process is started, gosentry builds the replay harness + runner.
- Monitoring: before fuzzing starts, gosentry snapshots the initial contents of `<libafl output dir>/queue/` into a `seen` set. A goroutine then polls `<libafl output dir>/queue/` every ~1s and only replays newly created seeds (skips dotfiles and `*.metadata`).

```text
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
│    - copies seed to `output/races/`                                        │
│    - stops the fuzz campaign (treat as bug/crash)                          │
└───────────────────────────────────────────────────────────────────────────┘
```
</details>

##### Catching goroutine leaks (`--catch-leaks`)

gosentry can also run a `goleak` replay loop that watches the LibAFL `queue/` directory and replays newly discovered seeds with `go.uber.org/goleak` enabled.

On a detected goroutine leak, gosentry prints the exact seed path and copies it into `output/leaks/`.

Note: `goleak` is for **goroutine leaks**, not memory leaks.

<details>
<summary><strong>How goroutine leaks mode works</strong></summary>

This mode also starts a small monitor inside `go test` (same parent process), and it runs for the whole fuzz campaign.
- Monitoring: a goroutine polls `<libafl output dir>/queue/` every ~1s and replays each new seed with `GOSENTRY_LIBAFL_CATCH_LEAKS=1` (enables `go.uber.org/goleak` after each execution).

```text
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

## Feature 6: Grammar-based fuzzing (Grammarinator)

#### Overview

Byte-level fuzzing is great, but parsers and file formats often need structured inputs. gosentry can generate inputs from an ANTLRv4 grammar via [Grammarinator](https://github.com/renatahodovan/grammarinator), and feed them to your regular Go fuzz harness (`testing.F.Fuzz`).

In grammar mode, LibAFL still runs the normal coverage-guided loop (pick a corpus seed → mutate → execute → keep inputs that increase coverage). The difference is the mutator: instead of byte-level havoc, gosentry uses Grammarinator to do **grammar-aware mutation** of the currently selected corpus seed (parse → mutate the derivation tree → serialize back to text).

For best results, use a one-arg fuzz callback that takes either a byte slice (`[]byte`) or a `string`:

```go
f.Fuzz(func(t *testing.T, data []byte) { /* parse data */ })
// or:
f.Fuzz(func(t *testing.T, s string) { /* parse s */ })
```

If you use multiple inputs in your harness, gosentry will decode the underlying byte buffer into separate values, so the original grammar-generated text won’t stay intact.

#### How to use 
Requirements:  `python3` with `grammarinator` installed (`python3 -m pip install grammarinator`) and Java (JRE/JDK) for Grammarinator/ANTLR.

<details>
<summary><strong>Command example</strong></summary>
Set `GOSENTRY_VERBOSE_AFL=1` to print a few generated inputs (useful to verify you are really running in grammar mode).

```bash
# Example (from this repo): JSON grammar + JSON harness.
gosentry test -fuzz=FuzzGrammarJSON --use-grammar --grammar=testdata/JSON.g4 --start-rule=json --focus-on-new-code=false --catch-races=false --catch-leaks=false
```

</details>

<details>
<summary><strong>Go fuzz harness example (JSON)</strong></summary>

```go
package mypkg

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

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

</details>

<details>
<summary><strong>ANTLRv4 grammar example (small JSON subset)</strong></summary>

```antlr
grammar MiniJSON;

json : value EOF ;

value
  : STRING
  | NUMBER
  | obj
  | arr
  | 'true'
  | 'false'
  | 'null'
  ;

obj  : '{' pair (',' pair)* '}' | '{' '}' ;
pair : STRING ':' value ;
arr  : '[' value (',' value)* ']' | '[' ']' ;

STRING : '"' [a-zA-Z0-9 _.-]* '"' ;
NUMBER : '-'? ('0' | [1-9] [0-9]*) ;
WS     : [ \t\r\n]+ -> skip ;
```

</details> 

<details>
<summary><strong>How grammar fuzzing works in gosentry</strong></summary>

```text
┌───────────────────────────────────────────────────────────────────────────┐
│ 0) gosentry `go test -fuzz=FuzzXxx` (LibAFL + --use-grammar)               │
│    - captures your `testing.F.Fuzz` callback + its parameter types          │
│    - builds `libharness.a` (libFuzzer-style entrypoints for LibAFL)         │
│    - runs `golibafl fuzz ... --use-grammar --grammar ... --start-rule ...`  │
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
│ 2) Grammarinator engine (`python3` subprocess, per client)                  │
│    - `ProcessorTool`: turns `.g4` file(s) into a Python `*Generator.py`     │
│    - protocol: JSON per line over stdin/stdout (generate / mutate(seed))    │
│    - mutate = parse seed -> mutate derivation tree -> serialize back        │
│    - validates candidates by re-parsing; retries on invalid outputs         │
└───────────────┬───────────────────────────────────────────────────────────┘
                v
┌───────────────────────────────────────────────────────────────────────────┐
│ 3) Grammar mode stages                                                     │
│    - initial corpus: if input dir empty, call `generate` N times            │
│    - fuzz loop: corpus seed -> `mutate(seed)` -> exec harness               │
│    - new coverage inputs are added to the on-disk corpus (`output/queue/`)  │
└───────────────────────────────────────────────────────────────────────────┘

Example protocol:
  {"op":"generate"}
  {"op":"mutate","input":"...seed..."}
  "<generated or mutated input string>"
```

</details>

Limitations (current glue):
- Grammar mode currently expects UTF-8 text inputs (the Grammarinator subprocess works with strings).
- Grammar mode works best with a single input argument; multi-arg fuzz targets will decode the underlying byte buffer into separate values.
- Grammarinator mutation is best-effort; `golibafl` validates candidates by re-parsing and retries. If repeated mutation attempts fail, it may fall back to generation-from-scratch to keep fuzzing.
- The LibAFL corpus is stored as raw bytes on disk; Grammarinator trees are cached only in-memory (per client, bounded), so restarts lose the tree cache.
- No grammar recombination/crossover between two corpus seeds yet (mutation is single-seed).

## Credits

Credits to Bruno Produit and Nills Ollrogge for their work on [golibafl](https://github.com/srlabs/golibafl/).
