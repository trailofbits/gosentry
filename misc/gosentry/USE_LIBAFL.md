# gosentry: `go test -fuzz` (LibAFL by default)

gosentry contains:

- `./`: a fork of the Go toolchain
- `golibafl/`: a LibAFL-based fuzzer that can fuzz Go code in-process via a libFuzzer-style entrypoint.

This repo adds a glue path so a user can keep writing **standard Go fuzz tests** (the ones used by `go test -fuzz=...`) and switch engines.

By default, when `-fuzz` is set, gosentry uses the LibAFL runner.

```bash
go test -fuzz=FuzzXxx --focus-on-new-code=false --catch-races=false --catch-leaks=false
```

To opt out:

```bash
go test -use-libafl=false -fuzz=FuzzXxx
```

## Git-aware scheduling (focus on new code)

`--focus-on-new-code={true|false}` enables git-aware scheduling to prefer inputs that execute recently changed lines (based on `git blame`).

This flag only applies in LibAFL mode and is required.

- `--focus-on-new-code=false`: keep the current behavior.
- `--focus-on-new-code=true`: prefer inputs that execute recently changed lines (based on `git blame`).

Note: `--focus-on-new-code=true` needs `git` (to run `git blame`) and `go tool addr2line` to map coverage counters back to source `file:line`.

## Catching data races (optional)

`--catch-races={true|false}` enables a separate `-race` replay loop that watches the LibAFL `queue/` corpus directory and replays only newly discovered seeds with `GORACE=halt_on_error=1`.

When a race is detected, gosentry prints the exact seed path, copies the seed into `output/races/` (under the LibAFL output directory), and stops the fuzz campaign (treats it like a bug/crash).

This flag only applies in LibAFL mode and is required.

Note: the Go race detector only reports unsynchronized concurrent access between goroutines in a single process. If the target has no concurrency / shared mutable state during the replay run, there may be no races to catch.

### CI note

This repo runs the `--catch-races` smoke test in its own GitHub Actions workflow (`.github/workflows/catch_races.yml`) so it shows up as a separate check.

## Catching goroutine leaks (optional)

`--catch-leaks={true|false}` enables a `goleak` replay loop that watches the LibAFL `queue/` corpus directory and replays only newly discovered seeds with `go.uber.org/goleak`.

When a goroutine leak is detected, gosentry prints the exact seed path, copies the seed into `output/leaks/` (under the LibAFL output directory), and stops the fuzz campaign (treats it like a bug/crash).

This flag only applies in LibAFL mode and is required.

Note: `goleak` is for **goroutine leaks**, not memory leaks.

### CI note

This repo runs the `--catch-leaks` smoke test in its own GitHub Actions workflow (`.github/workflows/catch_leaks.yml`) so it shows up as a separate check.

`golibafl` stores the generated mapping file under the LibAFL output directory as `git_recency_map.bin` (path provided to the runner via `LIBAFL_GIT_RECENCY_MAPPING_PATH`).
On large targets, generating this file can take several minutes because it needs to run `go tool addr2line` and `git blame` for many coverage counters.

To make this less “silent”, `golibafl` prints progress during generation (and runs `go tool addr2line` in parallel):

```
golibafl: generating git recency mapping (450229 counters); this may take a while
golibafl: running go tool addr2line on 450229 addresses
golibafl: addr2line sent 120000/450229 got 80000/450229 elapsed 30s
golibafl: running git blame on 1043 file(s)
golibafl: git blame progress 702/1043 (67.3%), elapsed 20s
```

To avoid regenerating the full mapping on commits that don't change the Go harness object (`go.o`), `golibafl` writes a small sidecar file next to it: `git_recency_map.bin.meta.json`.
If the sidecar indicates the current `go.o` hash matches, `golibafl` will reuse the existing mapping entries and only update the `head_time` header in `git_recency_map.bin`.

Implementation note: the git-aware scheduler currently comes from a local LibAFL fork (TODO: switch back to upstream LibAFL once upstreamed).

### Benchmark (geth)

A paired benchmark for `--focus-on-new-code` on a shallow clone of go-ethereum (geth) lives at `misc/gosentry/bench_focus_on_new_code_geth.sh`.

## Runner configuration

gosentry can pass a JSONC configuration file (JSON with `//` comments) to the LibAFL runner:

```bash
go test -fuzz=FuzzXxx --focus-on-new-code=false --catch-races=false --catch-leaks=false --libafl-config=libafl.jsonc
```

`golibafl` also needs a TCP broker port for LibAFL's internal event manager. By default, it picks a **random free port** (instead of always `1337`). If you need a fixed port, set `GOLIBAFL_BROKER_PORT=1337` (or pass `-p/--port 1337` when running `golibafl` directly).

Example `libafl.jsonc` (all fields optional; defaults shown in comments):

```jsonc
{
  // cores: CPU cores to bind LibAFL clients to (ex: "0,1" / "all" / "none")
  // default (gosentry go test): "0" (single client)
  "cores": "0,1",

  // exec_timeout_ms: per-execution timeout for the in-process harness
  // default: 1000
  "exec_timeout_ms": 1000,

  // git_recency_alpha: bias strength for git-aware scheduling when --focus-on-new-code=true
  // min: 0.0
  // max: 10.0
  // default: 2.0
  // recommended: 2.0
  "git_recency_alpha": 2.0,

  // corpus_cache_size: in-memory cache size for each on-disk corpus
  // default: 4096
  "corpus_cache_size": 4096,

  // initial_generated_inputs: generated corpus size if the input dir is empty
  // default: 8
  "initial_generated_inputs": 8,

  // initial_input_max_len: max length for generated initial inputs
  // default: 32
  "initial_input_max_len": 32,

  // tui_monitor: enable LibAFL's interactive terminal UI (TUI)
  // default: true
  "tui_monitor": true,

  // debug_output: force-enable/disable LIBAFL_DEBUG_OUTPUT (otherwise auto)
  // default: auto (enabled when running with a single client)
  "debug_output": true
}
```

A ready-to-edit template lives at `misc/gosentry/libafl.config.jsonc`.

## Troubleshooting

If `golibafl` fails to launch, set `GOSENTRY_VERBOSE_AFL=1` to print extra diagnostics and write them to `OUTPUT_DIR/golibafl_launcher_failure_<pid>.txt`.

If fuzzing prints repeated timeouts with **0 executions** or appears stuck during startup, make sure you are using a LibAFL fork/build that runs the restarting manager in **non-fork (re-exec) mode**. The embedded Go runtime is not fork-safe once initialized, so forking-based restarts can deadlock and look like “exec/sec: 0.000”.

If you see a panic like `BUG: The current message never got committed using send!` (from `crates/ll_mp/...`) while stopping a fuzz run, it is a `golibafl`/LibAFL shutdown issue (not a Go harness bug). Rebuild/update `golibafl` and retry; clean shutdown should print `Fuzzing stopped by user. Good bye.` and `go test` should end with `ok ...`.

## Quick start

1) Build the forked toolchain:

```bash
cd src
./make.bash
```

2) Run a fuzz target with LibAFL (example in this repo):

```bash
cd test/gosentry/examples/reverse
CGO_ENABLED=1 ../../../../bin/go test -fuzz=FuzzReverse --focus-on-new-code=false --catch-races=false
```

Fuzzing runs until you stop it (Ctrl+C). The run prints `ok ...` on clean shutdown.

## Requirements

- `CGO_ENABLED=1` (required; the harness exports C ABI symbols)
- Rust toolchain + `cargo` (because the runner is `golibafl`)
- Repo layout assumption: `golibafl/` must live inside the active `GOROOT` directory (at `$GOROOT/golibafl`).
  - In this repo that means `.../gosentry/golibafl`.

## What happens under the hood

When `go test` sees `-fuzz` (and `-use-libafl` is true, which is the default), it does **not** execute Go’s native fuzzing coordinator/worker engine.
Instead it builds a **libFuzzer-compatible harness** and runs the Rust LibAFL runner against it.

### 1) `go test` builds a libFuzzer harness archive (`libharness.a`)

For the test package’s generated main package (`_testmain.go`), gosentry also generates an extra file (`_libaflmain.go`) and switches the link mode:

- buildmode: `c-archive` → produces a static archive: `libharness.a`
- exports:
  - `LLVMFuzzerInitialize`
  - `LLVMFuzzerTestOneInput`

Those are the standard libFuzzer entrypoints expected by `libafl_targets::libfuzzer`.

`LLVMFuzzerInitialize` selects the fuzz target that matches the `-fuzz` regexp and initializes the captured Go fuzz callback.

`LLVMFuzzerTestOneInput` converts the input bytes and calls the fuzz callback once.

### 2) The fuzz callback is captured from standard `testing.F.Fuzz`

The `testing` package is patched so that, in this special mode, the first `f.Fuzz(func(*testing.T, []byte){...})` call is **captured** instead of starting the native Go fuzzing engine.

Then `testing.LibAFLFuzzOneInput` runs the captured callback in a normal `testing.T` context (using `tRunner`) so that `t.Fatal` / `t.FailNow` behave correctly (they call `runtime.Goexit`).

### 3) `go test` runs `golibafl` (Rust) with `HARNESS_LIB=...`

After building `libharness.a`, `go test` launches:

```bash
cargo run --release -- fuzz -i <input_dir> -o <output_dir>
```

with:

- `HARNESS_LIB=<path to built libharness.a>`
- `HARNESS_LINK_SEARCH=/path/one:/path/two` (optional: extra native link search dirs)
- `HARNESS_LINK_LIBS=dylib=dl,static=z` (optional: extra `rustc-link-lib` entries)
- working directory set to the `golibafl/` crate

`golibafl` was updated to accept `HARNESS_LIB` and **link the prebuilt archive** instead of rebuilding a harness from a `HARNESS=...` directory.

### 4) Output directories

gosentry reuses Go’s fuzz cache root (roughly `$(go env GOCACHE)/fuzz`) so `go clean -fuzzcache` works.

LibAFL output is separated per **project + package + fuzz target**:

```
.../fuzz/<pkg import path>/libafl/<project>/<harness>/
  input/     # initial corpus dir (merged from testdata/fuzz + f.Add); may be empty
  queue/     # evolving corpus
  crashes/   # crashes (if any)
```

- `<project>` is derived from the package root directory (module root / GOPATH / GOROOT root) and formatted as `<basename>-<hash>`.
- `<harness>` is the fuzz target name when `-fuzz` is a simple identifier like `FuzzXxx` (or `^FuzzXxx$`), otherwise `pattern-<hash>`.

On each run, gosentry prepares `<...>/input/` as the initial `-i` corpus directory:

- files from `testdata/fuzz/` (if it exists) are copied into it
- manual seeds provided via `f.Add(...)` are written into it automatically
- if this fuzzing campaign was already run before, the previous LibAFL `queue/` corpus is automatically reused on restart (so Ctrl-C + rerun continues from the same corpus by default)

If the chosen `-i` directory is empty, `golibafl` generates a small random initial corpus.

On shutdown, `go test` prints the full output directory path:

```
libafl output dir: /full/path/to/.../libafl/<project>/<harness>
```

### Crash handling (stop on first crash)

In `--use-libafl` mode, gosentry follows `go test -fuzz` semantics: **stop the whole fuzzing run on the first crash** (even with multiple LibAFL clients).

When a crash is found, `golibafl` prints:
- the output directory + `crashes/` path
- the exact crash input file path
- a repro command: `golibafl run --input <crash_file>`

To keep fuzzing after crashes, set `"stop_all_fuzzers_on_panic": false` in the LibAFL JSONC config.

Note: reproducing may require the same runtime environment variables as fuzzing (e.g. `LD_LIBRARY_PATH` for native deps).

## Current limitations

- Supports **multiple parameters** and gosentry’s fuzzable types:
  - all of Go’s native fuzzing primitives (`[]byte`, `string`, `bool`, `byte`, `rune`, `float32`, `float64`, `int*`, `uint*`)
  - composite types built from those (`struct`, `array`, `slice`, `*T`), recursively

```go
f.Fuzz(func(t *testing.T, in MyStruct, data []byte, n int) { ... })
```

## Notes / gotchas

- `--use-libafl` is intended only for `go test -fuzz=...`.
  It errors if you pass it without `-fuzz`.
- The toolchain adds the `libfuzzer` build tag during compilation in this mode, enabling Go’s `-d=libfuzzer` instrumentation path for coverage/cmp tracing.
- On Unix, `golibafl` uses LibAFL’s restarting manager in **non-fork (re-exec) mode** for reliability with the embedded Go runtime. This is also why `golibafl` switches its working directory to `OUTPUT_DIR/workdir/<pid>` (so respawns don’t fail if the original cwd is deleted/unlinked).
