# gosentry architecture (feature ↔ code map)

This is a pointer document. For user-facing usage, see `README.md`.

## Feature 1: integer overflow/truncation detection (go-panikint-style)

- Compiler flags: `-overflowdetect`, `-truncationdetect` (`src/cmd/compile/internal/base/flag.go`)
- SSA instrumentation: `src/cmd/compile/internal/ssagen/ssa.go`
- Runtime panics: `panicoverflow{,detailed}`, `panictruncate{,detailed}` (`src/runtime/panic.go`)
- Tests: `tests/arithmetic_test.go`, `tests/truncation_test.go`

## Feature 2: panic on selected functions (“panic-on-call”)

- `go test` flag: `-panic-on` (`src/cmd/go/internal/test/testflag.go`)
- Pattern validation (AST scan): `src/cmd/go/internal/test/panic_on.go`
- Compiler flag parsing: `-panic-on-call=...` (`src/cmd/compile/internal/base/flag.go`)
- SSA pass injecting panic calls: `src/cmd/compile/internal/ssa/panic_on_call.go`
- Runtime helper: `runtime.panicOnCall` (`src/runtime/panic_on_call.go`)
- Examples: `test/gosentry/examples/panic_on`, `test/gosentry/examples/panic_on_nodot`

## Feature 3: LibAFL fuzzing via `go test -fuzz` (default)

- `go test` flags and defaulting behavior: `src/cmd/go/internal/test/testflag.go`, `src/cmd/go/internal/test/test.go`
- Generated bridge (`_libaflmain.go`) exports:
  - `LLVMFuzzerInitialize`
  - `LLVMFuzzerTestOneInput`
  (generated in `src/cmd/go/internal/test/test.go`)
- Fuzz target capture + byte encoding:
  - Capture path: `src/testing/fuzz.go`
  - Marshal/unmarshal + entrypoint: `src/testing/libafl.go`
- Rust runner (LibAFL):
  - CLI + fuzz loop: `golibafl/src/main.rs`
  - Go wrappers: `golibafl/harness_wrappers/*`

## Feature 4: git-aware scheduling (`-focus-on-new-code`)

- `go test` flag: `-focus-on-new-code={true|false}` (required in LibAFL mode)
- Env wiring to runner: `src/cmd/go/internal/test/test.go`
- Runner implementation: `GitAwareStdWeightedScheduler` usage in `golibafl/src/main.rs`

## Feature 5: catch-races / catch-leaks / catch-hangs

- `go test` flags: `-catch-races`, `-catch-leaks` (required in LibAFL mode)
- Sidecar replays (watch `queue/`): `src/cmd/go/internal/test/test.go`
- Leak detection:
  - vendor: `src/vendor/go.uber.org/goleak/*`
  - in-process check: `src/testing/libafl.go`

## Feature 6: grammar-based fuzzing (Nautilus)

- `go test` flags: `-use-grammar`, `-grammar` (`src/cmd/go/internal/test/testflag.go`)
- Runner implementation:
  - Nautilus integration: `NautilusBytesGenerator` / `NautilusBytesMutator` in `golibafl/src/main.rs`
  - Protocol + caveats: `misc/gosentry/USE_LIBAFL.md`
- Example: `test/gosentry/examples/grammar_json`
