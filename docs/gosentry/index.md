# gosentry dev docs (start here)

This folder is the repo-local “system of record” for gosentry’s internal design and workflows.
User-facing docs stay in `README.md`.

## Navigation

- Project overview + user docs: `README.md`
- LibAFL mode (flags, grammar fuzzing, git-aware, catch-*): `misc/gosentry/USE_LIBAFL.md`
- Architecture map (features ↔ code): `docs/gosentry/architecture.md`
- Dev loop (fast feedback): `docs/gosentry/dev-loop.md`
- Benchmarks (feedback via performance): `docs/gosentry/benchmarks.md`

## Repo map (most edited)

- Compiler + runtime changes:
  - Compiler flags: `src/cmd/compile/internal/base/flag.go`
  - SSA instrumentation (overflow/truncation): `src/cmd/compile/internal/ssagen/ssa.go`
  - Panic-on-call SSA pass: `src/cmd/compile/internal/ssa/panic_on_call.go`
  - Runtime panic helpers: `src/runtime/panic.go`, `src/runtime/panic_on_call.go`
- `go test` plumbing / flags:
  - Flags: `src/cmd/go/internal/test/testflag.go`
  - LibAFL wiring + sidecars: `src/cmd/go/internal/test/test.go`
  - Panic-on pattern validation: `src/cmd/go/internal/test/panic_on.go`
- `testing` fuzz glue:
  - Fuzz capture / encoding: `src/testing/fuzz.go`, `src/testing/libafl.go`
- Rust runner: `golibafl/` (entry: `golibafl/src/main.rs`)
- Examples + smoke tests:
  - Examples: `test/gosentry/examples/*`
  - Smoke scripts: `misc/gosentry/tests/*`
  - Unit tests for panikint/truncation/panic-on-call: `tests/`
- CI workflows: `.github/workflows/*`

## Quick commands

- Build toolchain: `cd src && ./make.bash`
- Build + run core unit tests: `bash misc/gosentry/scripts/quickcheck.sh`
- LibAFL smoke suite (needs Rust): `bash misc/gosentry/tests/smoke_use_libafl.sh`
- Quick LibAFL bench (reverse example): `bash misc/gosentry/scripts/bench_libafl_reverse.sh`
- Full git-aware benchmark (geth): `bash misc/gosentry/bench_focus_on_new_code_geth.sh`

## Knowledge rules (kept short on purpose)

- `AGENTS.md` is a map (pointers), not a full manual.
- If you change `go test` LibAFL flags (see `src/cmd/go/internal/test/testflag.go`), update `misc/gosentry/USE_LIBAFL.md`.
