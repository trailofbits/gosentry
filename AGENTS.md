- **Start here (user docs):** `README.md`
- **Start here (dev docs / repo map):** `docs/gosentry/index.md`
- **LibAFL mode docs (canonical):** `misc/gosentry/USE_LIBAFL.md`

## Key code areas (gosentry-specific)

- Compiler flags: `src/cmd/compile/internal/base/flag.go`
- Overflow/truncation instrumentation: `src/cmd/compile/internal/ssagen/ssa.go`
- Panic-on-call instrumentation: `src/cmd/compile/internal/ssa/panic_on_call.go`, `src/runtime/panic_on_call.go`
- `go test` glue + flags: `src/cmd/go/internal/test/testflag.go`, `src/cmd/go/internal/test/test.go`
- Fuzz capture/encoding for LibAFL: `src/testing/fuzz.go`, `src/testing/libafl.go`
- LibAFL runner (Rust): `golibafl/src/main.rs`

## Feedback loops

- Build: `cd src && ./make.bash`
- Unit tests: `bash misc/gosentry/scripts/quickcheck.sh`
- LibAFL smoke: `bash misc/gosentry/tests/smoke_use_libafl.sh`
- Benchmark: `bash misc/gosentry/bench_focus_on_new_code_geth.sh`

## Rules

- Keep this file as a **map**, not an encyclopedia.
- If you change any feature of gosentry, update `misc/gosentry/USE_LIBAFL.md`.
