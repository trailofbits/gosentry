# gosentry dev loop (LLM-friendly)

The goal is fast, repeated feedback with repo-local knowledge (so agents can work with minimal external context).

## The “golden loop”

1. Make the smallest change that implements the intended behavior.
2. Add/adjust a test or a smoke case that fails without the change.
3. Run the tightest feedback loop that covers the change.
4. Update repo knowledge when behavior/flags change.
5. Repeat until green.

## Which checks to run

- Compiler/runtime instrumentation changes (`src/cmd/compile/*`, `src/runtime/*`):
  - `bash misc/gosentry/scripts/quickcheck.sh`
- `go test` / fuzz plumbing changes (`src/cmd/go/internal/test/*`, `src/testing/*`, `golibafl/*`):
  - `bash misc/gosentry/scripts/quickcheck.sh`
  - `bash misc/gosentry/tests/smoke_use_libafl.sh`
- Grammar fuzzing changes:
  - `bash misc/gosentry/tests/smoke_use_libafl_grammar_json.sh`
- Git-aware scheduling changes:
  - `bash misc/gosentry/tests/smoke_use_libafl_focus_on_new_code.sh`
  - Optional: `bash misc/gosentry/bench_focus_on_new_code_geth.sh`

## Documentation sync rules

- If you change LibAFL `go test` flags or semantics:
  - Update `misc/gosentry/USE_LIBAFL.md` (this is the canonical doc for `--use-libafl` mode).
- If you change user-visible behavior outside LibAFL (compiler flags, panics, messages):
  - Update `README.md`.
- If you change internal wiring or dev workflows:
  - Update `docs/gosentry/*` (start at `docs/gosentry/index.md`).
