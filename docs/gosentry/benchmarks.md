# gosentry benchmarks (feedback loop)

Benchmarks are a second feedback loop next to correctness tests: they help catch regressions and validate that new ideas actually add value.

## Quick benchmark (local)

Runs a short LibAFL fuzz campaign on the `reverse` example and prints a small on-disk corpus summary.

```bash
bash misc/gosentry/scripts/bench_libafl_reverse.sh
```

## Git-aware benchmark (bigger, reproducible)

Benchmarks `--focus-on-new-code=true` on a shallow clone of go-ethereum (geth), measuring time-to-first-crash.

```bash
bash misc/gosentry/bench_focus_on_new_code_geth.sh --trials 3 --warmup 5 --timeout 60
```
