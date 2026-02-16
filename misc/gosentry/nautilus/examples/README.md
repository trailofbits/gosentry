# Nautilus grammar examples

gosentry grammar fuzzing (`--use-grammar`) currently loads **JSON** grammars (Nautilus JSON format).

## JSON grammars (loadable by gosentry)

- `json/gosentry_json.json`: small JSON subset grammar (copied from `test/gosentry/examples/grammar_json/testdata/JSON.json`).
- `json/libafl_ruby_grammar.json`: larger example grammar (copied from LibAFL's `fuzzers/structure_aware/baby_fuzzer_nautilus/grammar.json`).

## Python grammars (reference only)

These come from upstream Nautilus/LibAFL and show the `ctx.rule(...)` style, but gosentry does **not** load `.py` grammars today.

- `python/nautilus_grammar_py_example.py`: upstream Nautilus "grammar_py_example.py".
- `python/libafl_forkserver_simple_grammar.py`: minimal LibAFL `forkserver_simple_nautilus` grammar.
