# Nautilus grammar examples

gosentry grammar fuzzing (`--use-grammar`) currently loads **JSON** grammars (Nautilus JSON format).

## JSON grammars (loadable by gosentry)

- [`json/gosentry_json.json`](json/gosentry_json.json): small JSON subset grammar (copied from `test/gosentry/examples/grammar_json/testdata/JSON.json`).
- [`json/libafl_ruby_grammar.json`](json/libafl_ruby_grammar.json): larger example grammar (copied from LibAFL's `fuzzers/structure_aware/baby_fuzzer_nautilus/grammar.json`).
- [`json/libafl_quickjs_grammar.json`](json/libafl_quickjs_grammar.json): JavaScript grammar (copied from `andreafioraldi/libafl_quickjs_fuzzing`).
