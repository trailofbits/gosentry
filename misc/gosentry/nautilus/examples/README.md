# Nautilus grammar examples

gosentry grammar fuzzing (`--use-grammar`) currently loads **JSON** grammars (Nautilus JSON format).

## JSON grammars (loadable by gosentry)

- [`json/gosentry_json.json`](json/gosentry_json.json): small JSON subset grammar (copied from `test/gosentry/examples/grammar_json/testdata/JSON.json`).
- [`json/libafl_ruby_grammar.json`](json/libafl_ruby_grammar.json): larger example grammar (copied from LibAFL's `fuzzers/structure_aware/baby_fuzzer_nautilus/grammar.json`).
- [`json/libafl_quickjs_grammar.json`](json/libafl_quickjs_grammar.json): JavaScript grammar (copied from `andreafioraldi/libafl_quickjs_fuzzing`).
- [`json/libafl_workshop_grammar.json`](json/libafl_workshop_grammar.json): small example grammar (copied from `atredis-jordan/libafl-workshop-blog`, root renamed from `START` to `Document` for gosentry compatibility).
- [`json/nautilus_ruby_new_antlr_grammar.json`](json/nautilus_ruby_new_antlr_grammar.json): Ruby grammar (copied from `RUB-SysSec/nautilus`).
- [`json/sqlite_syntax_grammar.json`](json/sqlite_syntax_grammar.json): SQLite-like syntax grammar (copied from `theber/fuzzing_grammar`).
