**Summary**
- 

**Checklist**
- [ ] Ran `bash misc/gosentry/scripts/quickcheck.sh`
- [ ] If fuzz plumbing changed: ran `bash misc/gosentry/tests/smoke_use_libafl.sh` (or a narrower smoke script)
- [ ] If LibAFL `go test` flags changed: updated `misc/gosentry/USE_LIBAFL.md`
- [ ] If user-visible behavior changed: updated `README.md`
- [ ] If internal wiring/workflows changed: updated `docs/gosentry/*` (start at `docs/gosentry/index.md`)
