# Wallet benchmarks

This package measures SQL Wallet APIs through imported public `wallet` APIs.
Keep legacy and maintained kvdb comparisons in the existing `wallet` suite;
SQL execution must remain independent when kvdb is retired.

Follow the [benchmark methodology](../../docs/developer/benchmark/README.md)
and use the [record template](../../docs/developer/benchmark/template.md).

- Share deterministic node cases and read measurement through
  `wallet/internal/bwtest`. Keep common native lifecycle and seeding in
  `setup_test.go`. Method files own untimed requests and native API calls.
- Vary the target dimension while holding independent background dimensions
  fixed. Document derived relationships and match logical data, request
  filters and completion boundaries across implementations.
- Seed once, then repeatedly call the API. Exclude provisioning, startup,
  seeding and cleanup from timing and allocation counts. `b.Loop` resets
  both on its first call and stops timing when it returns false.
- Leave fixture and result correctness to unit/integration tests. Fail on
  setup or operation errors; add no validation reads or result assertions.
- Run one selected case at a time in the common pinned Docker environment.
  Use the parameterized `make bench` command and keep settings in its script.
- Develop with the tiny `smoke` case and relevant package checks. Complete
  code review and obtain explicit run approval before full fixture preparation
  or timing/profile collection. Never report smoke metrics as full results.
- Persist fixtures for every backend across code revisions. Open only private
  copies or restored databases; SQL setup remains independent of kvdb. Keep
  shared node seeding and SQL lifecycle in setup, independent of kvdb.
- Report unprofiled ns/op, B/op and allocs/op. Capture CPU and heap profiles
  separately after setup and before cleanup; use heap baseline/delta analysis.
- Keep one short record per method, with measured SHA, request, data, results and run
  metadata. Keep execution commands in the shared benchmark README. Describe the common environment once in the
  [reproducibility guide](../../docs/developer/benchmark/reproducibility.md).
  Add no reporting framework, custom CPU/RSS metrics or future API scaffolding.
