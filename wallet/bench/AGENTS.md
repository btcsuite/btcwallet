# Wallet benchmarks

This package measures SQL Wallet reads independently of the existing kvdb
comparison suite in `wallet`, so kvdb retirement can remove that suite.

Follow the [methodology](../../docs/developer/benchmark/methodology.md),
[execution guide](../../docs/developer/benchmark/reproducibility.md) and
[report template](../../docs/developer/benchmark/template.md).

- Share node data and measurement through `wallet/internal/bwtest`. Keep common
  seeding/cache policy in `setup_test.go`; native fixture helpers use
  `test_db_postgres` or `!test_db_postgres`. Method files own untimed requests
  and native reads through one entrypoint shared by both SQL builds.
- Fail on setup/operation errors. Validate newly seeded fixture counts through
  the shared Store checks before saving, outside measurement. Existing
  Wallet/Store tests own native correctness; avoid redundant helper unit tests
  and keep result assertions out of timed reads.
- Use `smoke` and relevant package checks during development. Full preparation
  and timing/profile collection require completed review and explicit run
  approval. Reuse saved fixtures through private copies/restores.
