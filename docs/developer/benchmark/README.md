# Benchmarks

This directory describes Wallet read benchmarks, their shared datasets and
how to collect and report results. Use `make bench` from the repository root;
see the [execution commands](./reproducibility.md#run-and-repeat).

---

## 📐 Methodology

Read scope, suite boundaries and comparison principles.

**[➡️ Read the Methodology](./methodology.md)**

---

## 🔁 Reproducibility

Commands, environment, saved datasets and diagnostic artifacts.

**[➡️ Run and Repeat Benchmarks](./reproducibility.md)**

---

## 📊 Record Template

A short API report with measured sources, results and comparison notes.

**[➡️ Use the Record Template](./template.md)**

## Startup-to-synced

Startup uses the same scalar runner with explicit native package/patterns.
Its case IDs describe [chain placement](reproducibility.md#startup-chain-dataset),
independently of read sizes. Use the [startup timing
contract](methodology.md#chain-synchronization) and the shared environment table.
The [completed comparison](start_to_synced.md) links to the full collection's
source, samples, exclusions and profile evidence.
Only the selected smoke/reuse milestone is authorized during implementation;
full preparation, all cases and profiles need explicit run approval.

```sh
# Run one fresh SQLite lifecycle; repeating this command reuses saved fixtures.
BENCH_PACKAGE=./wallet/bench \
BENCH_CASE='^BenchmarkStartToSynced$/^smoke$' \
  make bench method=start-to-synced db=sqlite case=smoke duration=1x \
  out=/tmp/btcwallet-bench/startup-pilot
```

Native kvdb selection uses package `./wallet` with
`^BenchmarkStartToSynced$/^smoke$/^Legacy$` or
`^BenchmarkStartToSynced$/^smoke$/^KVDB$`. PostgreSQL uses `./wallet/bench`
with `^BenchmarkStartToSynced$/^smoke$`; the scalar db selects its
`test_db_postgres` build. Set the matching scalar db.
For approved full runs, replace the anchored smoke case and scalar case ID
with `empty`, `hits-0`, `hits-1`, `small-node` or `hits-100`. Startup has no collection shortcut;
run explicit cases serially in the shared balanced order. Use separate output
roots to preserve each independent 1x observation and its exact command/log.

```sh
# Only after profile approval, capture one prepared startup independently.
BENCH_PACKAGE=./wallet/bench \
BENCH_CASE='^BenchmarkStartToSynced$/^small-node$' \
  make bench method=start-to-synced db=sqlite case=small-node \
  profile=cpu duration=1x out=/tmp/btcwallet-bench/startup-profiles
```

Use profile=mem in another invocation for the heap capture. Do not combine
profiling with timing samples or interpret the pilot as a full result table.

### Forced compact-filter comparison

`BenchmarkStartToSynced` retains the full-block selectors above.
`BenchmarkStartToSyncedCFilters` uses the same fixtures and forces compact
filters. Select `./wallet` with
`^BenchmarkStartToSyncedCFilters$/^smoke$/^KVDB$`, or `./wallet/bench` with
`^BenchmarkStartToSyncedCFilters$/^smoke$` and the matching SQL backend.
Legacy rescan remains a single baseline under the original entrypoint.

```sh
# Give this forced-filter lifecycle its own output root while reusing the chain.
BENCH_PACKAGE=./wallet/bench \
BENCH_CASE='^BenchmarkStartToSyncedCFilters$/^smoke$' \
  make bench method=start-to-synced db=sqlite case=smoke duration=1x \
  out=/tmp/btcwallet-bench/startup-cfilters
```

Use separate output roots for each mode, sample and backend. Both modes keep
`method=start-to-synced`, the same closed fixture keys and the same resources.
The [matched-mode protocol](reproducibility.md#matched-sync-mode-protocol)
defines collection and completed-Wallet verification.
