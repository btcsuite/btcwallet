# Benchmarks

Use shared node datasets for Wallet read benchmarks. Prepare each dataset
once per backend and fixture revision. Reuse saved data across methods and
performance changes. Chain sync and startup need separate lifecycle benchmarks.

- [Methodology](methodology.md): dataset rationale, backend comparisons and
  measurement boundaries.
- [Reproducibility](reproducibility.md): observed data, exact model counts,
  preparation, persistence and Docker settings.
- [Record template](template.md): the format for each method's results.

The existing `wallet` suite compares legacy and maintained kvdb calls.
Use `wallet/bench` for independent SQLite and PostgreSQL public API benchmarks.
Matched cases use the same logical data and native runtimes. Original kvdb
comparison cases keep their own fixtures. Remove that suite when kvdb retires.

## Select a benchmark

Run commands from the repository root with Docker available. The generic
framework accepts an exact Go package and benchmark pattern. It works without
API consumers. This compile-only example checks the command without data work:

```sh
# An explicit empty benchmark pattern builds the package without a workload.
BENCH_PACKAGE=./wallet BENCH_CASE='^$' \
  make bench method=compile-only db=kvdb case=smoke
```

API consumers add these friendly method selectors:
`list-unspent`, `get-utxo`, `list-addresses`, `get-address-info`, `get-tx`,
`list-txns`, `get-account` and `list-accounts`. Use these selectors only when
the corresponding benchmark consumer is present. Explicit `BENCH_PACKAGE`
and `BENCH_CASE` inputs take precedence and must be supplied together.
They select one scalar leaf; collection shortcuts require friendly selectors.

Select `legacy`, `kvdb`, `sqlite` or `postgres` for one implementation.
Legacy GetUtxo needs a chain-tip RPC and uses different confirmation counts.
Legacy ListAddresses and ListAccounts return different scope/balance data.
These friendly selectors report unavailable without starting Docker, including
profile requests. The original kvdb comparison matrices remain available.

During development, use one affected backend and the default `smoke` case.
It measures one API call. Use unit tests for correctness. Do not report smoke
metrics as full results. Complete code review and get run approval before
full preparation or measurement.

```sh
# Replace the method label to check another installed read consumer.
method=list-unspent
make bench method="$method" db=sqlite case=smoke duration=1x
```

## Collect timing results

The shared full cases are `small-node`, `medium-node` and `large-node`.
Full cases default to a 3s target. A duration target does not guarantee multiple
calls. Inspect N in every accepted sample. If one implementation needs a fixed
iteration count, rerun the whole method/size group with that same count.

```sh
# Preserve stdout/stderr and keep each run under its recorded label.
method=list-unspent
run_label=read-baseline
mkdir -p /tmp/btcwallet-bench/"$run_label"
make bench method="$method" db=all \
  case="small-node medium-node large-node" duration=3s \
  out=/tmp/btcwallet-bench/"$run_label" \
  2>&1 | tee /tmp/btcwallet-bench/"$run_label"/timing.log
```

`db=all` runs eight serial rotated/reversed orders. Each of four backend slots
appears in each position twice. Unavailable legacy leaves are skipped; the
remaining three backends are not exactly balanced across three positions.
Record their actual orders. Run no competing Docker or build jobs.
Retain excluded attempts and repeat samples affected by foreign jobs.

Use the median of eight accepted samples for each implementation and dataset.
Report `ns/op`, `B/op` and `allocs/op`. Each method report gives its measured
commit, request, run label, sample count, iteration policy and actual results.
The report names the ratio baseline and any unavailable implementation.
Store exact commands, UTC times, orders and raw outputs with the run evidence.

## Collect profiles

Profiles are separate diagnostics. They do not supply timing result tables.
Use one backend/case, or `db=all` and `profile=all` for one CPU and heap capture
per available backend/case. CPU capture uses a 15s target; heap uses 3s below.

```sh
# Reuse the saved data, then capture only the prepared API workload.
method=list-unspent
run_label=read-profiles
for backend in legacy kvdb postgres sqlite; do
  make bench method="$method" db="$backend" case=small-node \
    profile=cpu duration=15s out=/tmp/btcwallet-bench/"$run_label"
  make bench method="$method" db="$backend" case=small-node \
    profile=mem duration=3s out=/tmp/btcwallet-bench/"$run_label"
done
```

Artifacts use `<out>/<method>/<case>/<backend>/<timing|cpu|mem>/`.
Each invocation writes `benchmark.test`. CPU capture writes `cpu.pprof`.
Heap capture writes `heap-before.pprof` and `heap-after.pprof`. The runner
prints pprof analysis after cleanup. Heap analysis subtracts the post-setup
baseline for both allocation traffic and retained heap.

Docker volume `btcwallet-bench-fixtures` stores prepared data. Repeated runs
restore private storage without repeating preparation. Build, restore and
startup still take time outside API measurement. See
[reproducibility](reproducibility.md#run-and-repeat) for exact storage and
[methodology](methodology.md#timing-and-profiles) for interpretation.
