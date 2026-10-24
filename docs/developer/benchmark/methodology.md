# Benchmark methodology

Use the same logical Wallet state and completed API operation across backends.
Prioritize lnd's wallet use case. Keep data construction separate from the API
being measured. The [reproducibility guide](reproducibility.md) records exact
counts, seed paths, saved storage, environment. The [shared guide](README.md) owns execution commands.

## Why these datasets

The completed lnd experiment gives the model a concrete source. One 1 BTC
deposit funded 100 channels through successive change outputs. The node closed
98 channels cooperatively and force-closed two with pending HTLCs. This history
includes spent funding outputs, returned funds and resolution transactions.
It represents wallet activity beyond a collection of independent payments.
Settled off-chain payments do not add one wallet transaction or ordinary
address per payment, so the model does not generate that traffic.

Keep the observed relationships between accounts, addresses, keys, history and
unspent outputs. Ordinary addresses are mostly used. Internal channel keys
remain in separate accounts and are not marked as ordinary used addresses.
The model keeps the observed scope and script types. This gives read APIs a
wallet history with channel activity, beyond only live output rows.

The shared cases are `small-node`, `medium-node` and `large-node`. They model
1, 10 and 100 initial funding UTXOs. Each deposit funds 100 channels. The
small case follows the observed endpoint. The larger cases repeat that
normalized history in one Wallet. Accounts stay fixed; addresses, channel
keys, transaction history and final outputs grow together. These names describe
model sizes, not measured user populations.

The completed lnd observation covers one deposit only. Larger models estimate
its scale. They repeat three sweep transactions per deposit. Real lnd can batch
sweeps across deposits, select other fee inputs or consolidate funds. Do not
interpret these cases as measurements of three real lnd populations.

All Wallet API benchmarks use these saved datasets as a common base. Each
invocation works on a private restored copy. A method records its request and
any changes to that copy. For a focused parameter study, vary the method's
target dimension and keep independent background data fixed. The node cases
vary related dimensions together; they do not isolate live UTXO count.

## How the suites connect

Keep the existing kvdb comparison suite in
[wallet/utxo_manager_benchmark_test.go](../../../wallet/utxo_manager_benchmark_test.go).
It compares legacy and maintained Wallet APIs. Preserve its original growth
matrix. Each method adds matched cases that consume the shared node definition.
Only these matched cases supply kvdb baselines for the SQL comparison.
Remove the kvdb suite when kvdb is retired.

Legacy and maintained kvdb must use the same saved database for each node size.
Each gets a private file copy. Legacy reopens it through Loader. Maintained
kvdb reopens it through Manager.
Both call their native read APIs and unlock before timing. Their native setup
paths differ because the APIs use different Wallet runtimes.

The independent SQL suite is in [wallet/bench](../../../wallet/bench).
It creates and restores SQLite and PostgreSQL through their normal Manager
and Store mechanisms. Method entrypoints call the selected public Wallet API.
The SQL suite does not run the kvdb suite or read stored baseline results.
This suite remains usable after kvdb retirement.

Both suites consume the same deterministic
[case builder](../../../wallet/internal/bwtest/bench_cases.go). Match account
selection, scripts, values, transaction links, confirmations, tip and request
filters. Backend IDs and seeding paths can differ. Compare completed native
calls with normal database I/O, including PostgreSQL's client/server work.
SQLite runs inside the Wallet process. PostgreSQL runs in a separate container.
The comparison measures these native configurations, including their storage
and transport costs.

Unit and integration tests own fixture and API correctness. Benchmark setup
and operations fail on errors. Do not add result or fixture-content validation
to the benchmarks.

For point reads, select a retained cooperative return before measurement.
Choose the smallest txid/index among outputs with the shared cooperative value.
This selects the same address, outpoint and one-input/two-output transaction
shape across implementations. Request preparation does not validate results.

Legacy GetUtxo uses an external chain-tip RPC and computes confirmed counts
as tip minus height. The maintained API reads its stored tip and includes the
confirming block. Mark this legacy baseline unavailable for the offline read
suite. Do not add a timed chain mock or change legacy semantics to compare it.

Legacy ListAddresses aggregates scopes and lifetime receipts. The maintained
request selects BIP86/default addresses and current unspent balances. Legacy
ListAccounts includes scoped imported aliases and assigns balances by account
number without matching scope. These operations differ on the shared history.
Mark those matched legacy baselines unavailable; preserve the original matrices.
Use maintained kvdb as the declared baseline for those three method reports.

## Timing and profiles

Seed once per backend, size and fixture revision. Close and save that state.
Restore private storage and start a fresh Wallet for every invocation, including
the first. This prevents the seed process's Wallet caches from carrying into
the query. The first `b.Loop` resets time and allocation counts after setup.
Loop exit stops timing before cleanup. Restoration, database readiness,
connections and unlock are outside measurement.

Call the selected API once after unlock, without timing or profiling. Use the
same request and active Wallet for later timed calls. This excludes first-use
cache work for every implementation. Otherwise, one slow first call can fill
a duration target while other implementations amortize it over many calls.
These measurements compare repeated reads, not first-call latency.

A duration such as `3s` is a target, not a fixed iteration count or a maximum
call duration. Inspect iteration counts and require multiple timed calls in
each accepted sample before interpreting repeated-call comparisons.

Use one pinned Docker environment on the same host and architecture. Run one
implementation at a time. Eight rotated/reversed orders place each of four
backend slots in each position twice. When a legacy leaf is unavailable, the
remaining three backends do not have exactly balanced three-position orders.
Retain and report the actual order. Retain all raw attempts. Repeat samples
that overlap competing
jobs. Report the median of eight accepted samples per implementation and
dataset. Compare time, bytes and allocation count against the declared baseline
median. Use matching legacy where available, otherwise maintained kvdb. For
lower values, divide baseline by measured value; for higher values, divide
measured by baseline. Use green for lower, red for higher and white for
equal or baseline. Use faster/slower for time and lower/higher for
allocation metrics, with two decimal places and no multiplier sign.
These descriptive ratios are not confidence intervals.

Report unprofiled `ns/op`, `B/op` and `allocs/op`. Go allocation metrics cover
the Wallet process; they exclude PostgreSQL server memory. Do not combine
profiled and unprofiled samples. Collect CPU and heap profiles separately,
after setup and the untimed call, before cleanup. Timer reset alone does not
control profile capture. Use the post-setup heap baseline to separate fixture
allocations from workload allocations. Distinguish retained heap from
cumulative allocations.
Profiles explain measured work; they do not replace unprofiled latency data.

Read benchmarks share restored data, untimed request preparation, one first
read and the common measurement loop. Only the API call varies. Chain sync
and startup measure lifecycle work and cannot use this repeated-read boundary.
