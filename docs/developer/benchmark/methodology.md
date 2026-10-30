# Benchmark methodology

Wallet reads are the priority because writes occur less often. This suite
measures repeated read operations. Chain sync and startup need separate
lifecycle benchmarks.

## How the suites connect

The existing [wallet suite](../../../wallet/utxo_manager_benchmark_test.go)
compares legacy and maintained kvdb APIs. The independent
[SQL suite](../../../wallet/bench) measures SQLite and PostgreSQL. This
separation lets the kvdb suite be removed when kvdb is retired.

All four implementations use the same logical dataset and matched queries.
Compare completed native operations with the same or comparable responses.
Each API report describes its request, native semantics and material response
differences; shared data alone does not establish equal API work.

## Dataset rationale

The shared cases model an observed lnd channel-wallet lifecycle, including
funding, channel closes and resolution sweeps. Larger cases repeat that
normalized history. Related dimensions grow together, so these are model
sizes rather than measured user populations or isolated UTXO-count studies.
See the [data source](reproducibility.md#data-source-an-lnd-node) and
[dataset census](reproducibility.md#shared-node-datasets).

## Measurement boundary

Provisioning, restoration, startup, unlock, request preparation, one first
read and cleanup are outside measurement. Excluding the first read prevents
first-use cache work from consuming a duration target. Timed calls complete
the native API operation, including normal database I/O.

Each invocation issues one read at a time. `ns/op` is end-to-end call latency:
it includes PostgreSQL server execution under its fixed quota and transport
between the client and server. The current setup uses a local Docker bridge;
additional network latency from an off-host database is not simulated.

`B/op`, `allocs/op` and CPU/heap profiles cover only the Wallet's Go process.
PostgreSQL server resources are provisioned separately. This compares Wallet
client resources with a fixed server environment; it does not compare equal
total deployment costs. See the
[environment](reproducibility.md#docker-environment) for the client and server
limits.

## Serial comparisons

Run implementations serially so they do not compete for CPU, memory and
storage. Rotate their positions to reduce order bias from host load and cache
state. Balanced positions do not prove equal native API work or remove all
measurement bias.

See [reproducibility](reproducibility.md) for execution and profiling, and the
[record template](template.md) for aggregation and ratio instructions.

## Chain synchronization

Startup-to-synced measures a fresh native lifecycle discovering a prepared
chain. It uses the [startup dataset](reproducibility.md#startup-chain-dataset),
which preserves the lnd Wallet shape and address distribution while defining
block placement separately from the read snapshots. Shared Wallet inventory
alone does not define a chain workload. Hold the chain, starting metadata,
background traffic, source and completion condition fixed across implementations.

Prepare and mine the target before measurement. Save a closed unfunded native
Wallet at the common chain base. Restore private storage and construct a fresh
Manager, chain source and connections for every sample. Database startup,
physical open, restore, NewManager, mining, random generation and shutdown are
untimed. There is no read warmup. Time Manager.Start, including durable Wallet
loading, through public Info observing native readiness and the exact configured
target hash/height. Legacy times OpenWithRetry, StartDeprecated and SynchronizeRPC
through its equivalent persisted-tip/ChainSynced condition plus live-tip RPC.
The live RPC matches Info's observation work and lets network polling progress
on one processor. Unsuccessful observations yield; they add no completion sleep.

Legacy uses native rescan. Maintained kvdb, SQLite and PostgreSQL expose
separate forced full-block and compact-filter entrypoints. Both modes restore
the same native baseline and chain target. Forced compact filters return an
error when unavailable; Auto selection and its watchlist threshold are not
part of this comparison. Compact-filter positives may include false positives
and do not redefine the dataset's actual Wallet-hit block ratios.
Both kvdb runtimes restore the same closed baseline and persist freelists.
The SQL suite owns its usual native lifecycle independently. These paths need
not have artificial structural symmetry. Report only this explicit workload
and mode comparison; do not infer a general ranking of storage backends.

The three nonzero full cases hold the same 204 Wallet graph transactions fixed
and distribute them into 1, 10 or 100 matching blocks within 1,000 blocks. Thus
average graph transactions per matching block changes as 204, 20.4 and 2.04. This
studies placement/clustering with fixed Wallet work, not increasing Wallet
transaction volume. The populated 0% baseline intentionally has no Wallet work.
Treat that boundary explicitly when examining trends; three nonzero points do
not establish general linear scaling. Background payments remain identical.

Coinbase-only empty blocks are a separate control from populated blocks with
no Wallet matches. Both start with the same unfunded metadata, including its
existing addresses and keys. Keep empty-block results outside the populated
hit-ratio relationship. Foreign-only graph transactions are not Wallet hits.

Calibrate block payload by weight and serialized bytes rather than transaction
count alone. The deterministic background payment template models scan load,
while the Wallet graph preserves lnd transaction shapes. Mainnet traffic mixes
and Lightning contract timing/witnesses remain disclosed simplifications.
Inspect real pilot blocks before scaling; never silently substitute lighter
blocks, synthetic Store ingestion, mocks or the legacy stress dataset.

The maintained scanner keeps the 1,000-block logical window. Its Core adapter
bounds each getblock RPC batch to 100 blocks, consuming a response before
queuing the next. The earlier single-batch sender built about 2.8 GB of reply
hex at this payload and replayed that work after an HTTP timeout; see the
[diagnostic evidence](reproducibility.md#rpc-batch-replay-and-repair).
Keep the original fixed startup settings in the
[environment table](reproducibility.md#docker-environment) across modes and
record the repaired source explicitly with any subsequent matched cohort.
The small pilot establishes validity/reuse, not full-window memory feasibility.

Use 1x for each restored lifecycle. CPU and heap captures are separate 1x runs;
finish capture before Wallet/source teardown. Keep usual database and matched
chain I/O measured. Fixture correctness belongs in tests and separate
inspection. After both timer and profile capture stop, each lifecycle logs its
public unspent-output count, outpoints and satoshi values. External receipt
validation compares that census across implementations and modes, without
adding expected result assertions, waits or queries to the measured operation.
Whole-command duration includes setup; a timeout or OOM supplies no startup
timing or usable profile. Keep failed/excluded attempts with their actual
source revision and never relabel old dense or biased runs.
