# Benchmark reproducibility

Use the [methodology](methodology.md) for comparison scope and the
[record template](template.md) for results. Run evidence owns actual commands,
source revisions, dates, orders and exceptions.

## Shared node datasets

These are the populated Wallet sizes for every shared case. The
[case builder](../../../wallet/internal/bwtest/bench_cases.go) fixes the seed,
accounts, address/key paths and normalized transaction history across backends.

| Parameter | smoke | small-node | medium-node | large-node |
| --- | ---: | ---: | ---: | ---: |
| Initial 1 BTC deposits | 1 | 1 | 10 | 100 |
| Channels | 20 | 100 | 1,000 | 10,000 |
| Cooperative closes | 18 | 98 | 980 | 9,800 |
| Force closes | 2 | 2 | 20 | 200 |
| Pending HTLCs at force close | 20 | 20 | 200 | 2,000 |
| Derived scoped accounts | 260 | 260 | 260 | 260 |
| Ordinary payment/change addresses | 43 | 203 | 2,030 | 20,300 |
| Channel keys | 121 | 601 | 6,001 | 60,001 |
| Total address/key records | 164 | 804 | 8,031 | 80,301 |
| Wallet transaction records | 44 | 204 | 2,040 | 20,400 |
| Final confirmed tip | 42 | 202 | 2,020 | 20,200 |
| Final spendable P2TR outputs (UTXOs) | 21 | 101 | 1,010 | 10,100 |
| Final owned value (sat) | 97,913,654 | 89,636,054 | 896,360,540 | 8,963,605,400 |

The 260 derived accounts comprise four ordinary default accounts (one per
BIP44/49/84/86 scope) and 256 scope 1017 key-family accounts. Reserved imported
pseudo-accounts exposed by legacy APIs are excluded. Ordinary addresses include
receiving, change and closing/sweep branches; they exclude channel keys.
`NumAddresses` is that ordinary-address count. Total address/key records include
both categories; an API's filters determine which records it returns.

`AddressBatches` gives native seeders nine allocation groups: three ordinary
address branches and six channel key families. Families 0–4 allocate one key
per channel; family 5 includes one extra unused index-zero allocation per Wallet
to match [lnd's revocation producer][lnd-revocation]. This models the reference
node's key usage and does not change btcwallet's production allocator.

New fixtures are checked after seeding and before saving: account count,
committed branch allocation counters, ordinary-address total, transaction total
and current UTXO count. Transaction checks include confirmed and unconfirmed
records. These checks are outside measurement and do not repeat for cached
restores; they do not enumerate every address or calculate its balance.

Larger cases repeat the observed one-deposit history with fixed accounts and
distinct scripts, outpoints, contracts and ordered timestamps. Transactions are
unsigned; foreign contracts preserve types and ownership without channel replay.
Each confirmed record has one distinct synthetic block height, so height-range
reads see one Wallet transaction per block and the tip equals the confirmed
record count. Each deposit retains two unconfirmed force closes and one unused
ordinary address. This ordering does not reproduce real block packing, maturity
or mining cadence. Real lnd may combine sweeps or choose other fee inputs; these
model sizes do not predict user populations.

## Docker environment

The reference setup uses an Apple M1 Max host (`arm64`) with Docker 29.6.2
and `linux/arm64` benchmark containers. This identifies the reference setup,
not every historical collection. Keep each collection's actual CPU model,
benchmark GOOS/GOARCH, Docker version and source revisions in its run evidence.
Hardware details stay here and in that evidence; API reports link here.

Compare backends on the same host and architecture within a collection. Other
measured platforms can use separate collection records and matched baselines.
Keep their samples separate. Both absolute values and ratios can change across
CPUs and architectures; a speedup factor applies to its measured environment.

| Component | Image and settings |
| --- | --- |
| Wallet client | `golang:1.25.11-bookworm`; 1 CPU, 4 GiB, no swap, GOMAXPROCS=1, CGO=0, `-buildvcs=false -trimpath -p=1`. |
| PostgreSQL | `postgres:18-alpine`, version 18.4; 1 CPU, 1 GiB, same-host bridge TCP, `fsync=on`. |
| SQLite | Embedded in the client; WAL, native `synchronous=FULL`, foreign keys, 5s busy timeout. Both SQL pools use the normal 25-connection limit. |

PostgreSQL has an additional server quota outside the Wallet client limits:
client 1 CPU plus server 1 CPU, while embedded backends share the client's
1 CPU. These are CPU-time limits, not dedicated cores. Server work still enters
`ns/op`; see the [measurement boundary](methodology.md#measurement-boundary).
The containers communicate on the same Docker host/VM. This measures local
bridge transport; it does not simulate off-host PostgreSQL network latency.

Earlier collections used Testcontainers' `fsync=off` default. The fixture now
keeps native durable synchronization enabled. Preserve each historical run's
settings and measured source identity. These read results do not measure durable
write throughput.

The [runner](../../../scripts/benchmark.sh) pins the client digest to
`sha256:b96f24a8d7d010ea0acb9c3ba99064740f02b6b984612b28bd3c9c5ab9453e38`.
The [PostgreSQL setup](../../../wallet/bench/setup_postgres_test.go) pins the
server digest to
`sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15`.
Source is read-only. Database storage is inside the Docker VM; build/module
caches use `/tmp/go-build-cache/benchmark` on the host.

## Run and repeat

Run from the repository root with Docker available, including its socket for
PostgreSQL Testcontainers. These read fixtures need no live Bitcoin node.
The shared regression-genesis mock supplies startup responses.

### Select a benchmark

Explicit `BENCH_PACKAGE` and `BENCH_CASE` inputs select an exact package and
pattern together. This example compiles without running a workload:

```sh
# An explicit empty benchmark pattern builds the package without a workload.
BENCH_PACKAGE=./wallet BENCH_CASE='^$' \
  make bench method=compile-only db=kvdb case=smoke
```

Installed consumers can use `list-unspent`, `get-utxo`, `list-addresses`,
`get-address-info`, `get-tx`, `list-txns`, `get-account` or `list-accounts`.
Select `db=legacy|kvdb|sqlite|postgres`. Explicit inputs take precedence and
select one leaf; collection shortcuts require an installed method selector.

Use one affected backend and the default `smoke` case during development.
Complete review and obtain run approval before full preparation or measurement.

```sh
# Replace the method label to check another installed read consumer.
method=list-unspent
make bench method="$method" db=sqlite case=smoke duration=1x
```

SQL uses SQLite by default; `db=postgres` selects `test_db_postgres`.
Both builds use one `Benchmark<API>` entrypoint and
`RunSQLBenchmark(b, prepare)`. Shared node data comes from
`bwtest.NodeBenchmarkWorkload`, `NodeBenchmarkAddressBatch` and
`NodeBenchmarkCases`; method consumers own native requests and read callbacks.

### Collect timing results

Select full cases explicitly and preserve raw output with the run evidence.

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

Each invocation restores private storage, starts and unlocks a fresh Wallet,
prepares the request and calls it once before measurement. The first `b.Loop`
resets time/allocation counts; loop exit stops timing before cleanup. Whole
command time includes build/setup/shutdown and is not API latency. See the
[measurement boundary](methodology.md#measurement-boundary) for interpretation.

## Serial schedule and collection record

Use `db=all` to collect repeated timings across all four backends. The method
must have matching kvdb and SQL benchmark consumers installed; this framework
provides their shared setup and measurement helpers.

```sh
# Collect eight serial passes for one case with the installed API benchmarks.
make bench method=list-unspent db=all case=small-node duration=3s
```

Leave `profile`, `BENCH_PACKAGE` and `BENCH_CASE` unset for this collection.
The runner applies the following schedule automatically; the letters are
notation, not command inputs. L=legacy kvdb, K=maintained kvdb, P=PostgreSQL
and S=SQLite:

`LKPS KPSL PSLK SLKP PKLS KLSP LSPK SPKL`

Each group is one serial pass: `LKPS` runs legacy kvdb, maintained kvdb,
PostgreSQL and SQLite in that order. Eight passes produce eight samples per
backend, or 32 benchmark invocations per case. Each backend occupies every
position twice. Save raw output as shown in the
[timing command](#collect-timing-results); aggregation follows the
[template](template.md).

Each benchmark excludes setup and makes an untimed first read. Go's `b.Loop`
controls timing and iterations within that invocation. These controls cannot
remove differences in host conditions between backend runs. Serial execution
avoids resource competition; rotating positions spreads possible early/late
effects from host load and cache state. This collection policy reduces possible
order bias. It does not guarantee unbiased results or equal native API work.
Single-backend runs do not use this schedule.

The configured schedule does not establish which order retained samples used.
Keep actual orders, accepted/excluded attempts and group membership in evidence;
do not combine separate collections into a claimed contemporary balanced run.
Pause competing builds/measurements during collection and retain affected
attempts.

Smoke defaults to `1x`; full reads default to a `3s` target. A duration is not
a hard timeout or a guarantee of multiple calls. Inspect actual N and keep
fixed-count policies and single-call diagnostics identifiable in evidence and
API Notes. Follow the [template](template.md) when aggregating accepted groups.

## Persisted fixture reuse

The volume `btcwallet-bench-fixtures`, mounted at `/fixtures`, saves datasets
across methods and executable revisions. Missing data is prepared once; every
invocation restores private storage, including the first. Keep this volume
between performance changes.

Kvdb uses `lnd-wallet/v2/kvdb/<case>.db`. Version 2 keeps default account 0
and creates key-family accounts 1–255 explicitly. Version 1 could overwrite
account 0 and omit family 255; its saved files and historical measurements keep
their original identity and do not carry the new count guarantee. SQL uses
`lnd-wallet/v1/<schema-hash>/<backend>/<case>.db`, with backend `sqlite` or
`postgres`. The compatibility hash covers SQL bootstrap/migration files, not
queries or executable identity. Rebuild only for fixture inputs, seed behavior
or storage compatibility changes. Direct Go runs without
`BTCWALLET_BENCH_FIXTURE_DIR` use temporary data.

Setup logs distinguish preparation and restoration. Reused runs should restore
without preparing; retain saved-file hashes, sizes and modification times in
evidence to check that reuse left them unchanged.

## Artifacts and profiles

Profiles use separate invocations after setup and the untimed first call,
before cleanup. They explain measured work and never supply unprofiled result
tables. Select one backend/case or use `db=all profile=all` for installed leaves.

CPU and heap captures run separately so CPU-profiler work and allocations do
not enter the heap delta. Each diagnostic can also use its own duration.

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
Retain stdout/stderr for completed, failed and excluded attempts in evidence.

| Invocation | Files |
| --- | --- |
| All executed benchmarks | `benchmark.test` |
| CPU | `cpu.pprof` |
| Heap | `heap-before.pprof`, `heap-after.pprof` |

Subtract the post-setup/first-read baseline `heap-before.pprof` from
`heap-after.pprof` with `go tool pprof -base`. Inspect `alloc_space` for new
allocation traffic and `inuse_space` for retained-heap change. Each snapshot
uses one explicit GC and the same sampling policy. The runner prints analysis
after cleanup. Go memory metrics cover the Wallet client, including normal
client work; they exclude PostgreSQL server memory.

## Data source: an lnd node

The reference observed the funding node's btcwallet, separately from the peer,
lnd channel database and chain inventory:

1. Confirm a 1 BTC deposit and open 100 public anchor channels to one peer.
   Each has 500,000 sat capacity and sends 100,000 sat to the peer; successive
   change funds the next channel.
2. Close 98 channels cooperatively. In each remaining channel, hold ten
   outgoing 10,000-sat HTLCs, then force-close with positive balances on both
   sides. Advance CSV/CLTV maturity through balance and HTLC resolution.
3. Capture account/address/transaction/UTXO RPCs at each stage, then inspect
   the stopped wallet's address records. Record pending anchor sweeps separately.

The fee estimate was 2,500 sat/kw. Settled off-chain payments do not add a
Wallet transaction or ordinary address per payment. Internal channel keys use
scope 1017 and separate families; contract use does not mark them as ordinary
used addresses.

### Observed reference

The experiment used native macOS arm64 and Go 1.27.3 to establish data shape,
not Docker API latency. Its local experiment commit is
`804ac54201c40adb1466617dba9676f6307bfc9d`, based on lnd
`1a359d4aa1e58daad2c3c5ade1ff3f415f91ac1b`, btcwallet
`16cfb4483d1f618bae04dbe9206584bf4ee2e72d` and btcd v0.26.0.
It is not in upstream lnd; these commands require that experiment checkout.
Normal benchmarks reuse saved model data instead.

```sh
# Build the experiment harness and keep its raw RPC data and stopped snapshots.
export GOTOOLCHAIN=go1.27.3
export LND_WALLET_REFERENCE_DIR=/absolute/path/to/reference-output
make build-itest backend=btcd GOCC=/opt/homebrew/opt/go/bin/go
# Select only the one-deposit channel scenario in the prepared harness.
make itest-only backend=btcd dbbackend=bbolt \
  icase=wallet_channel_reference timeout=30m GOCC=/opt/homebrew/opt/go/bin/go
```

| Funding wallet data | Funded | 100 channels open | Closes resolved |
| --- | ---: | ---: | ---: |
| Regular scoped accounts | 260 | 260 | 260 |
| Accounts with address/key records | 1 | 8 | 8 |
| Ordinary addresses | 1 | 101 | 203 |
| Ordinary addresses marked used | 1 | 101 | 202 |
| Channel keys, all unmarked as used | 0 | 601 | 601 |
| Wallet transaction records | 1 | 101 | 204 |
| Confirmed spendable UTXOs | 1 | 1 | 101 |

Four ordinary default accounts and 256 scope 1017 accounts make the 260 regular
accounts; five imported pseudo-accounts are separate. The final addresses are
one BIP84 receiving, 100 BIP86 change and 102 BIP86 external addresses. Key
families 0–4 have 100 keys each; family 5 has 101 because lnd skips index zero.

The 204 transactions are one deposit, 100 openings, 100 closes and three sweeps.
Two force-close records stay unconfirmed after resolution. Sweeps combine
both local balances and 20 HTLC timeout inputs, using one cooperative output
for fees, then combine the 20 second-stage outputs. The 101 final UTXOs are one
funding change, 97 cooperative returns and three sweeps, totaling 89,636,054 sat.
Two uneconomical 330-sat anchors remain pending, outside the spendable count.

## Prepare and save data

[SQL setup](../../../wallet/bench/setup_test.go) uses public Manager APIs to
create/unlock the Wallet and allocate accounts/addresses/internal keys. Its
Store applies normalized history through `ApplyTxBatch`.
[Kvdb setup](../../../wallet/benchmark_helpers_test.go) uses its native Manager
and scoped bulk allocator, then Store writes with confirmed-tip progression.
Both use the shared case definition; SQL preparation does not call the kvdb
suite. Legacy and maintained kvdb share the same saved database per size.

Close all database users before saving. Kvdb/SQLite save closed files;
PostgreSQL saves a custom `pg_dump` archive. Analyze each private PG restore
before Wallet startup so timed reads have planner statistics. Preparation and
restoration remain outside timing.

[lnd-revocation]: https://github.com/lightningnetwork/lnd/blob/1a359d4aa1e58daad2c3c5ade1ff3f415f91ac1b/lnwallet/revocation_producer.go#L23-L33
