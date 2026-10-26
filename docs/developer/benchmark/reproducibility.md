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
| Wallet client | `golang:1.25.11-bookworm`; 1 CPU, 4 GiB for reads or 16 GiB for start-to-synced, no swap, GOMAXPROCS=1, CGO=0, `-buildvcs=false -trimpath -p=1`. |
| Bitcoin Core (startup only) | `lightninglabs/bitcoin-core:30`, version 30.2, digest `sha256:844f2a308e243ce3aa3df7918bd2fe230259419280f7826a62b896510ad3dcbd`, 1 CPU, 12 GiB, no swap, regtest, `-disablewallet -txindex -blockfilterindex=1 -mocktime=2100000000`, RPC/ZMQ. |
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

## Startup chain dataset

Startup uses the same small-node Wallet model with a separate chain placement.
Every case starts with one unfunded Wallet: 260 regular accounts, 203 ordinary
addresses and 601 channel keys, the seed/birthday above and zero recovery
lookahead. Keys already exist; a new or unfunded Wallet is not an empty
metadata database. Ordinary receiving uses BIP84; change and closing addresses
use BIP86. Internal channel-key families remain separate and unused as payment
addresses. Backend-specific native allocation is reused without ApplyTxBatch.

The nonzero cases use the same 204-transaction graph: one deposit, 100 openings,
98 cooperative closes, two force closes and three sweeps. Shapes are 1-to-2
openings/cooperative closes, 1-to-14 commitments, a 2-to-1 balance sweep,
21-to-21 timeout/fee transaction and 20-to-1 final sweep. Owned scripts, amounts,
ancestry and the expected 101 spendable outputs follow the shared model.
The two foreign-only force parents need not appear as discovered Wallet
records. See the [interpretation](methodology.md#chain-synchronization).

| Startup case | Catch-up blocks | Background tx/block | Blocks with Wallet matches | Wallet graph tx |
| --- | ---: | ---: | --- | ---: |
| smoke | 10 | 6,000 | 5 | 204 |
| empty | 1,000 | 0 | none | 0 |
| hits-0 | 1,000 | 6,000 | none | 0 |
| hits-1 | 1,000 | 6,000 | 500 | 204 |
| small-node | 1,000 | 6,000 | 100,200,...,1,000 | 204 |
| hits-100 | 1,000 | 6,000 | 10,20,...,1,000 | 204 |

The three full nonzero ratios are 0.1%, 1% and 10% of blocks containing actual
Wallet matches. They are not Wallet fractions of all transactions or counts
of positive compact filters. Graph index i, starting at zero, is assigned to
occupied block floor(i*H/204), interpreted as an index into the explicit H
occupied heights. Keep parent-before-child order within a block. Foreign-only
parents do not by themselves count as Wallet matches. Empty schedules still
prepare all requested blocks; nil history is not a target-cache hit.

Each unrelated transaction spends one miner P2WPKH input to a distinct tagged
foreign P2WSH recipient and P2WPKH miner change. It pays 1,000 sat with a
1,000 sat fee. Six thousand lanes roll change forward independently; only the
prior background block is retained during preparation. Estimated background
payload is about 3.6..3.7 million weight units and 1.4 MB per block. Actual
mined block data belongs in run evidence, separately from these estimates.

Calibration uses mainnet blocks 973169..973183, obtained from the
[fixed-height metadata endpoint](https://mempool.space/api/v1/blocks/973183).
Their 2,237..7,783 transactions occupy about 3.993..3.998 million weight units;
median serialized size is 1,584,601 bytes. Raw examples at heights 973183,
973182 and 973171 were inspected against their header hashes, byte counts and
weights. This is a small reference window, not a universal traffic estimate.
The controlled single-template background approximates payload and scan load;
it does not reproduce mainnet input/output, witness, script or OP_RETURN mixes.

The observed lnd lifecycle occupied 731 blocks: deposit 439, openings 440+6*i,
cooperative closes 1040..1137, both force parents 1138, balance sweep 1142,
timeout/fee 1165 and final sweep 1169. The controlled placements compress that
schedule, including same-block ancestry. Tagged foreign witnesses replace
Lightning CSV/CLTV contracts while preserving P2WSH type and distinctness.
Their script/witness sizes differ from real Lightning contracts. This is a
chain-valid shape model, not an lnd protocol replay or mainnet archive replay.
Disclose these differences and inspect the pilot before scaling.

### Prepare and reuse the startup fixture

Mine 103 maturity blocks with the fixed preparation miner. Coinbase one funds
the Wallet deposit. Mature coinbases two through four fund one 6,000-output
P2WPKH fan-out at height 104. Their 150 BTC permits each lane to pay 2,000 sat
per block throughout 1,000 blocks. Save the stopped common base 104, including
this fan-out, even for the empty control. Its exact hash is retained in logs.
Every native Wallet baseline synchronizes to this exact base before shutdown.

After Wallet shutdown, mine the case's explicit ordered transactions through
real Core generateblock. Core validates and submits each block. There is no
mempool-throughput measurement or synthetic database ingestion. Full targets
end at 1104; smoke ends at 114. Save the closed target before publishing each
closed native Wallet baseline. Independent targets have their own hashes.
The smoke contains 60,000 background and 204 Wallet graph transactions; each
populated full target contains 6,000,000 background transactions and, when
nonzero, 204 Wallet graph transactions. Coinbase and base funding are separate.

The current volume namespace is `start-to-synced/v3/bitcoin-30.2`; the
historical v2 namespace and its measured fixtures remain unchanged. Common base is
`chain/base`; targets are `chain/<case>/target`. Kvdb baselines use
`kvdb/<case>.db`; SQL uses `<schema-hash>/<backend>/<case>.db`. The case ID is
separate from fixed Wallet model ID. Reuse across executable changes; read
fixtures and old startup-v1 evidence remain separate. Restores are private
closed files/directories, or the existing PostgreSQL dump/restore mechanism.
A missing target is published even for zero-history cases.

Untimed native and SQL preparation allow 20 minutes; measured samples retain
30 minutes and the outer startup command retains one hour. The first full
hits-0 attempt at `ff8ac2997bb64e0b41e82a0216d66651ee0099fb` exhausted the
former ten-minute preparation context. It supplied no sync metric or recorded
OOM event; its 619.103s whole-command duration is a failed preparation outcome.

Use the resource table above for every implementation in this cohort. The
Docker VM allocation was increased to 32 GB before collection. Old startup
observations used smaller container limits and a different dense chain;
retain their provenance and exclusions rather than pooling them with v2.
Two selected SQLite smoke invocations establish real-chain validity and
persistent reuse. Inspect the closed target block file separately to record
actual weights, bytes, counts and placement; add no benchmark validation reads.
They do not establish the capacity of a 1,000-block batch. After separate full
run approval, begin with one hits-0 target and one maintained SQLite 1x sample,
recording preparation time and exact deadline/OOM outcome. Continue an approved
matrix only after that succeeds. A resource or deadline failure requires a
replan before changing payload, limits, modes or existing preparation timeout.

### Startup pilot observations

The two selected SQLite smoke invocations on 2026-10-26 measured source
`f993b2ea8c94bcb7d78a069a5e3466e76b6bbd54`. They used identical binaries,
SHA256 `6c4f82c8403d22f2461d274e9cb17d7169e85c6bfa9cc0e1f1f1fd0737b79ac9`.
These are development observations, not the full comparison result.

| Invocation | ns/op | B/op | allocs/op | Whole command |
| --- | ---: | ---: | ---: | ---: |
| Initial preparation | 1,095,287,584 | 374,081,184 | 1,910,174 | 20.047s |
| Persistent reuse | 1,089,946,168 | 378,279,024 | 1,907,960 | 6.781s |

All 64 saved fixture files kept identical checksums after reuse, which logged
restoration without allocation/mining. Both invocations completed at height 114,
hash `3b86f077c7d8476b5a42aaf0ab299f9cdad04918ae7e888b51e1c7b473c16ea6`.
The common base 104 hash is
`2d95ea58f90bb55d546d4e6c56a7c57884b275799aeaebf969798993e7d452f5`.

Standalone inspection of the closed target block file found exactly 60,000
background transactions and 204 graph transactions. Offset 5 (height 109) has
6,205 transactions including coinbase, of which 202 have modeled Wallet credits.
Other catch-up blocks each have 6,001 transactions including coinbase.
Their sizes are 1,407,205..1,407,278 bytes and weights 3,657,850..3,657,923 WU.
The matching block is 1,451,049 bytes and 3,795,684 WU, including the graph.
These observations confirm the selected payload fits individual valid blocks;
they do not establish 1,000-block batch capacity. Raw command receipts, immutable
fixture checksums and block-inspection.json are retained under the task-local
`.lgtm/task-sync-bench/runs/chain-v2/` evidence directory. No full cases or
profiles were collected for this cohort.
