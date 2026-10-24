# Benchmark reproducibility

This document records the shared data and test setup. The
[methodology](methodology.md) explains why we use them. All Wallet API
benchmarks reuse these datasets.
The lnd observation is complete; later methods reuse its model and saved data.

## Docker environment

The recorded measurements use Docker 29.6.2 and `linux/arm64` on the same host.
Docker fixes the client and server software and resource limits. Host load and
hardware still affect results. Run one benchmark at a time, without competing
Docker or build jobs.

| Component | Image and settings |
| --- | --- |
| Wallet client | `golang:1.25.11-bookworm`; 1 CPU, 4 GiB, no swap, GOMAXPROCS=1, CGO=0, `-buildvcs=false -trimpath -p=1`. |
| PostgreSQL | `postgres:18-alpine`, version 18.4; 1 CPU, 1 GiB, bridge TCP, Testcontainers `fsync=off`. |
| SQLite | Embedded in the client; WAL, foreign keys, 5s busy timeout. Both SQL pools use the normal 25-connection limit. |

The runner in `scripts/benchmark.sh` pins the client digest to
`sha256:b96f24a8d7d010ea0acb9c3ba99064740f02b6b984612b28bd3c9c5ab9453e38`.
The [SQL setup](../../../wallet/bench/setup_test.go) pins the server digest to
`sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15`.
The runner contains the complete Docker invocation. Source is read-only.
Database storage is inside the Docker VM. Build and module caches use
`/tmp/go-build-cache/benchmark` on the host.

## Run and repeat

Run from the repository root. Docker must be available to the client, including
its socket for PostgreSQL Testcontainers. No live Bitcoin node is required.
The SQL setup uses the existing chain mock. The saved history supplies the
query's confirmed tip.

Use the [shared commands](README.md) and the selected method record
for its measured source revision and run metadata. Develop with one selected
backend and the default smoke case.
Select full datasets explicitly after code review and run approval.

Select `legacy`, `kvdb`, `sqlite` or `postgres` to run one implementation.
Use `large-node` to select the largest saved dataset. The default `smoke` case
uses one call. Full cases default to a 3s target. Set `BENCH_PACKAGE` and
`BENCH_CASE` for one exact entrypoint. The shared guide gives native selection
commands. Method records retain
the actual serial sample orders. Do not run backends concurrently.

The named volume `btcwallet-bench-fixtures` stores data across commands and
code changes. It is mounted at `/fixtures`. On a cache miss, setup creates and
saves the selected dataset. On a hit, it skips creation and restores private
storage. Even the first invocation restores the saved snapshot before opening
the measured Wallet. Do not delete this volume between performance changes.
The source's fixture revision and SQL schema hash select compatible data.
Direct Go runs without `BTCWALLET_BENCH_FIXTURE_DIR` use temporary data instead.

Setup logs identify `fixture preparation` and `fixture restoration` separately.
A repeated run should report restoration without preparation. For the recorded
runs, the nine saved snapshots kept identical hashes, sizes and modification
times. A rerun still pays build, restore, startup, unlock and cleanup costs.
After unlock, call the selected API once with the measured request before
starting profiles or `b.Loop`. Timed calls reuse that Wallet and request.
Restore, startup, unlock, this first call and cleanup are outside API timing.
Whole-command time includes them.

The runner writes the selected binary and any profiles under
`<out>/<method>/<case>/<backend>/<timing|cpu|mem>/`.
Keep stdout/stderr for every invocation, including errors and excluded attempts.
Record the measured commit, exact command, sample order, date and wall time.
If other jobs overlap a sample, retain that attempt and repeat the sample after
they stop. Method records identify the samples used for their medians.

Use `profile=cpu` or `mem` for separate diagnostic runs. The runner
prints `go tool pprof` analysis after cleanup. CPU profiles use `cpu.pprof`.
Heap captures use `heap-before.pprof` and `heap-after.pprof`, with baseline
subtraction for both `alloc_space` and `inuse_space`. Profile capture starts
after setup and the untimed first call; it stops before Wallet cleanup. See the
[measurement rationale](methodology.md#timing-and-profiles) before interpreting
profiles or timing results.

## Data source: an lnd node

The completed lnd integration test observed the funding node's btcwallet data.
The peer's wallet, lnd's channel database and the chain inventory were separate.
The reference scenario had these steps:

1. Fund a new wallet with one confirmed 1 BTC UTXO.
2. Open 100 public anchor channels to one peer. Each channel has 500,000 sat
   capacity and sends 100,000 sat to the peer. Complete all opens before any
   close. Each funding transaction spends the previous transaction's change.
3. Close 98 channels cooperatively. Keep their returned wallet funds.
4. Send ten outgoing HTLCs of 10,000 sat through each remaining channel.
   The peer holds them. Both channels keep positive local and remote balances.
   Force-close both channels from the funding node.
5. Confirm commitments and advance CSV/CLTV maturity until both resolutions
   finish. Let lnd select sweep batches and fee inputs. Record pending anchor
   sweeps separately.

The reference used a fixed fee estimate of 2,500 sat/kw and the harness's
normal confirmation and CSV settings. Settled payments do not create a wallet
transaction or a new ordinary address for each payment. The scenario omits
these payments.

The experiment captured account, address, transaction, UTXO and pending-output
RPC responses after the deposit, channel opens and channel closes. It included
custom key accounts. It stopped the wallet and read a database copy through
the address manager. It counted persisted addresses and their used flags.
It counted imported pseudo-accounts separately from regular scoped accounts.

Channel keys use scope `1017` and separate key-family accounts. Key derivation
advances each index. Use inside a channel contract does not mark the key's
ordinary address as used. `ListUnspent` walks unspent outputs and finds their
owning addresses. It does not enumerate all unused channel keys. Separate
accounts and branches keep channel keys out of ordinary address discovery.
Broader load and rescan operations can still read these records.

### Observed reference

The reference passed on 2026-10-23. The lifecycle took 12m 19s; the whole test
took 12m 23s and mined 731 blocks. This native macOS arm64 experiment used
Go 1.27.3. It established data shape, not Docker API latency.

The local experiment commit is
`804ac54201c40adb1466617dba9676f6307bfc9d`, based on lnd
`1a359d4aa1e58daad2c3c5ade1ff3f415f91ac1b`. It used btcwallet
`16cfb4483d1f618bae04dbe9206584bf4ee2e72d` and btcd v0.26.0.
The experiment is not in upstream lnd. These commands identify the completed
reference run and require that checkout. Normal benchmark runs use the saved
model data below; they do not run this lnd experiment again.

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

The 260 accounts comprise four ordinary default accounts and 256 scope-1017
accounts. Five imported pseudo-accounts are separate. The final address
inventory has one BIP84 receiving address, 100 BIP86 change addresses and
102 BIP86 external addresses. Key families 0–4 each have 100 keys. Family 5
has 101 because lnd skips its first revocation-root index.

The 204 records comprise one deposit, 100 funding transactions, 100 closes
and three sweeps. The RPC gives positive confirmations for 202 records.
Its two force-close records still have zero confirmations after resolution.
The sweeper combines both local balances. It combines 20 HTLC timeout inputs
with one cooperative-close output for fees. It then sweeps the 20 second-stage
outputs together. One HTLC does not imply one independent wallet transaction.

The final 101 UTXOs are P2TR outputs: one funding-change output, 97 cooperative
returns and three sweep outputs. Their total value is 89,636,054 sat.
No channel resolution remains pending. Two uneconomical 330-sat anchor sweeps
remain pending. They are not part of the spendable output count.

## Shared node datasets

The [case builder](../../../wallet/internal/bwtest/bench_cases.go) models this
history with deterministic unsigned transactions and foreign contracts.
A shared fixed seed gives every backend the same account paths and scripts.
The builder keeps transaction links, credit ownership, values and script types.
It does not sign channels or import lnd's channel database.

Positive confirmation heights are dense. Each deposit's history has two
unconfirmed force-close bookkeeping records. All ordinary credits at the
endpoint are confirmed. Each deposit leaves one unused ordinary address.
All channel keys remain unused. These choices normalize the reference data;
they do not reproduce its full block schedule.

### small-node

This case models the observed one-deposit history.

| Parameter | Value |
| --- | --- |
| Initial deposits | 1 UTXO, 1 BTC |
| Channels | 100: 98 cooperative closes, 2 force closes |
| Pending HTLCs at force close | 20 |
| Regular scoped accounts | 260 |
| Ordinary addresses | 203 |
| Channel keys | 601 |
| Wallet transaction records | 204 |
| Final confirmed tip | 202 |
| Final spendable P2TR outputs | 101 |
| Final owned value | 89,636,054 sat |

### medium-node

This model repeats the normalized history for ten independent deposits in
one Wallet. Accounts stay fixed. Addresses, keys and transaction links are
distinct across deposits.

| Parameter | Value |
| --- | --- |
| Initial deposits | 10 UTXOs, 10 BTC |
| Channels | 1,000: 980 cooperative closes, 20 force closes |
| Pending HTLCs at force close | 200 |
| Regular scoped accounts | 260 |
| Ordinary addresses | 2,030 |
| Channel keys | 6,001 |
| Wallet transaction records | 2,040 |
| Final confirmed tip | 2,020 |
| Final spendable P2TR outputs | 1,010 |
| Final owned value | 896,360,540 sat |

### large-node

This model repeats the history for 100 deposits in one Wallet.

| Parameter | Value |
| --- | --- |
| Initial deposits | 100 UTXOs, 100 BTC |
| Channels | 10,000: 9,800 cooperative closes, 200 force closes |
| Pending HTLCs at force close | 2,000 |
| Regular scoped accounts | 260 |
| Ordinary addresses | 20,300 |
| Channel keys | 60,001 |
| Wallet transaction records | 20,400 |
| Final confirmed tip | 20,200 |
| Final spendable P2TR outputs | 10,100 |
| Final owned value | 8,963,605,400 sat |

Each additional deposit needs one BIP84 receiving address, 100 BIP86 change
addresses and 102 BIP86 closing/sweep addresses. Each key family gains 100 keys.
Family 5 skips index zero once per Wallet. Transaction hashes, outpoints,
foreign contracts and positive block metadata stay distinct. Received times
stay ordered across deposits.

The model repeats three resolution transactions per deposit. Real lnd can
combine sweeps across histories, select other fee inputs or consolidate funds.
Its final counts can differ. The lnd experiment observed only the one-deposit
origin.
The names describe model sizes, not measured user populations. Related data
grows together; these cases do not isolate the cost of live UTXO count.

The `smoke` development case uses one deposit and 20 channels. It has the same
260 accounts, with 43 ordinary addresses, 121 channel keys, 44 transaction
records and 21 final UTXOs. Use it for fast development checks.

## Prepare and save data

The shared [SQL setup](../../../wallet/bench/setup_test.go) owns common node preparation. It uses Manager to create and unlock the Wallet. It creates ordinary and internal
accounts through public APIs. It allocates ordinary addresses in bulk and
internal keys through the public key allocator. A separate Store writes the
complete transaction history through `ApplyTxBatch`.

The [kvdb setup](../../../wallet/benchmark_helpers_test.go) uses its
native Manager and scoped address manager. Its shared seeder derives addresses
in bulk and apply history through Store, with confirmed-tip progression.
Both suites must consume the same case definition. Legacy and maintained kvdb
share one saved database per size. SQL preparation does not call the kvdb suite.

Close all database users before saving data. Save kvdb and SQLite as closed
files. Save PostgreSQL with a custom-format `pg_dump` archive. Restore a private
copy before every invocation, even the first. This excludes seed-process caches
from the measured Wallet. Keep prepared data for all benchmark methods.
Analyze each private PostgreSQL restore before Wallet startup to give the
planner column statistics. This work is outside timing. Reuse the saved
archive without rebuilding its data.

The Docker volume uses `lnd-wallet/v1/kvdb/<case>.db` for kvdb.
SQL uses `lnd-wallet/v1/<schema-hash>/<backend>/<case>.db`, where the backend is
`sqlite` or `postgres`. The schema hash covers bootstrap and migration files.
Reuse this base when executable or query code changes. Rebuild only when
fixture inputs, seed behavior or storage compatibility change.

### Preparation measurements

These Docker observations date from 2026-10-23. The one-deposit source was
`963f383a18061961088480994cfbb6bef52d065d`. The ten- and hundred-deposit source
was `1883b5cb2caa8d5b904a6599bf1d3ec091ec8a6b`. These source IDs identify the
actual preparation runs.

Preparation includes Wallet creation, data writes, closure and snapshot save.
Restore measures only file copy or `pg_restore`. Whole-command time also
includes build, startup, one API call and cleanup. These one-call observations
are not API latency results. The saved files kept the same hash, size and
modification time after reuse. Saved runs did no seed work.

#### small-node preparation

| Storage | Prepare | Accounts | Addresses/keys | History | Restore | First command | Reused command |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| kvdb | 1.845s | 0.378s | 1.358s | 0.094s | 0.54–0.61ms | 11.47s | 3.06–3.21s |
| SQLite | 3.172s | 2.324s | 0.684s | 0.127s | 0.31ms | 7.21s | 3.40s |
| PostgreSQL | 3.661s | 2.367s | 0.732s | 0.343s | 147.69ms | 9.04s | 4.86s |

#### medium-node preparation

| Storage | Prepare | Accounts | Addresses/keys | History | Restore | First command | Reused command |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| kvdb | 15.870s | 0.390s | 14.104s | 1.356s | 3.41–3.53ms | 21.42s | 3.21–4.37s |
| SQLite | 14.607s | 2.361s | 7.842s | 4.364s | 1.81ms | 18.26s | 3.57s |
| PostgreSQL | 16.561s | 2.387s | 7.462s | 6.374s | 283.49ms | 21.77s | 5.03s |

#### large-node preparation

These observations cover data preparation only. They do not measure API
latency. Each method record gives its API measurements.

| Storage | Prepare | Accounts | Addresses/keys | History | Restore | First command | Reused command |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| kvdb | 2m37.7s | 0.396s | 136.475s | 20.756s | 23.21–23.38ms | 174.45s | 5.96–16.75s |
| SQLite | 9m13.5s | 2.377s | 85.762s | 465.255s | 14.80ms | 557.21s | 3.41s |
| PostgreSQL | 7m22.6s | 2.439s | 75.541s | 363.573s | 1.046s | 448.73s | 5.97s |

SQL's account phase includes Wallet creation and unlock. Kvdb includes those
costs in the total. The 16 larger preparation/reuse invocations took 21m 39s
of whole-command time. These costs belong to data preparation, which later
measurements avoid through saved reuse.
