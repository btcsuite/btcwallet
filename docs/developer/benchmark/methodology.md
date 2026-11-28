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
