# GetAccount

Read the default BIP86 account with its normal balance retrieval.
Measured source for repeated-item results:
`be0334cc543a74a954fe29c8fce8829c03f572ef`.
[Methodology](methodology.md) and [reproducibility](reproducibility.md).

### Benchmark Results

Baseline: Legacy kvdb.

🟢 below baseline · 🔴 above baseline · ⚪ baseline/equal.

The different-item and not-found tables are pending a completed matched
collection.

#### Repeated existing item

##### small-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 409,889 | ⚪ 1.00 | 361,984 | ⚪ 1.00 | 7,410 | ⚪ 1.00 |
| Maintained kvdb | 403,669 | 🟢 1.02 | 365,132 | 🔴 1.01 | 7,509 | 🔴 1.01 |
| PostgreSQL | 450,511 | 🔴 1.10 | 5,305 | 🟢 68.24 | 106 | 🟢 69.90 |
| SQLite | 246,939 | 🟢 1.66 | 4,839 | 🟢 74.81 | 113 | 🟢 65.57 |

##### medium-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 5,560,184 | ⚪ 1.00 | 4,774,444 | ⚪ 1.00 | 135,033 | ⚪ 1.00 |
| Maintained kvdb | 5,359,687 | 🟢 1.04 | 4,808,066 | 🔴 1.01 | 136,075 | 🔴 1.01 |
| PostgreSQL | 1,658,729 | 🟢 3.35 | 5,360 | 🟢 890.84 | 108 | 🟢 1250.30 |
| SQLite | 1,223,899 | 🟢 4.54 | 4,892 | 🟢 975.97 | 115 | 🟢 1174.20 |

##### large-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 71,137,147 | ⚪ 1.00 | 46,605,174 | ⚪ 1.00 | 1,512,547 | ⚪ 1.00 |
| Maintained kvdb | 69,869,805 | 🟢 1.02 | 46,937,164 | 🔴 1.01 | 1,522,878 | 🔴 1.01 |
| PostgreSQL | 14,091,987 | 🟢 5.05 | 5,492 | 🟢 8486.78 | 108 | 🟢 14005.06 |
| SQLite | 13,133,147 | 🟢 5.42 | 5,010 | 🟢 9303.36 | 115 | 🟢 13152.58 |

#### Different existing items (pending)

Read different accounts once each. Use the ordinary default accounts first,
then the BIP1017 channel-key accounts. The scope and name identify an account;
family zero is named `default`, and later families use `act:1` to `act:255`.

#### Not found (pending)

Read a different absent account name in an existing scope on each call.

### Note

The legacy helper lists accounts, selects the requested account and maps its
total balance to `ConfirmedBalance`. The modern API separates confirmed and
unconfirmed balances and adds creation time and sync policy. This fixture's
current credits are confirmed, but legacy omits some modern metadata. For future
optimization, use maintained kvdb's modern snapshot as the reference. Inspect
balance aggregation and repeated metadata reads while preserving the returned
fields.
