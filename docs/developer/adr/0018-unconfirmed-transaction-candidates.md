# ADR 0018: Recording Competing Transactions

## Status

- **Status:** Accepted
- **Date:** 2026-11-12

## Relationships

- **Amends:** [ADR 0006](0006-wtxmgr-sql-schema.md).
- **Supersedes:** None.
- **Amended by:** None.
- **Superseded by:** None.

## 1. Problem

The wallet must retain competing transactions that spend the same input.
Suppose it creates A spending F:0, records A and attempts to broadcast it.
The user then creates replacement B spending F:0. Before B's broadcast attempt
returns, the wallet observes C spending F:0. All three transactions belong in
history; neither recording B nor its late broadcast result can decide which
transaction spends F:0 in the current chain.

If a block confirms B, B becomes the confirmed spender and A/C become invalid
under that chain. A reorg can remove that confirmation and change eligibility
again. The wallet needs to represent this full lifecycle without overwriting
competing history or treating a broadcast result as confirmation.

## 2. Context

The SQL table `transactions` retains raw transaction bytes, lifecycle status
and current block association. The SQL table `utxos` retains wallet-owned
credits, including spent credits used for history and address ownership.

A single spender pointer on a credit cannot represent several unconfirmed
claimants. Credits also do not cover every input: the parent can be external,
or its wallet ownership can be discovered after the spending transaction.
The wallet therefore needs input relationships independently of owned credits.

### Constraints

- Complete the DB write before the broadcast attempt. A failed DB write stops
  that attempt; an uncertain broadcast outcome must not erase recorded history.
- Recording an unconfirmed competitor does not select a winner or release
  another transaction's input claims.
- Balance, output discovery and coin selection must agree about reservations
  while retaining their existing confirmation, maturity and lease policies.

## 3. Decision

Retain each transaction and index its inputs in SQL table `tx_inputs`.
Determine spend availability from those inputs, transaction status and current
block association. Keep the existing `transactions.tx_status`; no additional
stored publication, rejection or conflict status is introduced.

### Schema changes

Add SQL table `tx_inputs` with these required fields:

| Field | SQLite / PostgreSQL | Key and purpose |
|---|---|---|
| `wallet_id` | `INTEGER` / `BIGINT` | Wallet scope; part of the primary key. |
| `tx_id` | `INTEGER` / `BIGINT` | Spending transaction; part of the primary key. |
| `input_index` | `INTEGER` / `BIGINT` | Non-negative input position; part of the primary key. |
| `prev_tx_hash` | `BLOB` / `BYTEA` | 32-byte hash of the transaction creating the spent output. |
| `prev_output_index` | `INTEGER` / `BIGINT` | Position of that output, from 0 through 4294967295. |

The primary key is `(wallet_id, tx_id, input_index)`. The composite foreign key
`(wallet_id, tx_id)` references `transactions(wallet_id, id)` with cascading
deletion. `wallet_id` also references `wallets(id)` with restricted deletion.
A non-unique index on `(wallet_id, prev_tx_hash, prev_output_index)` finds all
claimants of an outpoint. There is no parent-UTXO foreign key.

Remove these fields from SQL table `utxos`:

| Field | Replacement |
|---|---|
| `spent_by_tx_id` | Look up spending transactions through the input index. |
| `spent_input_index` | Read the spending input's `tx_inputs.input_index`. |

Input rows reflect the retained raw transaction and do not change on
confirmation or rollback. Deleting a transaction removes its input rows.

### Using the input relation

Find a credit's claimants by its wallet and creating outpoint. Apply existing
transaction status and block association when interpreting those input rows.
A Pending or Published unconfirmed claimant reserves the output while no
confirmed competitor or invalid ancestor blocks it. A confirmed claimant
establishes the spend. Removing one claimant does not release another's claim.

Unconfirmed competition does not mark a transaction Replaced. When a competitor
confirms, direct conflicts become Replaced and invalidated descendants become
Failed. Rollback must re-evaluate affected claims against the remaining chain,
including descendants of orphaned coinbases. Exact status restoration remains
open below; this ADR does not redefine the existing publication lifecycle.

The A/B/C example shows why the relation retains all claimants. Two other cases
explain its coverage:

- **Incompatible change:** A and B spend F:0 and each creates wallet change.
  Both change outputs can be listed with conflict metadata, but cannot be
  counted as independent safe funds or selected together.
- **Late parent:** B spends P:0 and confirms before the wallet discovers P:0
  as its credit. Indexed input lookup immediately finds confirmed B and
  excludes P:0; scanning only unconfirmed transactions would miss that spend.

## 4. Rationale

The input relation represents every recorded claimant, including spends of
external or late-discovered parents. It supports wallet-scoped indexed lookup
without decoding unrelated history for each outpoint. Retaining raw bytes
keeps the original transaction available for validation and broadcast.

Keeping `tx_status` reuses the existing lifecycle and rebroadcast distinction.
Deriving spenders and unresolved conflict metadata avoids synchronizing another
pointer or flag across every recording, deletion and rollback operation.
The tradeoff is more read work for eligibility and ancestry evaluation.

Bitcoin Core's [spender index][core-spends] and [transaction state][core-state]
also distinguish known input relationships from current eligibility. Its exact
full-node mempool policy is not imposed on Neutrino.

## 5. Alternatives Considered

### Alternative: A single spender pointer

A pointer makes some reads cheap, but an unconfirmed pointer cannot retain all
claimants. A confirmed-only pointer still needs another mechanism for live
reservations and external parents, and must be maintained during rollback.

### Alternative: Spender lists on each credit

Historical lists need transaction-state filtering; live-only lists need updates
when eligibility changes. Either can provide cheap credit reads, but neither
covers inputs whose parent has no wallet credit row.

### Alternative: Decode raw history for every lookup

This avoids an input index, but point lookups and late-parent discovery can
scan unrelated transactions. Batching helps listings without eliminating that
cost. No benchmark establishes a universal performance winner.

## 6. Consequences

### Positive

- Competing transactions remain visible without selecting an unconfirmed winner.
- One input relation covers owned, external and late-discovered parent outputs.
- Output discovery can expose contingent change without inflating safe funds.

### Negative and Risks

- Input rows add storage, index and write costs. Eligibility reads must examine
  relevant ancestors and competitors; their full workload is not benchmarked.
- Point reads, listings and balances need consistent graph facts and status
  transitions. Large fanout and unbounded history listings remain costly.
- **Open restoration detail:** conflict/rollback handling must still restore
  Pending versus Published and Failed descendants according to their cause.
  Replaced/Failed alone do not preserve the earlier rebroadcast decision;
  the precise restoration rule remains unresolved.

## 7. Implementation Overview

SQL recording, chain updates and deletion apply related facts atomically under
the existing backend transaction boundaries. Input lookup supports queries
for each operation; listings and balances can batch graph facts. Native
KVDB retains its multiple-spender indexing and backend-specific read mechanisms.

This is the target architecture, not a completed implementation. Integrating
input lookup with existing conflict and rollback handling must preserve the
claim interpretation above. The open restoration detail is not resolved here.

## 8. References

- [ADR 0006: Wallet Transaction Manager SQL Schema](0006-wtxmgr-sql-schema.md).
- [ADR 0011](0011-no-addresses-used-column.md).
- Bitcoin Core v32.1: [spender lookup][core-spends] and [state][core-state].

[core-spends]: https://github.com/bitcoin/bitcoin/blob/v32.1/src/wallet/wallet.cpp#L789-L853
[core-state]: https://github.com/bitcoin/bitcoin/blob/v32.1/src/wallet/transaction.h#L260-L304
