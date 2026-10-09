# ADR 0016: Mixed Imported XPub and Local Account Custody

## Status

- **Status:** Accepted
- **Date:** 2026-10-09

## Relationships

- **Amends:** [ADR 0012](./0012-wallet-level-watch-only-uniformity.md).
- **Supersedes:** None.
- **Amended by:** None.
- **Superseded by:** None.

## 1. Problem

One Wallet must track an external signer's imported account XPub alongside
accounts whose private keys derive from the wallet root. An imported account
must remain visible without gaining local signing authority, while existing
local accounts continue signing. ADR 0012's uniform SQL account policy rejects
this public-only import in a signing wallet.

## 2. Context

Wallet mode describes whether the root contains local signing material. It is
immutable after creation. Account provenance already distinguishes keys derived
from that root from imported account keys; no secret-table read is needed to
identify imported custody. SQL account children retain branch/index coordinates
but a numberless imported account has no wallet-root signing path.

The existing UTXO result includes an optional spendability override. Wallet
already consumes that override before applying coinbase maturity. The kvdb
backend already supports external accounts in a signing wallet through its
existing account and UTXO mechanisms.

### Constraints

- Watch-only wallets must continue rejecting private-key material.
- Imported XPub children remain owned and tracked across reopen.
- Local account signing and immutable wallet/root mode remain unchanged.
- Raw public-key/script import policy, supplied numbered accounts, per-account
  address schemas, PSBT metadata, and coin selection are outside this amendment.
- Optional low-level account secret storage does not establish a wallet-root
  path for a numberless imported account.

## 3. Decision

Permit public-only account imports in both signing and watch-only wallets.
Report effective account custody as watch-only when either the wallet is
watch-only or the account key was imported rather than derived from the root.
HD child addresses inherit that external custody. Raw imports retain their
existing wallet-mode and secret handling.

Expose imported account outputs through normal ownership and UTXO queries,
with spendability set to false. Locally derived account outputs retain the
existing wallet default and maturity rules. The existing signer refuses an
external child without a local derivation path; importing an XPub grants
tracking authority only.

`Wallet.IsWatchOnly` continues reporting immutable root mode. Callers use
`AccountInfo.IsWatchOnly` for account custody and `Utxo.Spendable` for output
signability. Public address metadata continues distinguishing an HD child from
a raw import; absent wallet-root derivation metadata does not become account
zero.

## 4. Rationale

Persisted account provenance answers the custody question without joining
secret tables, adding a second wallet, or introducing mutable capability state.
The existing spendability override carries the same answer to Wallet callers.
Keeping the signer path unchanged preserves local signing and its established
refusal when an external child has no wallet-root path.

## 5. Alternatives Considered

### Alternative: Require a second watch-only wallet

A second wallet splits account ownership and lifecycle despite the requirement
to track both custodians together. Existing provenance can express the boundary
within one wallet.

### Alternative: Infer custody from encrypted account secrets

Joining secret tables would couple public account/address/UTXO reads to secret
storage. Imported provenance already identifies the missing local root path;
an optional low-level secret fixture does not supply that path.

## 6. Consequences

### Positive

- Signing wallets can track external XPub accounts without importing secrets.
- Creation, allocation, ownership reads, and reopen report consistent custody.
- Local accounts retain their existing signing behavior.

### Negative and Risks

- A signing wallet's root-mode flag alone cannot describe every account.
  Callers must inspect effective account or output custody for their purpose.
- The externally controlled account requires its external signer. This
  amendment does not introduce PSBT funding or decoration semantics.

## 7. Implementation Overview

SQL import admission retains the watch-only/private-material guard and removes
the inverse private-key requirement. Existing account and address conversion
paths combine wallet mode with account provenance. Existing point/list UTXO
conversions mark imported HD children non-spendable. No schema, public API,
secret-table join, signer implementation, or lifecycle state is added.

Verification exercises public import and allocation, account/address ownership,
both UTXO queries, close/reopen, external signing refusal, and preserved local
signing on the supported store and chain backends.

## 8. References

- [ADR 0012: Original uniform wallet policy](./0012-wallet-level-watch-only-uniformity.md).
- [ADR 0013: Normalized identity](./0013-normalized-account-address-identity.md).
- Roadmap Task 479: `btcwallet-sql-roadmap/tasks/479-mix-imported-xpub-accounts.md`.
