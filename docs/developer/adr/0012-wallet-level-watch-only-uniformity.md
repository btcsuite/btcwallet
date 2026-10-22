# ADR 0012: Wallet Root Mode and Account Custody

## 1. Context

Revision note: [PR #1411][mixed-account-pr] replaces the original wallet-wide
custody uniformity rule of this ADR with immutable wallet/root mode and
per-account custody. This change allows imported XPub accounts alongside local
signing accounts. [PR #1412][raw-import-pr] extends this policy to accountless
raw public-key and tapscript imports in signing wallets.

A wallet can track the imported account XPub of an external signer alongside
accounts whose private keys derive from the wallet root. The XPub import grants
tracking authority, and the external signer keeps custody. Local accounts must
continue to sign. Both kinds of accounts must keep their ownership and custody
across close/reopen.

The legacy `waddrmgr` already permits an imported XPub account inside a
signing wallet. The SQL store records the immutable wallet mode in
`wallets.is_watch_only`. The SQL store uses existing provenance to distinguish
root-derived accounts from imported accounts. Those fields can express the
same custody boundary without a join of `account_secrets` in public account,
address, or UTXO reads.

SQL UTXO results already carry an optional spendability override. Wallet uses
that override before it applies coinbase maturity. A wallet-level flag alone is
not sufficient for the outputs of an external account inside a signing wallet.

Bitcoin Core descriptor wallets use `disable_private_keys`, which gives context
for immutable root mode. But the descriptor-import admission policy of Bitcoin
Core does not express the mixed account requirement of btcwallet.

## 2. Decision

`Wallet.IsWatchOnly()` reports the immutable wallet/root mode. The wallet sets
this mode at creation and records it in `wallets.is_watch_only`. A signing
wallet may also track public-only imported XPub accounts. On both SQL
backends, watch-only wallets continue to reject private-key material at the
store boundary.

Effective account custody is watch-only when either of these conditions is
true:

- The wallet is watch-only.
- The account key was imported and was not derived from the wallet root.

HD child addresses inherit that account custody. Public reads use the existing
wallet mode and account provenance. Public reads do not infer custody from the
presence of secrets.

Imported account outputs remain visible through normal ownership and UTXO
queries, with `Spendable` set to false. Local account outputs keep the
existing wallet default and maturity rules. Callers use
`AccountInfo.IsWatchOnly` for account custody and `Utxo.Spendable` for output
signability. The root mode of a signing wallet does not imply that every
account can sign locally.

Balance reporting keeps its existing shape. The legacy JSON-RPC contract
(`getbalance`, `listaccounts`, `includeWatchOnly`) keeps its historical
fields. This decision adds no signing API, no secret-table join, no persisted
custody flag, and no new balance category. Raw imports keep the policy below.

### Supplied account XPub custody

Public account imports supply no matching private account material. SQL
accepts these imported XPubs in signing wallets and in watch-only wallets.
SQL reports their external custody at creation, at child allocation, in
ownership reads, and at reopen. The existing signer refuses an external child
that has no local wallet-root path. The XPub import does not make the child
locally signable.

Optional low-level account secret storage remains supported. But this storage
does not establish a wallet-root path for a numberless imported account. The
import of a private wallet root is different: accounts derived from that root
remain wallet-root-derived and may be spendable.

The immutable `NoChainSync` value of an account is independent of custody.
Signing wallets and watch-only wallets may each contain accounts with either
value. The exclusion of an account from automatic chain synchronization does
not add or remove signing capability.

ADR 0013 owns account identity, supported creation shapes, and chain-sync
policy. This custody decision does not expand backend capabilities for
supplied numbered accounts. This custody decision also does not change
per-account address schemas, PSBT metadata, or coin selection.

### Raw imported addresses use per-address custody

SQL raw imports follow [ADR 0013](0013-normalized-account-address-identity.md):
they are wallet-local `addresses` rows without an account, a scope, or a
`derived_addresses` row. The name `imported`
(`db.DefaultImportedAccountName`) is a compatibility alias, not a stored SQL
account row. A raw address import does not create an account bucket.

The alias remains reserved: `CreateDerivedAccount` and
`CreateImportedAccount` reject `DefaultImportedAccountName` with
`ErrReservedAccountName`. Raw imported addresses cannot be retargeted into an
HD account. kvdb keeps its legacy per-scope imported-address pseudo-account.
That bucket does not represent an imported XPub account.

Raw-import admission applies per address, independently of XPub account
custody:

- Signing wallets accept raw public-key and tapscript imports. These imports
  do not require matching private-key material and do not change the wallet
  root mode.
- Watch-only wallets continue to reject private-key-bearing imports with
  `ErrWatchOnlyViolation`.
- A raw address is watch-only when its wallet is watch-only, or when its own
  private-key ciphertext is absent or empty. Script ciphertext alone does not
  supply signing authority. This check does not decrypt or validate
  ciphertext. This check does not prove that a retained script can be
  satisfied.
- Address reads reuse their existing address-secret join and Boolean result
  for effective custody. UTXO queries expose raw private-key absence
  separately from the imported-HD custody rule of the existing Go shape
  helper. Keyless raw outputs receive the existing false `Spendable` override.
  Private raw outputs and local HD outputs keep their existing defaults and
  maturity checks.

Raw imports reuse committed registration before public success. Repeated
imports resolve canonical stored metadata and retry registration in either
root mode. Matching wallet/output scripts keep their first tapscript. Later
reveals are not merged or substituted, and key-only records are not upgraded.
Uncertain commits return no success and are not automatically retried. Wallet
lifetime cancellation and Stop retain ownership of registration.

Startup reconstructs watches from persisted addresses. Reopen preserves these
behaviors:

- public address, balance, UTXO, and transaction reporting
- stored script access
- local signing refusal for missing keys
- future receipt

This policy adds no historical scan, account selector, or PSBT behavior.

Derived addresses are not affected. They still inherit their key material
from the account xpub/xpriv. Callers reach them through `AccountKeyFromParams`
(the caller-supplied account name), not through the raw-import alias.

### P2A / anchor outputs are transaction state, not imports

Pay-to-anchor (P2A) outputs are keyless by construction (`OP_1
<0x4e73>`): there is no private key to import and none to require. Bitcoin
Core can encode P2A as an address/destination. But a P2A is not useful as
long-lived wallet address material. The relevance of a P2A comes from the
transaction flow that created it. Typically, a P2A is a temporary anchor that
a child transaction uses to fee-bump its parent.

This ADR therefore treats P2A as transaction/output state, not as a standard
managed or imported address. A spendable wallet that needs to observe an
anchor tracks the concrete output through the relevant-output /
watched-outpoint path. The wallet does not import an address row for the
anchor. No imported-address or address-secret row is created for the anchor,
so raw admission and custody rules do not apply to this path.

The child transaction that spends and fee-bumps the parent signs with the
wallet's own key material on its other inputs/outputs. The keyless anchor
input contributes no signature, so the spend flow keeps the immutable wallet
root-mode model.

## 3. Consequences

- Signing wallets can track external account XPubs, and local accounts keep
  their existing signing behavior. Reopen preserves the custody distinction.
- `db.AccountInfo.IsWatchOnly` and `db.AddressInfo.IsWatchOnly` describe
  effective account/HD-child custody. Raw address custody also reflects the
  absence of its own private key. These values do not need to equal
  `Wallet.IsWatchOnly()` in a signing wallet that tracks external material.
- `db.UtxoInfo` needs no new watch-only field. Its existing optional
  `Spendable` override marks imported HD children and keyless raw outputs as
  non-spendable. Local children and private raw imports keep their existing
  conversion and wallet-default behavior.
- Account/address/UTXO reads do not consult `account_secrets` to infer
  custody. Existing account provenance identifies external accounts. This
  identification needs no mutable capability state and no second wallet.
- `CreateImportedAccount` permits public-only imports in signing wallets and
  keeps the watch-only/private-material guard. Optional encrypted account
  secrets may still be persisted. The presence of these secrets does not
  change imported provenance into local root custody.
- Raw-import per-address secret checks remain separate from XPub account
  admission. The inverse raw private-key requirement is removed. Watch-only
  roots still refuse private material, and raw imports stay accountless.
- Local accounts use wallet-root signing material. HD addresses do not require
  per-address private keys in `address_secrets`. The absence of an address
  secret alone does not imply external custody.
- `account_secrets` and `key_scope_secrets` remain available to their existing
  consumers. This decision changes neither their storage nor the signer path.
- The kvdb backend reuses its account/output custody mechanisms. Unlock and
  recovery skip private derivation for imported watch-only accounts in either
  lock state. Unlock and recovery keep local account derivation.
- External accounts require their external signer. Funding and PSBT decoration
  semantics remain outside this decision.

## 4. References

- [ADR 0006](0006-wtxmgr-sql-schema.md): wtxmgr SQL schema (related).
- [ADR 0011](0011-no-addresses-used-column.md): addresses table omits the
  `used` column (related).
- [ADR 0013](0013-normalized-account-address-identity.md): defines account
  provenance, optional number and fingerprint, scope, schema, and chain-sync
  policy independently of wallet custody.
- [PR #1411][mixed-account-pr]: mixed imported XPub and local signing accounts.
- [Bitcoin Core v23.0 release notes][btc-core-v23-release]: descriptor wallets
  become the default wallet type for new wallets.
- [Bitcoin Core `createwallet` documentation][btc-core-createwallet]:
  describes the `disable_private_keys` flag used as context for immutable root
  mode.
- [Bitcoin Core descriptor import implementation][btc-core-importdescriptors]:
  provides the descriptor admission policy for comparison; btcwallet permits
  public account tracking alongside local signing accounts.

[mixed-account-pr]: https://github.com/btcsuite/btcwallet/pull/1411
[raw-import-pr]: https://github.com/btcsuite/btcwallet/pull/1412
[btc-core-v23-release]: https://bitcoincore.org/en/releases/23.0/
[btc-core-createwallet]: https://bitcoincore.org/en/doc/31.0.0/rpc/wallet/createwallet/
[btc-core-importdescriptors]: https://github.com/bitcoin/bitcoin/blob/v31.0/src/wallet/rpc/backup.cpp
