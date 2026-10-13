# ADR 0012: Wallet Root Mode and Account Custody

## 1. Context

Revision note: [PR #1411][mixed-account-pr] replaces this ADR's original
wallet-wide custody uniformity rule with immutable wallet/root mode and
per-account custody, allowing imported XPub accounts alongside local signing
accounts. [PR #1412][raw-import-pr] extends this policy to accountless raw
public-key and tapscript imports in signing wallets.

A wallet can track an external signer's imported account XPub alongside
accounts whose private keys derive from the wallet root. Importing the XPub
grants tracking authority, while the external signer retains custody. Local
accounts must continue signing, and both kinds of accounts must retain their
ownership and custody across close/reopen.

The legacy `waddrmgr` already permits an imported XPub account inside a
signing wallet. The SQL store records immutable wallet mode in
`wallets.is_watch_only` and distinguishes root-derived accounts from imported
accounts through existing provenance. Those fields can express the same
custody boundary without joining `account_secrets` in public account, address,
or UTXO reads.

SQL UTXO results already carry an optional spendability override. Wallet uses
that override before applying coinbase maturity. A wallet-level flag alone is
insufficient for an external account's outputs inside a signing wallet.

Bitcoin Core descriptor wallets provide context for immutable root mode
through `disable_private_keys`, but their descriptor-import admission policy
does not express btcwallet's mixed account requirement.

## 2. Decision

`Wallet.IsWatchOnly()` reports immutable wallet/root mode, set at creation and
recorded in `wallets.is_watch_only`. A signing wallet may also track
public-only imported XPub accounts. Watch-only wallets continue rejecting
private-key material at the store boundary on both SQL backends.

Effective account custody is watch-only when either the wallet is watch-only
or the account key was imported rather than derived from its root. HD child
addresses inherit that account custody. Public reads use the existing wallet
mode and account provenance rather than inferring custody from secret
presence.

Imported account outputs remain visible through normal ownership and UTXO
queries, with `Spendable` set to false. Local account outputs retain the
existing wallet default and maturity rules. Callers use
`AccountInfo.IsWatchOnly` for account custody and `Utxo.Spendable` for output
signability; a signing wallet's root mode does not imply that every account
can sign locally.

Balance reporting retains its existing shape. The legacy JSON-RPC contract
(`getbalance`, `listaccounts`, `includeWatchOnly`) retains its historical
fields. This decision adds no signing API, secret-table join, persisted
custody flag, or new balance category. Raw imports retain the policy below.

### Supplied account XPub custody

Public account imports supply no matching private account material. SQL
accepts these imported XPubs in signing and watch-only wallets, and reports
their external custody at creation, child allocation, ownership reads, and
reopen. The existing signer refuses an external child without a local
wallet-root path; importing its XPub does not make the child locally signable.

Optional low-level account secret storage remains supported, but does not
establish a wallet-root path for a numberless imported account. Importing a
private wallet root is different: accounts derived from that root remain
wallet-root-derived and may be spendable.

An account's immutable `NoChainSync` value is independent of custody. Signing
and watch-only wallets may each contain accounts with either value; excluding
an account from automatic chain synchronization neither adds nor removes
signing capability.

ADR 0013 owns account identity, supported creation shapes, and chain-sync
policy. This custody decision does not expand backend capabilities for
supplied numbered accounts or alter per-account address schemas, PSBT
metadata, or coin selection.

### Raw imported addresses use per-address custody

SQL raw imports follow [ADR 0013](0013-normalized-account-address-identity.md):
they are wallet-local `addresses` rows without an account, scope, or
`derived_addresses` row. The name `imported`
(`db.DefaultImportedAccountName`) is a compatibility alias, not a stored SQL
account row. Importing a raw address does not create an account bucket.

The alias remains reserved: `CreateDerivedAccount` and
`CreateImportedAccount` reject `DefaultImportedAccountName` with
`ErrReservedAccountName`. Raw imported addresses cannot be retargeted into an
HD account. kvdb retains its legacy per-scope imported-address pseudo-account;
that bucket does not represent an imported XPub account.

Raw-import admission applies per address, independently of XPub account
custody:

- Signing wallets accept raw public-key and tapscript imports without
  requiring matching private-key material or changing the wallet root mode.
- Watch-only wallets continue rejecting private-key-bearing imports with
  `ErrWatchOnlyViolation`.
- A raw address is watch-only when its wallet is watch-only or its own
  private-key ciphertext is absent or empty. Script ciphertext alone does not
  supply signing authority. This check does not decrypt or validate ciphertext
  and does not prove that a retained script can be satisfied.
- Address reads reuse their existing address-secret join and Boolean result
  for effective custody. UTXO queries expose raw private-key absence separately
  from the existing Go shape helper's imported-HD custody rule. Keyless raw
  outputs receive the existing false `Spendable` override; private raw and
  local HD outputs retain their existing defaults and maturity checks.

Raw imports reuse committed registration before public success. Repeated
imports resolve canonical stored metadata and retry registration in either
root mode. Matching wallet/output scripts retain their first tapscript; later
reveals are not merged or substituted, and key-only records are not upgraded.
Uncertain commits return no success and are not automatically retried. Wallet
lifetime cancellation and Stop retain ownership of registration.

Startup reconstructs watches from persisted addresses. Reopen preserves public
address, balance, UTXO and transaction reporting, stored script access, local
signing refusal for missing keys, and future receipt. This policy adds no
historical scan, account selector or PSBT behavior.

Derived addresses are unaffected: they inherit their key material from the
account xpub/xpriv and are reached through `AccountKeyFromParams` (the
caller-supplied account name), rather than the raw-import alias.

### P2A / anchor outputs are transaction state, not imports

Pay-to-anchor (P2A) outputs are keyless by construction (`OP_1
<0x4e73>`): there is no private key to import and none to require. Although
Bitcoin Core can encode P2A as an address/destination, a P2A is not useful as
long-lived wallet address material. Its relevance comes from the transaction
flow that created it, typically as a temporary anchor used by a child
transaction to fee-bump its parent.

This ADR therefore treats P2A as transaction/output state, not as a standard
managed or imported address. A spendable wallet that needs to observe an anchor
tracks the concrete output through the relevant-output / watched-outpoint path,
not by importing an address row. No imported-address or address-secret row is
created for the anchor, so raw admission and custody rules do not apply to
this path. The child
transaction that spends and fee-bumps the parent signs with the wallet's own
key material on its other inputs/outputs; the keyless anchor input contributes
no signature, so the spend flow retains the immutable wallet root-mode
model.

## 3. Consequences

- Signing wallets can track external account XPubs while local accounts retain
  their existing signing behavior. Reopen preserves the custody distinction.
- `db.AccountInfo.IsWatchOnly` and `db.AddressInfo.IsWatchOnly` describe
  effective account/HD-child custody. Raw address custody additionally reflects
  its own private-key absence. These values need not equal
  `Wallet.IsWatchOnly()` in a signing wallet tracking external material.
- `db.UtxoInfo` needs no new watch-only field. Its existing optional
  `Spendable` override marks imported HD children and keyless raw outputs
  non-spendable; local children and private raw imports retain their existing
  conversion and wallet-default behavior.
- Account/address/UTXO reads do not consult `account_secrets` to infer
  custody. Existing account provenance identifies external accounts without
  mutable capability state or requiring a second wallet.
- `CreateImportedAccount` permits public-only imports in signing wallets and
  retains the watch-only/private-material guard. Optional encrypted account
  secrets may still be persisted; their presence does not change imported
  provenance into local root custody.
- Raw-import per-address secret checks remain separate from XPub account
  admission. The inverse raw private-key requirement is removed; watch-only
  roots still refuse private material, and raw imports stay accountless.
- Local accounts use wallet-root signing material. HD addresses do not require
  per-address private keys in `address_secrets`; absence of an address secret
  alone does not imply external custody.
- `account_secrets` and `key_scope_secrets` remain available to their existing
  consumers. This decision changes neither their storage nor the signer path.
- The kvdb backend reuses its account/output custody mechanisms. Unlock and
  recovery skip private derivation for imported watch-only accounts in either
  lock state, while retaining local account derivation.
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
