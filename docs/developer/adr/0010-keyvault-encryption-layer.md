# ADR 0010: Keyvault Encryption Layer

## Status

- **Status:** Accepted
- **Date:** 2026-02-06

## Relationships

- **Amends:** None.
- **Supersedes:** None.
- **Amended by:** None.
- **Superseded by:** None.

## 1. Context

The legacy `waddrmgr` design combines storage, lock state, key derivation,
and encryption. The SQL migration needs a boundary between secret use and
persistence. ADR 0009 defines the encryption model, and ADR 0007 defines
the planned cryptographic primitives.

Raw decryption alone does not give the vault control of secret lifetime.
Wallet code can hold a decrypted key after the vault releases its mutex.
Thus `Lock` can return while another operation still uses that key.

Account creation also needs secret operations inside a Store transaction.
Passphrase rotation must not take the Store and vault locks in the opposite
order. Otherwise, the two operations can wait for each other.

## 2. Decision

### Wallet Scope and Persistence

Each `wallet/internal/keyvault.Vault` belongs to one wallet. Construction
supplies its `db.Store` and wallet ID. Vault methods do not take wallet IDs.
The vault accesses persistence only through the Store, which stores opaque
ciphertext. Wallet code can use the Store directly for nonsecret data.

Vault selectors use a key scope with an account name or optional BIP44
account number, a derivation path, or a script pubkey. They do not contain
SQL row IDs or kvdb adapter IDs.

### Secret Operations

The vault owns private derivation, primitive signing, ECDH, and secret
encryption and decryption. It follows ADR 0009 and adopts ADR 0007's
primitives when implemented. Use narrow typed operations rather than raw
decryption or caller callbacks. `UnsafeVault.Decrypt` remains only for
existing callers during migration.

The Wallet owns these responsibilities:

- Transaction, PSBT, and script-commitment checks.
- Digest and sighash construction.
- Witness assembly, signature serialization, and signature-record policy.
- Public-only derivation and ordinary nonsecret script construction.
- Request admission and the auto-lock schedule.

Public-only derivation stays available while the wallet is locked.

The vault receives multiplication and addition coefficients through
`KeyTweak`, introduced by PR #1437. It applies `mul*d + add` internally,
where `d` is the wallet private key.

### Synchronization and Lock Order

A secret operation holds the vault guard from its lock-state check through
its secret use and cleanup. `Lock` waits for active operations, then clears
runtime secrets and any secret cache. Until a later `Unlock`, operations
that need unlocked secrets fail with `ErrVaultLocked`.

The guard is not reentrant. Guarded code must not call a public vault
method, submit a Wallet request, or run caller-supplied code. Internal
helpers use the state of the operation without taking the guard again.

The lock order is Store transaction, then vault guard. The vault must not
call the Store while it holds the guard. Load persisted inputs before
taking the guard. An account-derivation operation inside a Store transaction
must use available runtime state or previously loaded ciphertext, without
nested Store access.

`Unlock` and passphrase rotation must serialize credential reads and state
changes. No Store transaction can wait for that credential exclusion.
`Unlock` installs complete runtime state or leaves none; it must not
authenticate against credentials that a completed rotation replaced.

Rotation re-wraps the crypto keys without changing them. Thus account
ciphertext remains valid across rotation. Account creation keeps allocation,
derivation, and persistence atomic in its Store transaction. If the secret
operation fails, the transaction rolls back its allocation. This needs no
new compare-and-swap or preparation protocol.

### Ownership and Cleanup

The vault owns its runtime secrets and temporary work copies. It clears
temporary secrets on success, error, and panic. Runtime secrets remain
only while unlocked. The caller owns supplied passphrases, plaintext, and
tweak data. Tweak data can contain secrets; the vault owns and clears its
work copies, not the caller's originals. Do not log secrets or include them
in errors.

Safe operations return results, not wallet private keys, and never give
those keys to caller code. Private-key export belongs exclusively to
`UnsafeSigner`. There are two explicit copy exceptions:

- `UnsafeSigner` key returns are independent caller-owned copies. The
  caller must clear them after use.
- The safe vault operation `DecryptScript(ctx, scriptPubKey)` returns an
  independent caller-owned copy of the decrypted script. Wallet code uses
  this operation for `AddressManager.ScriptForOutput`.

After either return, the vault cannot control the copy's lifetime. `Lock`
does not clear it. Callers also own returned signatures, public keys, and
ECDH results.

Legacy `waddrmgr` paths can coexist during migration. Existing deprecated
key exports and private-key callbacks are not part of the safe surface.
Do not add such exposure to new safe operations. Any new operation that a
legacy vault supports must follow this contract.

## 3. Alternatives

### Return Private Keys to Wallet Code

Wallet code could decrypt and use keys itself. The vault would then have no
control over when those keys are cleared. This defeats operation-scoped
ownership except for the explicit export boundary above.

### Pass a Private Key to a Caller Callback

A callback can retain the key after the operation returns. The vault cannot
enforce its lifetime guarantee. Typed operations express the supported uses
without giving keys to caller code. Callbacks can also reenter the vault or
invert its lock order.

### Expose Backend Locators and a Second Public Signing API

PR #1279 shares the digest-level signing boundary, but its `AccountID`
locator exposes backend identity. Semantic selectors keep callers portable.
A second public signature hierarchy adds no ownership guarantee. The PR
can align with this decision; it need not close first and is not accepted
implementation evidence.

### Add a Credential Preparation Protocol

Rotation preserves the crypto keys, so it does not invalidate account
ciphertext. A new preparation or compare-and-swap protocol adds states and
failure paths without solving another consistency problem here.

## 4. Tradeoffs

The boundary isolates secret use from persistence and Wallet policy. Tests
can replace the Store or vault independently. Typed operations require more
internal methods, and migration temporarily keeps both keyvault and legacy
paths. `Lock` can wait for a slow operation.

Memory cleanup has limits. Some parsers require temporary immutable
strings. Such parsing must be bounded, retain no string reference, and
clear wipeable sources and work copies. The vault cannot erase immutable
strings or guarantee erasure of compiler, runtime, or library copies.

## References

- [ADR 0001: Multi-Wallet Architecture](0001-multi-wallet-architecture.md)
- [ADR 0007: XChaCha20-Poly1305
  Encryption](0007-xchacha20-poly1305-encryption.md)
- [ADR 0009: Single-Passphrase Encryption
  Model](0009-single-passphrase-encryption.md)
- PR [#1279](https://github.com/btcsuite/btcwallet/pull/1279): vault
  signing proposal.
- PR [#1437](https://github.com/btcsuite/btcwallet/pull/1437): typed key
  tweaks and effective-key signing.
- PR [#1485](https://github.com/btcsuite/btcwallet/pull/1485): the ECDH
  result contract.
