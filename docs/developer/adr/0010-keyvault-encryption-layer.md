# ADR 0010: Keyvault Encryption Layer

## 1. Context

The encryption model defined in ADR 0009 and the cryptographic primitive
migration proposed in ADR 0007 require a clear boundary between wallet domain
logic and database persistence.

The legacy `waddrmgr` design couples storage, locking, key derivation, and
encryption. This makes the SQL migration harder, spreads encryption behavior
across persistence code, and makes lock state difficult to test in isolation.

We need a dedicated component that owns lock state, key derivation, secret
material lifetime, and encryption. The database layer should remain encryption
agnostic and store encrypted key material as opaque bytes.

The `db.Store` remains available to other wallet code for non-cryptographic
queries and updates.

## 2. Decision

We will introduce a dedicated `wallet/internal/keyvault` package. This package
defines the encryption boundary between wallet domain code and the store layer.

A wallet facing `keyvault.Vault` is scoped to exactly one wallet at construction
time. It receives a `db.Store` and a wallet identifier during wiring, then keeps
persistence routing internal. Callers that hold a vault do not pass a wallet ID
to each lock, unlock, encrypt, decrypt, or derivation operation.

Keyvault accesses persistence through `db.Store`. It does not talk directly to
SQL backends.

The vault API also includes a digest level signing method. `DerivePubKey` and
`Sign` keep private key use inside the same wallet scoped boundary that owns
lock state and key lifecycle. Callers identify keys with a sealed
`wallet/signing.KeyLocator` variant: `FullHDKeyLocator` for a full HD
derivation path, `AccountKeyLocator` for an account row child reference, or
`ScriptPubKeyLocator` for raw or imported rows without exposing private key
material or database routing.

Wallet code builds a sealed `wallet/signing.Request` containing both the key
locator and a caller computed `[32]byte` digest, then calls `Sign` with that
request. Requests do not accept transactions, PSBTs, scripts, witnesses, or
sighash types. Transaction sighash construction, PSBT assembly, signature
serialization, appended sighash bytes, witness construction, and Taproot tree
construction remain wallet layer responsibilities.

`Sign` accepts a sealed `wallet/signing.Request` variant instead of a
flag-heavy parameter struct. The sealed variants describe ECDSA, compact
recoverable ECDSA, Schnorr, and tweaked Schnorr primitive operations, making
invalid mode combinations unrepresentable outside the shared signing package.
The shared package also defines sealed signature result variants so keyvault
and later public wallet signing code can use the same primitive request and
result machinery.

The Schnorr tweak request uses BIP340 terminology for even-Y key normalization
and carries an already computed additive secp256k1 scalar. This scalar is the
final key-tweak value, not a Taproot script root, merkle root, or BIP341 tweak
input byte string. These references describe the key and tweak concepts only.
They do not move transaction, script, or Taproot tree knowledge into the vault.

`wallet/signing.CompactECDSARequest` remains digest-level, and the returned
compact recoverable ECDSA bytes remain the caller's responsibility for compact
signature use and wallet-layer transaction assembly.

`wallet/signing.SchnorrKeyTweak` is a value descriptor with a
`Scalar btcec.ModNScalar` and `NormalizeEvenY bool`. Passing the additive scalar
as data lets the vault apply the private key operation internally without
accepting a private key callback from the wallet layer.

```mermaid
flowchart TD
    wallet[Wallet]

    subgraph support[Supporting libraries]
        hd[btcutil/hdkeychain<br/>BIP32 and BIP44 derivation]
        crypto[AEAD crypto<br/>current and migrated primitives]
    end

    subgraph vault_boundary[keyvault boundary]
        vault[keyvault.Vault<br/>wallet scoped lock state<br/>key lifecycle<br/>secret material API]
        cache[(In memory secret cache<br/>unlocked keys<br/>derived keys)]
    end

    subgraph store_boundary[db.Store boundary]
        store[db.Store<br/>multi wallet persistence API]

        subgraph backends[Persistence backends]
            sql[(SQL backend<br/>rows scoped by wallet_id)]
            kvdb[(kvdb backend<br/>legacy storage)]
        end
    end

    wallet -->|owns wallet scoped vault| vault
    wallet -->|uses store for non cryptographic data| store
    vault -->|persists encrypted key material| store
    vault -->|loads encrypted key material| store
    vault -->|keeps unlocked material| cache
    vault -->|derives HD keys| hd
    vault -->|encrypts and decrypts secrets| crypto
    store -->|routes by wallet_id| sql
    store -->|adapts legacy layout| kvdb
```

This is a structural boundary diagram, not a runtime call sequence.

The `Wallet` struct holds two related dependencies:

1. A wallet scoped `keyvault.Vault`
2. A multi wallet `db.Store`

Encrypted key material flows through the vault. Non-cryptographic wallet data
may still flow directly through the store.

The store remains the persistence boundary for wallet data and keeps wallet ID
routing inside the store or adapter layer. The vault hides that routing from
wallet facing lock, unlock, encryption, decryption, and derivation APIs.

### Responsibilities

1. **Own lock state and key lifecycle**
   Keyvault manages lock state, key material lifetime, and secure memory
   zeroing.

2. **Expose typed domain interfaces**
   Keyvault exposes typed domain operations and results such as public keys,
   signatures, and encrypted bytes as appropriate. Private key material remains
   inside the vault instead of being returned to wallet code as raw key bytes or
   blobs.

3. **Handle HD derivation**
   Keyvault uses `btcutil/hdkeychain` for BIP32 and BIP44 derivation and returns
   or persists derived key material as needed.

4. **Maintain an in memory secret cache**
   Keyvault may cache account level keys and derived keys while unlocked to
   avoid repeated derivation and database reads.

5. **Keep wallet facing APIs scoped to one wallet**
   A wallet facing `keyvault.Vault` is configured for one wallet during
   construction. Callers do not pass a wallet ID to every vault method.

6. **Track current and planned cryptographic primitives**
   Keyvault follows the single passphrase model accepted in ADR 0009 and adopts
   the ADR 0007 primitive migration once implemented.

7. **Coexist with `waddrmgr` during migration**
   New code uses keyvault while legacy code continues to rely on `waddrmgr`
   until the migration is complete.

8. **Sign caller computed digests**
   Keyvault signs sealed ECDSA, compact recoverable ECDSA, Schnorr, and tweaked
   Schnorr digest requests for located wallet keys while keeping transaction,
   PSBT, script, witness, sighash, and Taproot tree logic in the wallet layer.

## 3. Consequences

The wallet facing `keyvault.Vault` API intentionally does not expose wallet ID
parameters on methods such as `Unlock`, `Lock`, `IsLocked`, `Encrypt`,
`Decrypt`, or key derivation methods.

Code that holds a vault already holds the vault selected for that wallet.
Requiring every method call to pass a wallet ID would push database routing into
controllers, accounts, addresses, and tests. It would also make cross wallet
mistakes possible at every call site.

The SQL and store layers remain multi wallet aware through `wallet_id` fields
and parameters, consistent with ADR 0001. That routing is handled inside store
implementations or keyvault adapters, not repeated throughout wallet domain
code.

Auto lock timeout scheduling is a wallet or controller lifecycle policy, not
part of `keyvault.Vault`.

The signing surface follows the same boundary. Wallet code chooses the key,
constructs the 32-byte digest, builds the appropriate sealed
`wallet/signing.Request` carrying both values, calls `Sign`, then serializes and
attaches the returned sealed `wallet/signing.Signature` in the format required by
the transaction or PSBT flow. This keeps private key access inside the vault
without making the vault a Bitcoin transaction signer.

### Pros

1. **Separation of concerns**
   Database code stores opaque encrypted bytes without knowing about
   cryptography, lock state, or key derivation.

2. **Type safety**
   Wallet code works with typed keys and addresses instead of raw encrypted
   blobs.

3. **Centralized lock management**
   Lock state and secret zeroing are owned by one component, while timeout and
   auto lock scheduling stay outside the vault.

4. **Extensible responsibility boundary**
   Keyvault centralizes secret and key responsibilities, making it easier to
   add future responsibilities behind the same boundary without spreading
   changes across wallet callers.

5. **Lower call site complexity**
   Wallet, account, address, and controller code can use a vault without
   threading wallet IDs through every encryption or key access operation.

6. **Better testability**
   Keyvault can be tested against mock stores, and wallet domain code can be
   tested against mock vault implementations.

7. **Per wallet isolation**
   Each wallet has its own vault instance, lock state, cache, and secret
   material lifetime.

8. **Migration support**
   Keyvault can coexist with `waddrmgr`, allowing new SQL backed paths to move
   behind the new boundary before legacy paths are removed.

9. **Narrow signing boundary**
   Digest level signing keeps private key operations in one locked component
   without duplicating transaction, PSBT, script, witness, or Taproot tree
   responsibilities inside keyvault.

10. **Tweak data stays explicit**
    `wallet/signing.SchnorrKeyTweak` carries the already computed additive
    secp256k1 scalar and even-Y normalization flag as data, so callers can
    describe Taproot key tweaks without passing script roots, merkle roots,
    BIP341 tweak input bytes, or private key callbacks across the vault
    boundary.

### Cons

1. **Additional abstraction**
   The design introduces a new package boundary that must be maintained.

2. **Migration cost**
   Existing code paths must be refactored to use the new keyvault API.

3. **Temporary dual systems**
   `waddrmgr` and keyvault will coexist during the migration, increasing
   temporary complexity.

4. **Boundary discipline**
   Implementations must keep wallet ID routing inside constructors, adapters, or
   store methods. Exposing wallet ID on every vault method is rejected.

5. **Constructor and adapter indirection**
   Wiring a vault from `db.Store` plus wallet ID adds an adapter boundary
   between wallet domain code and persistence. That boundary is intentional, but
   future changes must keep it aligned with store methods that remain multi
   wallet aware.

## 4. Status

Accepted.
