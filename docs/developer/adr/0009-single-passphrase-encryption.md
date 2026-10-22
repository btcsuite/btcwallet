# ADR 0009: Single-Passphrase Encryption Model

## 1. Context

`btcwallet` is moving from a key-value database (kvdb) to a SQL-based
backend. This transition requires a clean, consistent encryption model that
works across SQLite and PostgreSQL.

The legacy system used a dual-passphrase hierarchy with separate public and
private encryption keys. In practice, downstream systems often set the public
passphrase to a known constant to allow auto-start. This practice removed the
privacy benefits but kept the complexity. The legacy model also diverges from
the industry standard of Bitcoin Core and libraries like BDK.

The design notes that guided this change are in
[Single-Passphrase Encryption Design Notes](https://gist.github.com/yyforyongyu/edfeee0f84cf79851735bcc3e740a871).

## 2. Decision

We will adopt a **Single-Passphrase Model**. This model encrypts **private data
only** and keeps public data in plaintext.

```mermaid
flowchart TD
    A[User Passphrase] --> B[scrypt KDF]
    B --> C[Master Key]
    C --> D[Encrypt Private Data]
    E[Public Data] --> F[(Database)]
    D --> F
```

### Key points

1. **One master encryption key** derived from the user passphrase
2. **Private data encrypted** (private keys, HD seeds, xprivs, scripts)
3. **Public data plaintext** (addresses, pubkeys, transactions, balances)
4. **Simplified hierarchy** because we remove `CryptoPubKey` and
   `CryptoScriptKey`

## 3. Consequences

### Pros

* **Simplicity**: Removes the dual-passphrase logic.
* **Performance**: Read-only operations do not decrypt public data. This
  reduces the query overhead.
* **Interoperability**: Aligns with Bitcoin Core and BDK conventions.
* **UX clarity**: Users only need a single passphrase.

### Cons

* **Privacy at rest**: If an attacker compromises the database, the
  transaction history, balances, and public keys are exposed. This tradeoff is
  consistent with Bitcoin Core. If users require stronger protection, they can
  use full disk encryption such as LUKS.
* **Migration effort**: Existing wallets must be migrated away from the legacy
  dual-passphrase model. We will do this work together with the SQL backend
  migration.

## 4. Threat Model and Security Boundaries

This model protects private key material at rest when an attacker can read the
database but cannot guess the wallet passphrase.

This model does not protect metadata privacy if an attacker exfiltrates the
database contents. By design, addresses, balances, and transaction history stay
visible.

This model requires these operational mitigations:

* Full disk encryption for database files.
* Host hardening (least privilege, patching, endpoint protection).
* Encrypted backups with independent access controls and key management.

## 5. Status

Accepted.
