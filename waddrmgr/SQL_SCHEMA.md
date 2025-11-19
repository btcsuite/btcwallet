# WAddrmgr SQL Schema

This document defines the schema design for the wallet address manager.

### Overview

The schema follows a hierarchical structure with proper foreign key relationships:

```
wallets (1:N) key_scopes (1:N) accounts (1:N) addresses
   |             |               |               |
   |             |               |               |-- address_secrets (1:1)
   |             |               |
   |             |               |-- account_secrets (1:1)
   |             |
   |             |-- key_scope_secrets (1:1)
   |
   |-- wallet_secrets (1:1)
   |
   |-- wallet_sync_states (1:1)

blocks
   |
   |-- Referenced by: wallet_sync_states, addresses

account_origins
   |
   |-- Referenced by: accounts

address_types
   |
   |-- Referenced by: key_scopes (internal_type_id, external_type_id), addresses

address_sync_statuses
   |
   |-- Referenced by: addresses
```

This structure ensures that:

- Each wallet can have multiple key scopes (BIP44, BIP49, BIP84, etc...)
- Each key scope can contain multiple accounts
- Each account can manage multiple addresses (HD-derived, imported addresses)
- Sensitive data is separated into dedicated tables with 1:1 relationships
- Block data is normalized in a separate table to eliminate redundancy and
   ensure consistency

### KVDB to SQL Mapping
The migration process transforms the hierarchical KVDB bucket structure into
normalized relational tables:

```
KVDB Bucket Structure       SQL Table Equivalent
|-- main/                   -> wallets
    |-- (encrypted keys)    -> wallet_secrets (FK: wallet_id)
|-- sync/                   -> wallet_sync_states (FK: wallet_id)
|-- scope-schema/           -> key_scopes (FK: wallet_id)  
|-- scope/<purpose>-<coin>/ -> key_scopes (FK: wallet_id)
    |-- meta/               -> key_scopes (metadata)
    |-- (encrypted keys)    -> key_scope_secrets (FK: scope_id)
    |-- acct/               -> accounts (FK: scope_id)
        |-- (encrypted keys)-> account_secrets (FK: account_id)
    |-- addr/               -> addresses (FK: account_id)
        |-- (secrets)       -> address_secrets (FK: address_id)
    |-- indexes/            -> SQL Indexes
    |-- usedaddrs/          -> addresses.first_seen_height (FK: blocks.height)
```

### SQL Schema reference

To be used as a reference for implementing the migrations, here is the
reference SQL schema:

```postgresql
-- Blocks table to store blockchain block information.
CREATE TABLE "blocks" (
    -- Blockchain block height, primary key.
    "height" INTEGER PRIMARY KEY,

    -- Hash of the block.
    "hash" BYTEA NOT NULL,

    -- Timestamp of the block.
    "timestamp" BIGINT NOT NULL
);

-- Unique index for fast lookup and prevent duplicate block hashes.
CREATE UNIQUE INDEX "uidx_blocks_hash" ON "blocks" ("hash");

-- Index for fast lookup in block timestamps.
CREATE INDEX "idx_blocks_timestamp" ON "blocks" ("timestamp");

-- Address Types defines the different types of addresses.
CREATE TABLE address_types (
    id INTEGER PRIMARY KEY,
    description TEXT NOT NULL
);

-- Unique index to prevent duplicate address types.
CREATE UNIQUE INDEX uidx_address_types_description
    ON address_types (description);

-- Insert address types explicitly.
INSERT INTO address_types (id, description) VALUES
    -- P2PKH is the Pay to Public Key Hash address type.
    (0, 'P2PKH'),
    -- P2SH is the Pay to Script Hash address type.
    (1, 'P2SH'),
    -- P2WPKH is the Pay to Witness Public Key Hash address type.
    (2, 'P2WPKH'),
    -- P2WSH is the Pay to Witness Script Hash address type.
    (3, 'P2WSH'),
    -- P2TR is the Pay to Taproot address type.
    (4, 'P2TR');

-- Synchronization statuses for addresses.
CREATE TABLE address_sync_statuses (
    id INTEGER PRIMARY KEY,
    description TEXT NOT NULL
);

-- Unique index to prevent duplicate sync statuses.
CREATE UNIQUE INDEX uidx_address_sync_statuses_description
    ON address_sync_statuses (description);

-- Insert sync statuses explicitly.
INSERT INTO address_sync_statuses (id, description) VALUES
    -- none indicates the address has not been synced.
    (0, 'none'),
    -- partial indicates the address has been partially synced.
    (1, 'partial'),
    -- full indicates the address has been fully synced.
    (2, 'full');

-- Accounts Origins defines the different origins for accounts.
CREATE TABLE account_origins (
    id INTEGER PRIMARY KEY,
    description TEXT NOT NULL
);

-- Unique index to prevent duplicate account origins.
CREATE UNIQUE INDEX uidx_account_origins_description
    ON account_origins (description);

-- Insert accounts origin explicitly.
INSERT INTO account_origins (id, description) VALUES
    -- derived indicates the account was derived from a hierarchical deterministic key.
    (0, 'derived'),
    -- imported indicates the account was imported from external source.
    (1, 'imported');

-- Wallets table to store non-sensitive data.
CREATE TABLE "wallets" (
    -- DB ID of the wallet, primary key. Only used for DB level relations.
    "id" BIGSERIAL PRIMARY KEY,

    -- Human friendly name for the wallet.
    "name" TEXT NOT NULL,

    -- Defines if the wallet was imported, so all accounts should be imported.
    "is_imported" BOOLEAN NOT NULL,

    -- Version of the wallet manager that created this wallet.
    "manager_version" SMALLINT NOT NULL,

    -- Defines if the wallet is a watch-only wallet.
    "is_watch_only" BOOLEAN NOT NULL,

    -- Params to derive the public master key.
    "master_pub_params" BYTEA NOT NULL,

    -- Encrypted key used to encrypt/decrypt wallet data related to public
    -- keys.
    "encrypted_crypto_pub_key" BYTEA NOT NULL,

    -- Encrypted HD public key of the wallet.
    "encrypted_master_hd_pub_key" BYTEA
);

-- Unique index to prevent duplicate wallet names.
CREATE UNIQUE INDEX "uidx_wallets_name" ON "wallets" ("name");

-- Wallet Secrets table to store rarely accessed, highly sensitive encrypted
-- material with a strict one-to-one relationship with the wallets table.
CREATE TABLE "wallet_secrets" (
    -- Reference to the wallet these secrets belong to.
    "wallet_id" BIGINT NOT NULL,

    -- Params to derive the private master key.
    "master_priv_params" BYTEA,

    -- Encrypted key used to encrypt/decrypt wallet data related to private
    -- keys.
    "encrypted_crypto_priv_key" BYTEA,

    -- Encrypted key used to encrypt/decrypt wallet data related to scripts.
    "encrypted_crypto_script_key" BYTEA,

    -- Encrypted HD private key of the wallet.
    "encrypted_master_hd_priv_key" BYTEA,

    FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT
);

-- Unique index to ensure one-to-one relationship between wallet and its
-- secrets.
CREATE UNIQUE INDEX "uidx_wallet_secrets_wallet" ON "wallet_secrets" ("wallet_id");

-- Wallet Sync States table to store the synchronization state of each wallet.
-- This is kept separate from the wallets table to avoid bloating it with
-- frequently changing data.
CREATE TABLE "wallet_sync_states" (
    -- Reference to the wallet this sync state belongs to.
    "wallet_id" BIGINT NOT NULL,

    -- Current sync status of the wallet (references blocks table).
    "synced_height" INTEGER,

    -- Birthday block height of the wallet (references blocks table).
    "birthday_height" INTEGER REFERENCES blocks(height),

    -- Indicates if the birthday block has been verified.
    "birthday_verified" BOOLEAN NOT NULL,

    -- Last updated timestamp to track changes.
    "updated_at" BIGINT NOT NULL,

    FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT,
    FOREIGN KEY (synced_height) REFERENCES blocks(height)
        ON DELETE RESTRICT
);

-- Unique index to ensure one-to-one relationship between wallet and its sync
-- state.
CREATE UNIQUE INDEX "uidx_wallet_sync_states_wallet"
    ON "wallet_sync_states" ("wallet_id");

-- Key Scopes table to store different key scopes (BIP standards) for each
-- wallet.
CREATE TABLE "key_scopes" (
    -- DB ID of the key scope, primary key.
    "id" BIGSERIAL PRIMARY KEY,

    -- Reference to the wallet this key scope belongs to.
    "wallet_id" BIGINT NOT NULL,

    -- Indicates the BIP standard for the key scope. This is typically will be
    -- 84h or 1017h.
    "purpose" BIGINT NOT NULL,

    -- Indicates the coin type for the key scope. This is typically 0 for BTC.
    "coin_type" BIGINT NOT NULL,

    -- Encrypted key used to derive public keys for this scope.
    "encrypted_coin_pub_key" BYTEA NOT NULL,

    -- Reference to the address type used for internal/change addresses.
    "internal_type_id" INTEGER NOT NULL,

    -- Reference to the address type used for external/receiving addresses.
    "external_type_id" INTEGER NOT NULL,

    FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT,
    FOREIGN KEY (internal_type_id) REFERENCES address_types(id) ON DELETE RESTRICT,
    FOREIGN KEY (external_type_id) REFERENCES address_types(id) ON DELETE RESTRICT
);

-- Index on foreign wallet_id for faster lookups and joins. Probably not needed
-- because with just one or a few wallets the cardinality is low, but added for
-- completeness.
CREATE INDEX "idx_key_scopes_wallet" ON "key_scopes" ("wallet_id");

-- Unique index to prevent duplicate key scopes for the same wallet.
CREATE UNIQUE INDEX "uidx_key_scopes_wallet_purpose_coin"
    ON "key_scopes" ("wallet_id", "purpose", "coin_type");

-- Key Scope Secrets table to hold encrypted coin-type secrets for each scope.
CREATE TABLE "key_scope_secrets" (
    -- Reference to the key scope these keys belong to.
    "scope_id" BIGINT NOT NULL,

    -- Encrypted key used to derive private keys for this scope.
    "encrypted_coin_priv_key" BYTEA,

    FOREIGN KEY (scope_id) REFERENCES key_scopes(id) ON DELETE RESTRICT
);

-- Unique index to ensure one-to-one relationship between key scope and its
-- secrets.
CREATE UNIQUE INDEX "uidx_key_scope_secrets_scope"
    ON "key_scope_secrets" ("scope_id");

-- Accounts table to store different accounts under each key scope.
CREATE TABLE "accounts" (
    -- DB ID of the account, primary key.
    "id" BIGSERIAL PRIMARY KEY,

    -- Reference to the key scope this account belongs to.
    "scope_id" BIGINT NOT NULL,

    -- Account number described in BIP44.
    "account_number" BIGINT NOT NULL,

    -- Human friendly name for the account.
    "name" TEXT NOT NULL,

    -- Reference to the origin of the account.
    "origin_id" INTEGER NOT NULL,

    -- Encrypted public key for the account.
    "encrypted_public_key" BYTEA NOT NULL,

    -- Master fingerprint is the fingerprint of the master pub key that created
    -- this account.
    "master_fingerprint" BYTEA NOT NULL,

    -- Defines if the account is watch-only.
    "is_watch_only" BOOLEAN NOT NULL,

    FOREIGN KEY (scope_id) REFERENCES key_scopes(id) ON DELETE RESTRICT,
    FOREIGN KEY (origin_id) REFERENCES account_origins(id) ON DELETE RESTRICT
);

-- Index on foreign scope_id for faster lookups and joins.
CREATE INDEX "idx_accounts_scope" ON "accounts" ("scope_id");

-- Unique index to prevent duplicate account numbers within the same key scope
-- and origin.
CREATE UNIQUE INDEX "uidx_accounts_scope_account_number_origin"
    ON "accounts" ("scope_id", "account_number", "origin_id");

-- Unique index to prevent duplicate account names within the same key scope.
CREATE UNIQUE INDEX "uidx_accounts_scope_name"
    ON "accounts" ("scope_id", "name");

-- Account Secrets table to hold encrypted account-level secrets.
CREATE TABLE "account_secrets" (
    -- Reference to the account these keys belong to.
    "account_id" BIGINT NOT NULL,

    -- Encrypted private key for the account (NULL for watch-only origins).
    "encrypted_private_key" BYTEA,

    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT
);

-- Unique index to ensure one-to-one relationship between account and its secrets.
CREATE UNIQUE INDEX "uidx_account_secrets_account"
    ON "account_secrets" ("account_id");

-- Addresses table to store addresses (e.g. HD-derived, imported) under each
-- account.
CREATE TABLE "addresses" (
    -- DB ID of the address, primary key.
    "id" BIGSERIAL PRIMARY KEY,

    -- Reference to the account this address belongs to.
    "account_id" BIGINT NOT NULL,

    -- The on-chain script pubkey which locks the funds.
    "encrypted_script_pub_key" BYTEA NOT NULL,

    -- Reference to the address type this address is.
    "type_id" INTEGER NOT NULL,

    -- Reference to the sync status of this address.
    "sync_status_id" INTEGER NOT NULL,

    -- Block height of when the address was first seen on the blockchain. Null
    -- if never seen. References the blocks table.
    "first_seen_height" INTEGER,

    -- Branch derivation if is HD Chain address.
    "address_branch" BIGINT,

    -- Index derivation if is HD Chain address.
    "address_index" BIGINT,

    -- Encrypted public key if is imported address.
    "encrypted_pub_key" BYTEA,

    -- Witness version if is Witness.
    "witness_version" SMALLINT,

    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE RESTRICT,
    FOREIGN KEY (first_seen_height) REFERENCES blocks(height)
        ON DELETE RESTRICT,
    FOREIGN KEY (type_id) REFERENCES address_types(id) ON DELETE RESTRICT,
    FOREIGN KEY (sync_status_id) REFERENCES address_sync_statuses(id)
        ON DELETE RESTRICT
);

-- Index on foreign account_id for faster lookups and joins.
CREATE INDEX "idx_addresses_account" ON "addresses" ("account_id");

-- Unique index to prevent duplicate address derivations within the same
-- account.
CREATE UNIQUE INDEX "uidx_addresses_branch_index"
    ON "addresses" ("account_id", "address_branch", "address_index")
    WHERE "address_branch" IS NOT NULL
    AND "address_index" IS NOT NULL;

-- Address Secrets table to hold sensitive encrypted material needed to spend
-- from an address.
CREATE TABLE "address_secrets" (
    -- Reference to the address these secrets belong to.
    "address_id" BIGINT NOT NULL,

    -- Encrypted private key if is imported address.
    "encrypted_priv_key" BYTEA,

    -- Encrypted script if is Script address.
    "encrypted_script" BYTEA,

    -- Denotes whether the script is considered to be "secret" and encrypted
    -- with the script encryption key or "public" and therefore only encrypted
    -- with the public encryption key.
    "is_secret_script" BOOLEAN,

    FOREIGN KEY (address_id) REFERENCES addresses(id) ON DELETE RESTRICT
);

-- Unique index to ensure one-to-one relationship between address and its
-- secrets.
CREATE UNIQUE INDEX "uidx_address_secrets_address"
    ON "address_secrets" ("address_id");
```
