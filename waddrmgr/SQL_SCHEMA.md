# WAddrmgr SQL Schema

This document defines the schema design for the wallet address manager.

### Overview

The schema follows a hierarchical structure relationship:

```
wallets (1:N) key_scopes (1:N) accounts (1:N) addresses
   \
    \----- (1:1) wallet_sync_states
```

This structure ensures that:

- Each wallet can have multiple key scopes (BIP44, BIP49, BIP84, etc.)
- Each key scope can contain multiple accounts
- Each account can manage multiple addresses (HD-derived, imported addresses)
- wallets has a separated table for state record, to avoid bloating the wallets
table

### KVDB to SQL Mapping

The migration process transforms the hierarchical KVDB bucket structure into
normalized relational tables:

```
KVDB Bucket Structure       SQL Table Equivalent
|-- main/                   -> wallets
|-- sync/                   -> wallet_sync_states
|-- scope-schema/           -> key_scopes  
|-- scope/<purpose>-<coin>/ -> key_scopes
    |-- meta/               -> key_scopes (metadata)
    |-- acct/               -> accounts
    |-- addr/               -> addresses
    |-- indexes/            -> SQL Indexes
    |-- usedaddrs/          -> addresses.first_seen_time
```

### SQL Schema reference

To be used as a reference for implementing the migrations, here is the
reference SQL schema:

```postgresql
-- Wallets table to store wallet metadata and encryption keys.
CREATE TABLE "wallets" (
    -- DB ID of the wallet, primary key. Only used for DB level relations.
    "id" UUID PRIMARY KEY,
    
    -- Human friendly name for the wallet.
    "name" TEXT NOT NULL,
    
    -- Version of the wallet manager that created this wallet.
    "manager_version" SMALLINT NOT NULL,
    
    -- Defines if the wallet is a watch-only wallet.
    "is_watch_only" BOOLEAN NOT NULL,
    
    -- Params to derive the public master key.
    "master_pub_params" BYTEA NOT NULL,
    
    -- Params to derive the private master key.
    "master_priv_params" BYTEA,
    
    -- Encrypted key used to encrypt/decrypt wallet data related to public
    -- keys.
    "encrypted_crypto_pub_key" BYTEA NOT NULL,
    
    -- Encrypted key used to encrypt/decrypt wallet data related to private
    -- keys.
    "encrypted_crypto_priv_key" BYTEA,
    
    -- Encrypted key used to encrypt/decrypt wallet data related to scripts.
    "encrypted_crypto_script_key" BYTEA,
    
    -- Encrypted HD private key of the wallet (if not watch-only).
    "encrypted_master_hd_priv_key" BYTEA,
    
    -- Encrypted HD public key of the wallet.
    "encrypted_master_hd_pub_key" BYTEA,
    
    -- Timestamp of when the wallet was created. Just for reference.
    "created_at" INTEGER NOT NULL
);

-- Unique index to prevent duplicate wallet names.
CREATE UNIQUE INDEX "uidx_wallets_name" ON "wallets" ("name");

-- Wallet Sync States table to store the synchronization state of each wallet.
-- This is kept separate from the wallets table to avoid bloating it with
-- frequently changing data.
CREATE TABLE "wallet_sync_states" (
    -- Reference to the wallet this sync state belongs to.
    "wallet_id" UUID NOT NULL,
    
    -- Current sync status of the wallet.
    "synced_to_height" INTEGER,
    "synced_to_hash" BYTEA,
    "synced_to_timestamp" INTEGER,
    
    -- Starting point for next wallet synchronization.
    "start_block_height" INTEGER,
    "start_block_hash" BYTEA,
    "start_block_timestamp" INTEGER,
    
    -- Birthday block timestamp for the wallet.
    "birthday" INTEGER NOT NULL,
    
    -- Indicates if the birthday block has been verified.
    "birthday_block_verified" BOOLEAN NOT NULL,
    
    -- Last updated timestamp to track changes.
    "updated_at" INTEGER NOT NULL
);

-- Foreign key from wallet_sync_states to wallets.
ALTER TABLE "wallet_sync_states" ADD FOREIGN KEY ("wallet_id")
    REFERENCES "wallets" ("id") ON DELETE CASCADE;

-- Unique index to ensure one-to-one relationship between wallet and its sync
-- state.
CREATE UNIQUE INDEX "uidx_wallet_sync_states_wallet" 
    ON "wallet_sync_states" ("wallet_id");

-- Key Scopes table to store different key scopes (BIP standards) for each
-- wallet.
CREATE TABLE "key_scopes" (
    -- DB ID of the key scope, primary key.
    "id" UUID PRIMARY KEY,
    
    -- Reference to the wallet this key scope belongs to.
    "wallet_id" UUID NOT NULL,
    
    -- Indicates the BIP standard for the key scope. This is typically will be
    -- 84h or 9735h.
    "purpose" BIGINT NOT NULL,
    
    -- Indicates the coin type for the key scope. This is typically 0 for BTC.
    "coin_type" BIGINT NOT NULL,
    
    -- Address type used for internal or change addresses. Mapped in the app
    -- layer.
    "internal_addr_type" SMALLINT NOT NULL,
    
    -- Address type used for external or receiving addresses. Mapped in the app
    -- layer.
    "external_addr_type" SMALLINT NOT NULL,
    
    -- Indicates if the witness public keys are compressed.
    "witness_pubkey_compression" BOOLEAN NOT NULL,
    
    -- Encrypted key used to derive public keys for this scope.
    "encrypted_coin_pub_key" BYTEA NOT NULL,
    
    -- Encrypted key used to derive private keys for this scope.
    "encrypted_coin_priv_key" BYTEA,
    
    -- Last created account number under this scope. It is a cache to fast
    -- lookup the next account number.
    "last_created_account" BIGINT NOT NULL,
    
    -- Timestamp of when the key scope was created. Just for reference.
    "created_at" INTEGER NOT NULL
);

-- Foreign key from key_scopes to wallets.
ALTER TABLE "key_scopes" ADD FOREIGN KEY ("wallet_id") 
    REFERENCES "wallets" ("id") ON DELETE CASCADE;

-- Index on foreign wallet_id for faster lookups and joins. Probably not needed
-- because with just one or a few wallets the cardinality is low, but added for
-- completeness.
CREATE INDEX "idx_key_scopes_wallet" ON "key_scopes" ("wallet_id");

-- Unique index to prevent duplicate key scopes for the same wallet.
CREATE UNIQUE INDEX "uidx_key_scopes_wallet_purpose_coin" 
    ON "key_scopes" ("wallet_id", "purpose", "coin_type");

-- Accounts table to store different accounts under each key scope.
CREATE TABLE "accounts" (
    -- DB ID of the account, primary key.
    "id" UUID PRIMARY KEY,
    
    -- Reference to the key scope this account belongs to.
    "scope_id" UUID NOT NULL,
    
    -- Account number described in BIP44.
    "account_number" BIGINT NOT NULL,
    
    -- Human friendly name for the account.
    "name" TEXT NOT NULL,

    -- Encrypted public key for the account.
    "encrypted_public_key" BYTEA NOT NULL,
    
    -- Encrypted private key for the account (if not watch-only).
    "encrypted_private_key" BYTEA,
    
    -- Master fingerprint is the fingerprint of the master pub key that created
    -- this account.
    "master_fingerprint" BYTEA NOT NULL
);

-- Foreign key from accounts to key_scopes.
ALTER TABLE "accounts" ADD FOREIGN KEY ("scope_id") 
    REFERENCES "key_scopes" ("id") ON DELETE CASCADE;

-- Index on foreign scope_id for faster lookups and joins.
CREATE INDEX "idx_accounts_scope" ON "accounts" ("scope_id");

-- Unique index to prevent duplicate account numbers within the same key scope.
CREATE UNIQUE INDEX "uidx_accounts_scope_account_number" 
    ON "accounts" ("scope_id", "account_number");

-- Unique index to prevent duplicate account names within the same key scope.
CREATE UNIQUE INDEX "uidx_accounts_scope_name" 
    ON "accounts" ("scope_id", "name");

-- Addresses table to store addresses (e.g. HD-derived, imported) under each
-- account.
CREATE TABLE "addresses" (
    -- DB ID of the address, primary key.
    "id" UUID PRIMARY KEY,
    
    -- Reference to the account this address belongs to.
    "account_id" UUID NOT NULL,
    
    -- Represents the type of address. This is handled in the app layer.
    -- e.g. 0 for HD chain and 3 for P2WSH.
    "type" SMALLINT NOT NULL,
    
    -- Timestamp of when the address was added to the wallet.
    "add_time" INTEGER NOT NULL,
    
    -- Current sync status of the address. Handled in the app layer.
    "sync_status" SMALLINT NOT NULL,

    -- Timestamp of when the address was first seen on the blockchain. Null if
    -- never seen.
    "first_seen_time" INTEGER,
    
    -- Branch derivation if is HD Chain address.
    "address_branch" BIGINT,
    
    -- Index derivation if is HD Chain address.
    "address_index" BIGINT,
    
    -- Encrypted public key if is imported address.
    "encrypted_pub_key" BYTEA,
    
    -- Encrypted private key if is imported address.
    "encrypted_priv_key" BYTEA,

    -- Encrypted address hash if is Script address.
    "encrypted_hash" BYTEA,
    
    -- Encrypted script if is Script address.
    "encrypted_script" BYTEA,

    -- Witness version if is Witness.
    "witness_version" SMALLINT,
    
    -- Denotes whether the script is considered to be "secret" and encrypted
    -- with the script encryption key or "public" and therefore only encrypted
    -- with the public encryption key.
    "is_secret_script" BOOLEAN
);

-- Foreign key from addresses to accounts.
ALTER TABLE "addresses" ADD FOREIGN KEY ("account_id") 
    REFERENCES "accounts" ("id") ON DELETE CASCADE;

-- Index on foreign account_id for faster lookups and joins.
CREATE INDEX "idx_addresses_account" ON "addresses" ("account_id");

-- Unique index to prevent duplicate address derivations within the same
-- account.
CREATE UNIQUE INDEX "uidx_addresses_branch_index" 
    ON "addresses" ("account_id", "address_branch", "address_index")
    WHERE type = 0 AND "address_branch" IS NOT NULL 
    AND "address_index" IS NOT NULL;
```

### Address Types

The `addresses` table uses integer constants to classify different address
types, defined at the application layer:

```
0 = HD chain address
1 = Imported address
2 = Script address
3 = Witness script address
4 = Taproot script address
```

### Synchronization Status

The blockchain synchronization state for each address is tracked using these
values, defined at the application layer:

```
0 = none (sync not started to this address)
1 = partial (still needs to be synced, but already has some data)
2 = full (sync completed)
```
