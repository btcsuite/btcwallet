# WAddrmgr SQL Schema

This document defines the schema design for the wallet address manager.

### Overview

The schema follows a hierarchical structure with proper foreign key relationships:

```
wallets (1:N) key_scopes (1:N) accounts (1:N) addresses
   |             |               |               |
   |             |               |               |-- address_secrets (1:1)
   |             |               |
   |             |               |-- account_keys (1:1)
   |             |
   |             |-- key_scope_keys (1:1)
   |
   |-- wallet_keys (1:1)
   |
   |-- wallet_sync_states (1:1)

blocks
   |
   |-- Referenced by: wallet_sync_states, addresses
```

This structure ensures that:

- Each wallet can have multiple key scopes (BIP44, BIP49, BIP84, etc.)
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
    |-- (encrypted keys)    -> wallet_keys (FK: wallet_id)
|-- sync/                   -> wallet_sync_states (FK: wallet_id)
|-- scope-schema/           -> key_scopes (FK: wallet_id)  
|-- scope/<purpose>-<coin>/ -> key_scopes (FK: wallet_id)
    |-- meta/               -> key_scopes (metadata)
    |-- (encrypted keys)    -> key_scope_keys (FK: scope_id)
    |-- acct/               -> accounts (FK: scope_id)
        |-- (encrypted keys)-> account_keys (FK: account_id)
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
CREATE TABLE "addr_blocks" (
    -- Blockchain block height, primary key.
    "height" INTEGER PRIMARY KEY,
    
    -- Hash of the block.
    "hash" BYTEA NOT NULL,
    
    -- Timestamp of the block.
    "timestamp" INTEGER NOT NULL
);

-- Unique index for fast lookup and prevent duplicate block hashes.
CREATE UNIQUE INDEX "addr_uidx_blocks_hash" ON "addr_blocks" ("hash");

-- Unique index for fast lookup and prevent duplicate block timestamps.
CREATE UNIQUE INDEX "addr_uidx_blocks_timestamp" ON "addr_blocks" ("timestamp");

-- Wallets table to store non-sensitive data.
CREATE TABLE "addr_wallets" (
    -- DB ID of the wallet, primary key. Only used for DB level relations.
    "id" UUID PRIMARY KEY,
    
    -- Human friendly name for the wallet.
    "name" TEXT NOT NULL,

    -- Human friendly origin, e.g. "imported", "generated", etc.
    "origin" TEXT NOT NULL,
    
    -- Version of the wallet manager that created this wallet.
    "manager_version" SMALLINT NOT NULL,
    
    -- Defines if the wallet is a watch-only wallet.
    "is_watch_only" BOOLEAN NOT NULL
);

-- Unique index to prevent duplicate wallet names.
CREATE UNIQUE INDEX "addr_uidx_wallets_name" ON "addr_wallets" ("name");

-- Wallet Keys table to store rarely accessed, highly sensitive encrypted key
-- material with a strict one-to-one relationship with the wallets table.
CREATE TABLE "addr_wallet_keys" (
    -- Reference to the wallet these keys belong to.
    "wallet_id" UUID NOT NULL,
    
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
    
    FOREIGN KEY (wallet_id) REFERENCES addr_wallets(id) ON DELETE CASCADE
);

-- Unique index to ensure one-to-one relationship between wallet and its keys.
CREATE UNIQUE INDEX "addr_uidx_wallet_keys_wallet" ON "addr_wallet_keys" ("wallet_id");

-- Wallet Sync States table to store the synchronization state of each wallet.
-- This is kept separate from the wallets table to avoid bloating it with
-- frequently changing data.
CREATE TABLE "addr_wallet_sync_states" (
    -- Reference to the wallet this sync state belongs to.
    "wallet_id" UUID NOT NULL,
    
    -- Current sync status of the wallet (references blocks table).
    "synced_height" INTEGER,

    -- Birthday block height of the wallet (references blocks table).
    "birthday_height" INTEGER REFERENCES addr_blocks(height),
    
    -- Indicates if the birthday block has been verified.
    "birthday_verified" BOOLEAN NOT NULL,
    
    -- Last updated timestamp to track changes.
    "updated_at" INTEGER NOT NULL,
    
    FOREIGN KEY (wallet_id) REFERENCES addr_wallets(id) ON DELETE CASCADE,
    FOREIGN KEY (synced_height) REFERENCES addr_blocks(height) 
        ON DELETE SET NULL
);

-- Unique index to ensure one-to-one relationship between wallet and its sync
-- state.
CREATE UNIQUE INDEX "addr_uidx_wallet_sync_states_wallet" 
    ON "addr_wallet_sync_states" ("wallet_id");

-- Key Scopes table to store different key scopes (BIP standards) for each
-- wallet.
CREATE TABLE "addr_key_scopes" (
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

    FOREIGN KEY (wallet_id) REFERENCES addr_wallets(id) ON DELETE CASCADE
);

-- Index on foreign wallet_id for faster lookups and joins. Probably not needed
-- because with just one or a few wallets the cardinality is low, but added for
-- completeness.
CREATE INDEX "addr_idx_key_scopes_wallet" ON "addr_key_scopes" ("wallet_id");

-- Unique index to prevent duplicate key scopes for the same wallet.
CREATE UNIQUE INDEX "addr_uidx_key_scopes_wallet_purpose_coin" 
    ON "addr_key_scopes" ("wallet_id", "purpose", "coin_type");

-- Key Scope Keys table to hold encrypted coin-type keys for each scope.
CREATE TABLE "addr_key_scope_keys" (
    -- Reference to the key scope these keys belong to.
    "scope_id" UUID NOT NULL,
    
    -- Encrypted key used to derive public keys for this scope.
    "encrypted_coin_pub_key" BYTEA NOT NULL,
    
    -- Encrypted key used to derive private keys for this scope.
    "encrypted_coin_priv_key" BYTEA,
    
    FOREIGN KEY (scope_id) REFERENCES addr_key_scopes(id) ON DELETE CASCADE
);

-- Unique index to ensure one-to-one relationship between key scope and its
-- keys.
CREATE UNIQUE INDEX "addr_uidx_key_scope_keys_scope" 
    ON "addr_key_scope_keys" ("scope_id");

-- Accounts table to store different accounts under each key scope.
CREATE TABLE "addr_accounts" (
    -- DB ID of the account, primary key.
    "id" UUID PRIMARY KEY,
    
    -- Reference to the key scope this account belongs to.
    "scope_id" UUID NOT NULL,

    -- Account number described in BIP44.
    "account_number" BIGINT NOT NULL,
    
    -- Human friendly name for the account.
    "name" TEXT NOT NULL,

    -- Human friendly origin, e.g. "imported", "generated", etc.
    "origin" TEXT NOT NULL,

    -- Master fingerprint is the fingerprint of the master pub key that created
    -- this account.
    "master_fingerprint" BYTEA NOT NULL,
    
    FOREIGN KEY (scope_id) REFERENCES addr_key_scopes(id) ON DELETE CASCADE
);

-- Index on foreign scope_id for faster lookups and joins.
CREATE INDEX "addr_idx_accounts_scope" ON "addr_accounts" ("scope_id");

-- Unique index to prevent duplicate account numbers within the same key scope.
CREATE UNIQUE INDEX "addr_uidx_accounts_scope_account_number" 
    ON "addr_accounts" ("scope_id", "account_number");

-- Unique index to prevent duplicate account names within the same key scope.
CREATE UNIQUE INDEX "addr_uidx_accounts_scope_name" 
    ON "addr_accounts" ("scope_id", "name");

-- Account Keys table to hold encrypted account-level keys.
CREATE TABLE "addr_account_keys" (
    -- Reference to the account these keys belong to.
    "account_id" UUID NOT NULL,
    
    -- Encrypted public key for the account.
    "encrypted_public_key" BYTEA NOT NULL,
    
    -- Encrypted private key for the account (NULL for watch-only origins).
    "encrypted_private_key" BYTEA,
    
    FOREIGN KEY (account_id) REFERENCES addr_accounts(id) ON DELETE CASCADE
);

-- Unique index to ensure one-to-one relationship between account and its keys.
CREATE UNIQUE INDEX "addr_uidx_account_keys_account" 
    ON "addr_account_keys" ("account_id");

-- Addresses table to store addresses (e.g. HD-derived, imported) under each
-- account.
CREATE TABLE "addr_addresses" (
    -- DB ID of the address, primary key.
    "id" UUID PRIMARY KEY,
    
    -- Reference to the account this address belongs to.
    "account_id" UUID NOT NULL,
    
    -- Represents the type of address. This is handled in the app layer.
    -- e.g. 0 for HD chain and 3 for P2WSH.
    "type" SMALLINT NOT NULL,

    -- Current sync status of the address. Handled in the app layer.
    "sync_status" SMALLINT NOT NULL,

    -- Block height of when the address was first seen on the blockchain. Null
    -- if never seen. References the blocks table.
    "first_seen_height" INTEGER,
    
    -- Branch derivation if is HD Chain address.
    "address_branch" BIGINT,
    
    -- Index derivation if is HD Chain address.
    "address_index" BIGINT,

    -- Witness version if is Witness.
    "witness_version" SMALLINT,
    
    FOREIGN KEY (account_id) REFERENCES addr_accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (first_seen_height) REFERENCES addr_blocks(height) 
        ON DELETE SET NULL
);

-- Index on foreign account_id for faster lookups and joins.
CREATE INDEX "addr_idx_addresses_account" ON "addr_addresses" ("account_id");

-- Unique index to prevent duplicate address derivations within the same
-- account.
CREATE UNIQUE INDEX "addr_uidx_addresses_branch_index"
    ON "addr_addresses" ("account_id", "address_branch", "address_index")
    WHERE type = 0 AND "address_branch" IS NOT NULL
        AND "address_index" IS NOT NULL;

-- Address Secrets table to hold sensitive encrypted material needed to spend
-- from an address.
CREATE TABLE "addr_address_secrets" (
    -- Reference to the address these secrets belong to.
    "address_id" UUID NOT NULL,
    
    -- Encrypted public key if is imported address.
    "encrypted_pub_key" BYTEA,
    
    -- Encrypted private key if is imported address.
    "encrypted_priv_key" BYTEA,

    -- Encrypted address hash if is Script address.
    "encrypted_hash" BYTEA,
    
    -- Encrypted script if is Script address.
    "encrypted_script" BYTEA,
    
    -- Denotes whether the script is considered to be "secret" and encrypted
    -- with the script encryption key or "public" and therefore only encrypted
    -- with the public encryption key.
    "is_secret_script" BOOLEAN,
    
    FOREIGN KEY (address_id) REFERENCES addr_addresses(id) ON DELETE CASCADE
);

-- Unique index to ensure one-to-one relationship between address and its
-- secrets.
CREATE UNIQUE INDEX "addr_uidx_address_secrets_address" 
    ON "addr_address_secrets" ("address_id");
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
