-- Wallet identity precedes owned block metadata so its foreign key can bind.
--
-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.
CREATE TABLE wallets (
    -- DB ID of the wallet, primary key. Only used for DB level relations.
    id INTEGER PRIMARY KEY,

    -- Human friendly name for the wallet.
    wallet_name TEXT NOT NULL,

    -- Defines if the wallet was imported, all its accounts would also be imported.
    is_imported BOOLEAN NOT NULL,

    -- Version of the wallet manager that created this wallet.
    manager_version INTEGER NOT NULL,

    -- Defines if the wallet is a watch-only wallet.
    is_watch_only BOOLEAN NOT NULL,

    -- Master HD public key of the wallet. NULL for certain wallet types that
    -- don't store extended public keys. Stored plaintext per ADR 0009
    -- (docs/developer/adr/0009-single-passphrase-encryption.md).
    master_hd_pub_key BLOB
);

-- Unique index to prevent duplicate wallet names.
CREATE UNIQUE INDEX uidx_wallets_name ON wallets (wallet_name);

-- Enforce that the watch-only status chosen at wallet creation time remains
-- immutable. This closes the database-boundary hole where a raw wallet update
-- could silently bypass the secret-table triggers by flipping the parent
-- wallet between watch-only and spendable after insert.
CREATE TRIGGER trg_assert_wallet_is_watch_only_immutable
BEFORE UPDATE OF is_watch_only ON wallets
FOR EACH ROW
WHEN new.is_watch_only != old.is_watch_only
BEGIN
    SELECT raise(ABORT, 'wallet is_watch_only cannot be changed after creation');
END;

-- Each Wallet retains its own chain view until its worker processes reorgs.
-- A replacement at one height must not overwrite another Wallet's history.
CREATE TABLE wallet_blocks (
    wallet_id INTEGER NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,
    block_height INTEGER NOT NULL CHECK (block_height >= 0),
    header_hash BLOB NOT NULL CHECK (length(header_hash) = 32),
    block_timestamp INTEGER NOT NULL CHECK (block_timestamp >= 0),
    PRIMARY KEY (wallet_id, block_height),
    UNIQUE (wallet_id, header_hash)
);
