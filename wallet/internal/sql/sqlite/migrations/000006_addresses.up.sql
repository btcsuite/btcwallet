-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- This table intentionally does NOT include a `used` column.
-- An address's used-ness is derived from the utxos table
-- (EXISTS(SELECT 1 FROM utxos WHERE address_id = ?)). The derivation
-- is monotonic because utxo rows are preserved through reorgs via
-- tx_status soft-delete (see ADR 0006) and ON DELETE RESTRICT. See
-- ADR 0011 for the full design rationale.
--
-- Addresses table stores all addresses under each account. Addresses can be
-- either HD-derived (following BIP32/BIP44 derivation paths) or imported from
-- external sources (e.g., watch-only addresses, hardware wallet addresses).
--
-- The table supports both address types through nullable derivation fields:
-- - HD-derived addresses have address_branch and address_index values
-- - Imported addresses have NULL derivation fields and store pub_key
CREATE TABLE addresses (
    -- DB ID of the address, primary key.
    id INTEGER PRIMARY KEY,

    -- Reference to the wallet this address belongs to.
    wallet_id INTEGER NOT NULL,

    -- Legacy reference to the account this address belongs to. This remains
    -- non-null while legacy queries are still present.
    account_id INTEGER NOT NULL,

    -- Shape marker for the normalized identity model. TRUE means this address
    -- has normalized derived identity with account ownership and path data.
    is_derived BOOLEAN NOT NULL DEFAULT TRUE,

    -- Script pubkey that locks funds on-chain (stored in plaintext per ADR 0009:
    -- docs/developer/adr/0009-single-passphrase-encryption.md).
    script_pub_key BLOB NOT NULL,

    -- Reference to the address type (e.g., P2PKH, P2WPKH, P2TR). Determines
    -- how the address is encoded and how funds can be spent.
    type_id INTEGER NOT NULL,

    -- Branch number in BIP44 derivation path (typically 0 for external, 1 for
    -- internal/change). NULL for imported addresses.
    address_branch INTEGER,

    -- Index number in BIP44 derivation path (sequential counter within each
    -- branch). NULL for imported addresses.
    address_index INTEGER,

    -- Public key for imported addresses (stored in plaintext per ADR 0009:
    -- docs/developer/adr/0009-single-passphrase-encryption.md). NULL for
    -- HD-derived addresses since their public keys are derived from the
    -- account key.
    pub_key BLOB,

    -- Timestamp when the address was created. Automatically set by the database.
    created_at DATETIME NOT NULL DEFAULT current_timestamp,

    -- Branch and index are set together for HD-derived addresses and both
    -- NULL for imported addresses.
    CHECK ((address_branch IS NULL) = (address_index IS NULL)),

    -- Branch must be a BIP44 branch number when set.
    CHECK (address_branch IS NULL OR address_branch IN (0, 1)),

    -- Address index must be non-negative when set.
    CHECK (address_index IS NULL OR address_index >= 0),

    -- Composite foreign key to accounts. This ensures account_id belongs to
    -- the same wallet_id as the address row. Wallet ownership is transitively
    -- enforced through accounts, which has its own FK to wallets. Using ON
    -- DELETE RESTRICT to ensure that the wallet/account cannot be deleted if
    -- addresses still exist.
    FOREIGN KEY (wallet_id, account_id)
    REFERENCES accounts (wallet_id, id) ON DELETE RESTRICT,

    -- Foreign key constraint to address types. Using ON DELETE RESTRICT to
    -- ensure that the address type cannot be deleted if addresses still exist.
    FOREIGN KEY (type_id) REFERENCES address_types (id) ON DELETE RESTRICT
);

-- Unique partial index to prevent duplicate address derivations within the
-- same account. Only enforced when both branch and index are non-NULL
-- (HD-derived addresses). Imported addresses are excluded from this constraint.
CREATE UNIQUE INDEX uidx_addresses_branch_index
ON addresses (account_id, address_branch, address_index)
WHERE
    address_branch IS NOT NULL
    AND address_index IS NOT NULL;

-- Unique index to prevent duplicate script_pub_key within the same wallet.
CREATE UNIQUE INDEX uidx_addresses_wallet_script_pub_key
ON addresses (wallet_id, script_pub_key);

-- Index on (account_id, id) for efficient pagination of addresses by account.
-- Used by ListAddressesByAccount for cursor-based pagination.
CREATE INDEX idx_addresses_account_id ON addresses (account_id, id);

-- Index for normalized raw-import address listing by wallet.
CREATE INDEX idx_addresses_wallet_derived_id
ON addresses (wallet_id, is_derived, id);

-- Enforce that wallet ownership chosen at address creation time remains
-- immutable. This closes the database-boundary hole where a raw update could
-- reparent an existing address into another wallet after insert.
CREATE TRIGGER trg_assert_address_wallet_id_immutable
BEFORE UPDATE OF wallet_id ON addresses
FOR EACH ROW
WHEN new.wallet_id != old.wallet_id
BEGIN
    SELECT raise(ABORT, 'address wallet_id cannot be changed after creation');
END;

-- Address Secrets table stores sensitive encrypted material needed to spend
-- from an address. This table has a one-to-one relationship with addresses.
-- Watch-only addresses may have no row in this table.
CREATE TABLE address_secrets (
    -- Reference to the address these secrets belong to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    address_id INTEGER PRIMARY KEY,

    -- Encrypted private key for imported addresses. NULL for HD-derived
    -- addresses since their private keys are derived from the account key.
    encrypted_priv_key BLOB,

    -- Encrypted script for script-based addresses (P2SH, P2WSH). Contains the
    -- redeem script or witness script needed to spend the output.
    encrypted_script BLOB,

    -- Foreign key constraint to addresses. Using ON DELETE RESTRICT to ensure
    -- that the address cannot be deleted if secrets still exist.
    FOREIGN KEY (address_id) REFERENCES addresses (id) ON DELETE RESTRICT
);

-- Enforce the watch-only address secret invariant at the database boundary.
-- Watch-only parent wallets may track imported scripts, but addresses
-- beneath them must not store private keys; otherwise a watch-only parent could
-- silently gain spend authority through an address secret row.
CREATE TRIGGER trg_assert_watch_only_address_secrets_insert
BEFORE INSERT ON address_secrets
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'watch-only address parents cannot store private keys')
    WHERE
        new.encrypted_priv_key IS NOT NULL
        AND EXISTS (
            SELECT 1
            FROM addresses AS addr
            INNER JOIN wallets AS w ON addr.wallet_id = w.id
            WHERE
                addr.id = new.address_id
                AND w.is_watch_only
        );
END;

CREATE TRIGGER trg_assert_watch_only_address_secrets_update
BEFORE UPDATE ON address_secrets
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'watch-only address parents cannot store private keys')
    WHERE
        new.encrypted_priv_key IS NOT NULL
        AND EXISTS (
            SELECT 1
            FROM addresses AS addr
            INNER JOIN wallets AS w ON addr.wallet_id = w.id
            WHERE
                addr.id = new.address_id
                AND w.is_watch_only
        );
END;

-- Increments imported_key_count when a new imported address is inserted.
CREATE TRIGGER trg_addresses_imported_key_count_insert
AFTER INSERT ON addresses
WHEN new.address_branch IS NULL
BEGIN
    UPDATE accounts
    SET imported_key_count = imported_key_count + 1
    WHERE id = new.account_id;
END;

-- Decrements imported_key_count when an imported address is deleted.
CREATE TRIGGER trg_addresses_imported_key_count_delete
AFTER DELETE ON addresses
WHEN old.address_branch IS NULL
BEGIN
    UPDATE accounts
    SET imported_key_count = imported_key_count - 1
    WHERE id = old.account_id;
END;
