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
    id BIGSERIAL PRIMARY KEY,

    -- Reference to the wallet this address belongs to.
    wallet_id BIGINT NOT NULL,

    -- Reference to the account this address belongs to.
    account_id BIGINT NOT NULL,

    -- Script pubkey that locks funds on-chain (stored in plaintext per ADR 0009:
    -- docs/developer/adr/0009-single-passphrase-encryption.md).
    script_pub_key BYTEA NOT NULL,

    -- Reference to the address type (e.g., P2PKH, P2WPKH, P2TR). Determines
    -- how the address is encoded and how funds can be spent.
    type_id SMALLINT NOT NULL,

    -- Branch number in BIP44 derivation path. We currently use only 0
    -- (external) and 1 (internal/change), so SMALLINT is sufficient. This can
    -- be widened to BIGINT later with ALTER COLUMN if branch semantics expand.
    -- NULL for imported addresses.
    address_branch SMALLINT,

    -- Index number in BIP44 derivation path (sequential counter within each
    -- branch). NULL for imported addresses.
    address_index BIGINT,

    -- Public key for imported addresses (stored in plaintext per ADR 0009:
    -- docs/developer/adr/0009-single-passphrase-encryption.md). NULL for
    -- HD-derived addresses since their public keys are derived from the
    -- account key.
    pub_key BYTEA,

    -- Timestamp when the address was created. Automatically set by the database
    -- in UTC.
    created_at TIMESTAMP NOT NULL DEFAULT (current_timestamp AT TIME ZONE 'UTC'),

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
WHERE address_branch IS NOT NULL
AND address_index IS NOT NULL;

-- Unique index to prevent duplicate script_pub_key within the same wallet.
CREATE UNIQUE INDEX uidx_addresses_wallet_script_pub_key
ON addresses (wallet_id, script_pub_key);

-- Index on (account_id, id) for efficient pagination of addresses by account.
-- Used by ListAddressesByAccount for cursor-based pagination.
CREATE INDEX idx_addresses_account_id ON addresses (account_id, id);

-- Enforce that wallet ownership chosen at address creation time remains
-- immutable. This closes the database-boundary hole where a raw update could
-- reparent an existing address into another wallet after insert.
CREATE FUNCTION assert_address_wallet_id_immutable() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.wallet_id IS DISTINCT FROM OLD.wallet_id THEN
        RAISE EXCEPTION 'address wallet_id cannot be changed after creation'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_address_wallet_id_immutable
BEFORE UPDATE OF wallet_id ON addresses
FOR EACH ROW
EXECUTE FUNCTION assert_address_wallet_id_immutable();

-- Address Secrets table stores sensitive encrypted material needed to spend
-- from an address. This table has a one-to-one relationship with addresses.
-- Watch-only addresses may have no row in this table.
CREATE TABLE address_secrets (
    -- Reference to the address these secrets belong to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    address_id BIGINT PRIMARY KEY,

    -- Encrypted private key for imported addresses. NULL for HD-derived
    -- addresses since their private keys are derived from the account key.
    encrypted_priv_key BYTEA,

    -- Encrypted script for script-based addresses (P2SH, P2WSH). Contains the
    -- redeem script or witness script needed to spend the output.
    encrypted_script BYTEA,

    -- Foreign key constraint to addresses. Using ON DELETE RESTRICT to ensure
    -- that the address cannot be deleted if secrets still exist.
    FOREIGN KEY (address_id) REFERENCES addresses (id) ON DELETE RESTRICT
);

-- Enforce the watch-only address secret invariant at the database boundary.
-- Watch-only parent wallets may track imported scripts, but addresses
-- beneath them must not store private keys; otherwise a watch-only parent could
-- silently gain spend authority through an address secret row.
CREATE FUNCTION assert_watch_only_address_secrets() RETURNS TRIGGER AS $$
DECLARE
    wallet_is_watch_only BOOLEAN;
BEGIN
    IF NEW.encrypted_priv_key IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT w.is_watch_only INTO wallet_is_watch_only
    FROM addresses AS addr
    INNER JOIN wallets AS w ON w.id = addr.wallet_id
    WHERE addr.id = NEW.address_id;

    IF wallet_is_watch_only THEN
        RAISE EXCEPTION 'watch-only address parents cannot store private keys'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_watch_only_address_secrets_insert
BEFORE INSERT ON address_secrets
FOR EACH ROW
EXECUTE FUNCTION assert_watch_only_address_secrets();

CREATE TRIGGER trg_assert_watch_only_address_secrets_update
BEFORE UPDATE ON address_secrets
FOR EACH ROW
EXECUTE FUNCTION assert_watch_only_address_secrets();

-- Increments imported_key_count for imported address inserts.
CREATE FUNCTION sync_account_imported_key_count_insert() RETURNS TRIGGER AS $$
BEGIN
    UPDATE accounts
    SET imported_key_count = imported_key_count + 1
    WHERE id = NEW.account_id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to keep imported_key_count accurate for imported address inserts.
CREATE TRIGGER trg_addresses_imported_key_count_insert
AFTER INSERT ON addresses
FOR EACH ROW
WHEN (new.address_branch IS NULL)
EXECUTE FUNCTION sync_account_imported_key_count_insert();

-- Decrements imported_key_count for imported address deletes.
CREATE FUNCTION sync_account_imported_key_count_delete() RETURNS TRIGGER AS $$
BEGIN
    UPDATE accounts
    SET imported_key_count = imported_key_count - 1
    WHERE id = OLD.account_id;

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- Trigger to keep imported_key_count accurate for imported address deletes.
CREATE TRIGGER trg_addresses_imported_key_count_delete
AFTER DELETE ON addresses
FOR EACH ROW
WHEN (old.address_branch IS NULL)
EXECUTE FUNCTION sync_account_imported_key_count_delete();
