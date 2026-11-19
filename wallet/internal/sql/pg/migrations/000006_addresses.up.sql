-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- This table intentionally does NOT include a `used` column.
-- An address's used-ness is derived from the utxos table
-- (EXISTS(SELECT 1 FROM utxos WHERE address_id = ?)). The derivation
-- is monotonic because utxo rows are preserved through reorgs via
-- tx_status soft-delete (see ADR 0006) and ON DELETE RESTRICT. See
-- ADR 0011 for the full design rationale.
--
-- Addresses table stores wallet-local address identity. HD derivation path and
-- owning account data live in derived_addresses; raw imports have an addresses
-- row without a derived_addresses child.
CREATE TABLE addresses (
    -- DB ID of the address, primary key.
    id BIGSERIAL PRIMARY KEY,

    -- Reference to the wallet this address belongs to.
    wallet_id BIGINT NOT NULL,

    -- Shape marker. TRUE means this address must have a derived_addresses child
    -- row with account ownership and BIP44 path data. Raw imported addresses
    -- leave this FALSE.
    is_derived BOOLEAN NOT NULL,

    -- Script pubkey that locks funds on-chain (stored in plaintext per ADR 0009:
    -- docs/developer/adr/0009-single-passphrase-encryption.md).
    script_pub_key BYTEA NOT NULL,

    -- Reference to the script type (e.g., P2PKH, P2WPKH, P2TR). Determines how
    -- the address is encoded and how funds can be spent.
    script_type_id SMALLINT NOT NULL,

    -- Public key for raw imported addresses (stored in plaintext per ADR 0009:
    -- docs/developer/adr/0009-single-passphrase-encryption.md). NULL for
    -- HD-derived addresses since their public keys are derived from the
    -- account key.
    pub_key BYTEA,

    -- Timestamp when the address was created. Automatically set by the database
    -- in UTC.
    created_at TIMESTAMP NOT NULL DEFAULT (current_timestamp AT TIME ZONE 'UTC'),

    -- Foreign key constraint to wallets. Raw imported addresses are wallet-
    -- local script identities and do not have key-scope derivation identity.
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,

    -- Foreign key constraint to address types. Using ON DELETE RESTRICT to
    -- ensure that the script type cannot be deleted if addresses still exist.
    FOREIGN KEY (script_type_id) REFERENCES address_types (id) ON DELETE RESTRICT
);

-- Unique index to prevent duplicate script_pub_key within the same wallet.
CREATE UNIQUE INDEX uidx_addresses_wallet_script_pub_key
ON addresses (wallet_id, script_pub_key);

-- Unique index to support composite foreign keys from derived_addresses.
CREATE UNIQUE INDEX uidx_addresses_id_wallet
ON addresses (id, wallet_id);

-- Index for raw-import address listing by wallet.
CREATE INDEX idx_addresses_wallet_derived_id
ON addresses (wallet_id, is_derived, id);

-- Derived Addresses table stores HD child ownership and path data.
CREATE TABLE derived_addresses (
    -- Reference to the parent address. Also serves as the primary key,
    -- enforcing one derived address row per address.
    address_id BIGINT PRIMARY KEY,

    -- Duplicate of addresses.wallet_id for account/address drift checks.
    wallet_id BIGINT NOT NULL,

    -- Reference to the account this derived address belongs to.
    account_id BIGINT NOT NULL,

    -- Branch number in BIP44 derivation path. We currently use only 0
    -- (external) and 1 (internal/change), so SMALLINT is sufficient. This can
    -- be widened to BIGINT later with ALTER COLUMN if branch semantics expand.
    address_branch SMALLINT NOT NULL,

    -- Index number in BIP44 derivation path.
    address_index BIGINT NOT NULL,

    -- Branch must be a BIP44 branch number.
    CHECK (address_branch IN (0, 1)),

    -- Address index must be non-negative.
    CHECK (address_index >= 0),

    -- Foreign key constraint to addresses. Using ON DELETE RESTRICT to ensure
    -- that the address cannot be deleted if derived identity still exists.
    FOREIGN KEY (address_id) REFERENCES addresses (id) ON DELETE RESTRICT,

    -- Foreign key constraint to accounts. Using ON DELETE RESTRICT to ensure
    -- that the account cannot be deleted if addresses still exist.
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE RESTRICT,

    -- Composite foreign key to ensure duplicated wallet_id matches the parent
    -- address row.
    FOREIGN KEY (address_id, wallet_id)
    REFERENCES addresses (id, wallet_id) ON DELETE RESTRICT,

    -- Composite foreign key to ensure derived address account ownership matches
    -- the address wallet. Scope is inherited from the owning account.
    FOREIGN KEY (account_id, wallet_id)
    REFERENCES accounts (id, wallet_id) ON DELETE RESTRICT
);

-- Unique index to prevent duplicate address derivations within the same account.
CREATE UNIQUE INDEX uidx_derived_addresses_account_branch_index
ON derived_addresses (account_id, address_branch, address_index);

-- Index for efficient pagination of addresses by wallet and account.
CREATE INDEX idx_derived_addresses_wallet_account_address
ON derived_addresses (wallet_id, account_id, address_id);

-- Narrow index for account-address joins when wallet_id is already known.
CREATE INDEX idx_derived_addresses_account_address
ON derived_addresses (account_id, address_id);

-- Enforce that structural address identity fields chosen at address creation
-- time remain immutable.
CREATE FUNCTION assert_address_identity_immutable() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.wallet_id IS DISTINCT FROM OLD.wallet_id
        OR NEW.is_derived IS DISTINCT FROM OLD.is_derived THEN

        RAISE EXCEPTION 'address identity cannot be changed after creation'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_address_identity_immutable
BEFORE UPDATE OF id, wallet_id, is_derived ON addresses
FOR EACH ROW
EXECUTE FUNCTION assert_address_identity_immutable();

-- Enforce that only addresses marked as derived can receive path/account rows.
CREATE FUNCTION assert_derived_address_parent() RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM addresses AS addr
        WHERE
            addr.id = NEW.address_id
            AND addr.wallet_id = NEW.wallet_id
            AND addr.is_derived
    ) THEN
        RAISE EXCEPTION 'derived address parent must be marked derived'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_derived_address_parent_insert
BEFORE INSERT ON derived_addresses
FOR EACH ROW
EXECUTE FUNCTION assert_derived_address_parent();

-- Derived address identity/path rows are allocated once and never retargeted.
CREATE FUNCTION reject_derived_address_update() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'derived address identity cannot be changed after creation'
        USING ERRCODE = '23514'; -- check_violation
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_reject_derived_address_update
BEFORE UPDATE ON derived_addresses
FOR EACH ROW
EXECUTE FUNCTION reject_derived_address_update();

-- Address Secrets table stores sensitive encrypted material needed to spend
-- from an address. This table has a one-to-one relationship with addresses.
-- Watch-only addresses may have no row in this table.
CREATE TABLE address_secrets (
    -- Reference to the address these secrets belong to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    address_id BIGINT PRIMARY KEY,

    -- Encrypted private key for raw imported addresses. NULL for HD-derived
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
