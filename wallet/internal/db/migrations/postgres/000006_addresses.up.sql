-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

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

    -- Reference to the account this address belongs to.
    account_id BIGINT NOT NULL,

    -- Script pubkey that locks funds on-chain (stored in plaintext).
    script_pub_key BYTEA NOT NULL,

    -- Reference to the address type (e.g., P2PKH, P2WPKH, P2TR). Determines
    -- how the address is encoded and how funds can be spent.
    type_id SMALLINT NOT NULL,

    -- Branch number in BIP44 derivation path (typically 0 for external, 1 for
    -- internal/change). NULL for imported addresses.
    address_branch BIGINT,

    -- Index number in BIP44 derivation path (sequential counter within each
    -- branch). NULL for imported addresses.
    address_index BIGINT,

    -- Public key for imported addresses (stored in plaintext). NULL for
    -- HD-derived addresses since their public keys are derived from the
    -- account key.
    pub_key BYTEA,

    -- Timestamp when the address was created. Automatically set by the database.
    created_at TIMESTAMP NOT NULL DEFAULT current_timestamp,

    -- Foreign key constraint to accounts. Using ON DELETE RESTRICT to ensure
    -- that the account cannot be deleted if addresses still exist.
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE RESTRICT,

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

-- Unique index to prevent duplicate script_pub_key within the same account.
CREATE UNIQUE INDEX uidx_addresses_account_script_pub_key
ON addresses (account_id, script_pub_key);

-- Index on script_pub_key for efficient lookups by script pubkey.
-- Used by GetAddressByScriptPubKey.
CREATE INDEX idx_addresses_script_pub_key ON addresses (script_pub_key);

-- Address Secrets table stores sensitive encrypted material needed to spend
-- from an address. This table has a one-to-one relationship with addresses.
-- Watch-only addresses may have no row in this table.
CREATE TABLE address_secrets (
    -- Reference to the address these secrets belong to.
    address_id BIGINT NOT NULL,

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

-- Unique index to ensure one-to-one relationship between address and its
-- secrets.
CREATE UNIQUE INDEX uidx_address_secrets_address
ON address_secrets (address_id);
