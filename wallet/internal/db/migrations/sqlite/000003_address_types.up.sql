-- Address type lookup table - provides standardized descriptions for Bitcoin
-- address types. This is a reference table that maps the AddressType enum
-- values used in Go code to their human-readable Bitcoin protocol names.
--
-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.
CREATE TABLE address_types (
    -- Primary key matching the Go AddressType enum values.
    -- Using explicit IDs rather than auto-increment to ensure consistency
    -- with the Go enum and across SQLite/Postgres implementations.
    id INTEGER PRIMARY KEY,

    -- Human-readable Bitcoin address type description.
    -- These match standard Bitcoin protocol terminology.
    description TEXT NOT NULL
);

-- Unique constraint on description to prevent duplicate entries.
-- This ensures referential integrity and enables efficient reverse lookups.
CREATE UNIQUE INDEX uidx_address_types_description
ON address_types (description);

-- Seed reference data matching the Go AddressType enum constants.
-- These values are static and represent the Bitcoin address types.
-- IDs MUST match the iota values in wallet/internal/db/data_types.go.
INSERT INTO address_types (id, description) VALUES
(0, 'P2PK'),           -- Pay-to-PubKey
(1, 'P2PKH'),          -- Pay-to-PubKey-Hash
(2, 'P2SH'),           -- Pay-to-Script-Hash
(3, 'P2SH-P2WPKH'),    -- Nested Witness PubKey
(4, 'P2WPKH'),         -- Pay-to-Witness-PubKey-Hash
(5, 'P2WSH'),          -- Pay-to-Witness-Script-Hash
(6, 'P2TR'),           -- Pay-to-Taproot
(7, 'P2A');            -- Pay-to-Anchor
