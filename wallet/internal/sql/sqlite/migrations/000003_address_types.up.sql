-- Address types are the stable public waddrmgr.AddressType values used by key
-- scope address schemas.
CREATE TABLE address_types (
    id INTEGER PRIMARY KEY CHECK (id BETWEEN 0 AND 7),
    type_name TEXT NOT NULL UNIQUE
);

INSERT INTO address_types (id, type_name) VALUES
    (0, 'pubkey-hash'),
    (1, 'script'),
    (2, 'raw-pubkey'),
    (3, 'nested-witness-pubkey'),
    (4, 'witness-pubkey'),
    (5, 'witness-script'),
    (6, 'taproot-pubkey'),
    (7, 'taproot-script');
