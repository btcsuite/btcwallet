-- Accounts preserve the two stable legacy account encodings. Every account,
-- including an imported watch-only account, retains its uint32 account number.
CREATE TABLE accounts (
    wallet_id INTEGER NOT NULL,
    scope_id INTEGER NOT NULL,
    account_number INTEGER NOT NULL
        CHECK (account_number BETWEEN 0 AND 4294967295),
    account_type INTEGER NOT NULL CHECK (account_type IN (0, 1)),
    account_name TEXT NOT NULL,
    encrypted_pub_key BLOB NOT NULL,
    encrypted_priv_key BLOB,
    master_key_fingerprint INTEGER
        CHECK (
            master_key_fingerprint IS NULL
            OR master_key_fingerprint BETWEEN 0 AND 4294967295
        ),
    next_external_index INTEGER NOT NULL DEFAULT 0
        CHECK (next_external_index BETWEEN 0 AND 4294967295),
    next_internal_index INTEGER NOT NULL DEFAULT 0
        CHECK (next_internal_index BETWEEN 0 AND 4294967295),
    external_addr_type INTEGER,
    internal_addr_type INTEGER,
    FOREIGN KEY (scope_id, wallet_id) REFERENCES key_scopes (id, wallet_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (external_addr_type) REFERENCES address_types (id)
        ON DELETE RESTRICT,
    FOREIGN KEY (internal_addr_type) REFERENCES address_types (id)
        ON DELETE RESTRICT,
    PRIMARY KEY (scope_id, account_number),
    UNIQUE (scope_id, account_name),
    UNIQUE (scope_id, account_number, wallet_id),
    CHECK (
        (external_addr_type IS NULL AND internal_addr_type IS NULL)
        OR (external_addr_type IS NOT NULL AND internal_addr_type IS NOT NULL)
    ),
    CHECK (
        (account_type = 0
            AND master_key_fingerprint IS NULL
            AND external_addr_type IS NULL
            AND internal_addr_type IS NULL)
        OR (
            account_type = 1
            AND encrypted_priv_key IS NULL
            AND master_key_fingerprint IS NOT NULL
        )
    )
);
