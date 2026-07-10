-- Key scopes preserve encrypted coin keys and the address schema associated
-- with each purpose and coin tuple.
CREATE TABLE key_scopes (
    id INTEGER PRIMARY KEY,
    wallet_id INTEGER NOT NULL,
    purpose INTEGER NOT NULL CHECK (purpose BETWEEN 0 AND 4294967295),
    coin_type INTEGER NOT NULL CHECK (coin_type BETWEEN 0 AND 4294967295),
    encrypted_coin_pub_key BLOB,
    encrypted_coin_priv_key BLOB,
    last_account_number INTEGER
        CHECK (last_account_number BETWEEN 0 AND 4294967295),
    external_addr_type INTEGER NOT NULL,
    internal_addr_type INTEGER NOT NULL,
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,
    FOREIGN KEY (external_addr_type) REFERENCES address_types (id)
        ON DELETE RESTRICT,
    FOREIGN KEY (internal_addr_type) REFERENCES address_types (id)
        ON DELETE RESTRICT,
    UNIQUE (wallet_id, purpose, coin_type),
    UNIQUE (id, wallet_id)
);
