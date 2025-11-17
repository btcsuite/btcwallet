-- name: CreateWallet :one
INSERT INTO wallets (
    name,
    is_imported,
    manager_version,
    is_watch_only,
    master_pub_params,
    encrypted_crypto_pub_key,
    encrypted_master_hd_pub_key
) VALUES (
    ?, ?, ?, ?, ?, ?, ?
)
RETURNING id;

-- name: InsertWalletSyncState :exec
INSERT INTO wallet_sync_states (
    wallet_id,
    synced_height,
    birthday_height,
    birthday_verified,
    updated_at
) VALUES (
    ?, ?, ?, ?, CURRENT_TIMESTAMP
);

-- name: UpdateWalletSyncState :execrows
UPDATE wallet_sync_states
SET
    -- If synced_height param is NOT NULL, use it. Otherwise, keep existing value.
    synced_height = COALESCE(sqlc.narg('synced_height'), synced_height),

    -- If birthday_height param is NOT NULL, use it. Otherwise, keep existing value.
    birthday_height = COALESCE(sqlc.narg('birthday_height'), birthday_height),

    -- If birthday_verified param is NOT NULL, use it. Otherwise, keep existing value.
    birthday_verified = COALESCE(sqlc.narg('birthday_verified'), birthday_verified),

    -- Always update timestamp to current database time.
    updated_at = CURRENT_TIMESTAMP
WHERE
    wallet_id = sqlc.arg('wallet_id');

-- name: GetWalletByName :one
SELECT
    w.id,
    w.name,
    w.is_imported,
    w.manager_version,
    w.is_watch_only,
    s.synced_height,
    s.birthday_height,
    s.birthday_verified,
    s.updated_at,
    b_synced.header_hash AS synced_block_hash,
    b_synced.timestamp AS synced_block_timestamp,
    b_birthday.header_hash AS birthday_block_hash,
    b_birthday.timestamp AS birthday_block_timestamp
FROM wallets w
LEFT JOIN wallet_sync_states s ON s.wallet_id = w.id
LEFT JOIN blocks b_synced ON s.synced_height = b_synced.block_height
LEFT JOIN blocks b_birthday ON s.birthday_height = b_birthday.block_height
WHERE w.name = ?;

-- name: ListWallets :many
SELECT
    w.id,
    w.name,
    w.is_imported,
    w.manager_version,
    w.is_watch_only,
    s.synced_height,
    s.birthday_height,
    s.birthday_verified,
    s.updated_at,
    b_synced.header_hash AS synced_block_hash,
    b_synced.timestamp AS synced_block_timestamp,
    b_birthday.header_hash AS birthday_block_hash,
    b_birthday.timestamp AS birthday_block_timestamp
FROM wallets w
LEFT JOIN wallet_sync_states s ON s.wallet_id = w.id
LEFT JOIN blocks b_synced ON s.synced_height = b_synced.block_height
LEFT JOIN blocks b_birthday ON s.birthday_height = b_birthday.block_height
ORDER BY w.id;

-- name: GetWalletByID :one
SELECT
    w.id,
    w.name,
    w.is_imported,
    w.manager_version,
    w.is_watch_only,
    s.synced_height,
    s.birthday_height,
    s.birthday_verified,
    s.updated_at,
    b_synced.header_hash AS synced_block_hash,
    b_synced.timestamp AS synced_block_timestamp,
    b_birthday.header_hash AS birthday_block_hash,
    b_birthday.timestamp AS birthday_block_timestamp
FROM wallets w
LEFT JOIN wallet_sync_states s ON s.wallet_id = w.id
LEFT JOIN blocks b_synced ON s.synced_height = b_synced.block_height
LEFT JOIN blocks b_birthday ON s.birthday_height = b_birthday.block_height
WHERE w.id = ?;

-- name: InsertWalletSecrets :exec
INSERT INTO wallet_secrets (
    wallet_id,
    master_priv_params,
    encrypted_crypto_priv_key,
    encrypted_crypto_script_key,
    encrypted_master_hd_priv_key
) VALUES (
    ?, ?, ?, ?, ?
);

-- name: GetWalletSecrets :one
SELECT
    wallet_id,
    master_priv_params,
    encrypted_crypto_priv_key,
    encrypted_crypto_script_key,
    encrypted_master_hd_priv_key
FROM wallet_secrets
WHERE wallet_id = ?;

-- name: UpdateWalletSecrets :execrows
UPDATE wallet_secrets
SET
    master_priv_params = ?,
    encrypted_crypto_priv_key = ?,
    encrypted_crypto_script_key = ?,
    encrypted_master_hd_priv_key = ?
WHERE wallet_id = ?;
