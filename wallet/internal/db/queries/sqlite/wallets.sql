-- name: CreateWallet :one
INSERT INTO wallets (
    wallet_name,
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
    birthday,
    updated_at
) VALUES (
    ?, ?, ?, ?, current_timestamp
);

-- name: UpdateWalletSyncState :execrows
UPDATE wallet_sync_states
SET
    -- If synced_height param is NOT NULL, use it. Otherwise, keep existing value.
    synced_height = coalesce(sqlc.narg('synced_height'), synced_height),

    -- If birthday_height param is NOT NULL, use it. Otherwise, keep existing value.
    birthday_height = coalesce(sqlc.narg('birthday_height'), birthday_height),

    -- If birthday param is NOT NULL, use it. Otherwise, keep existing value.
    birthday = coalesce(sqlc.narg('birthday'), birthday),

    -- Always update timestamp to current database time.
    updated_at = current_timestamp
WHERE
    wallet_id = sqlc.arg('wallet_id');

-- name: GetWalletByName :one
SELECT
    w.id,
    w.wallet_name,
    w.is_imported,
    w.manager_version,
    w.is_watch_only,
    s.synced_height,
    s.birthday_height,
    s.birthday,
    s.updated_at,
    b_synced.header_hash AS synced_block_hash,
    b_synced.block_timestamp AS synced_block_timestamp,
    b_birthday.header_hash AS birthday_block_hash,
    b_birthday.block_timestamp AS birthday_block_timestamp
FROM wallets AS w
LEFT JOIN wallet_sync_states AS s ON w.id = s.wallet_id
LEFT JOIN blocks AS b_synced ON s.synced_height = b_synced.block_height
LEFT JOIN blocks AS b_birthday ON s.birthday_height = b_birthday.block_height
WHERE w.wallet_name = ?;

-- name: ListWallets :many
SELECT
    w.id,
    w.wallet_name,
    w.is_imported,
    w.manager_version,
    w.is_watch_only,
    s.synced_height,
    s.birthday_height,
    s.birthday,
    s.updated_at,
    b_synced.header_hash AS synced_block_hash,
    b_synced.block_timestamp AS synced_block_timestamp,
    b_birthday.header_hash AS birthday_block_hash,
    b_birthday.block_timestamp AS birthday_block_timestamp
FROM wallets AS w
LEFT JOIN wallet_sync_states AS s ON w.id = s.wallet_id
LEFT JOIN blocks AS b_synced ON s.synced_height = b_synced.block_height
LEFT JOIN blocks AS b_birthday ON s.birthday_height = b_birthday.block_height
ORDER BY w.id;

-- name: GetWalletByID :one
SELECT
    w.id,
    w.wallet_name,
    w.is_imported,
    w.manager_version,
    w.is_watch_only,
    s.synced_height,
    s.birthday_height,
    s.birthday,
    s.updated_at,
    b_synced.header_hash AS synced_block_hash,
    b_synced.block_timestamp AS synced_block_timestamp,
    b_birthday.header_hash AS birthday_block_hash,
    b_birthday.block_timestamp AS birthday_block_timestamp
FROM wallets AS w
LEFT JOIN wallet_sync_states AS s ON w.id = s.wallet_id
LEFT JOIN blocks AS b_synced ON s.synced_height = b_synced.block_height
LEFT JOIN blocks AS b_birthday ON s.birthday_height = b_birthday.block_height
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
