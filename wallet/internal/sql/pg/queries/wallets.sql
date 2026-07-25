-- name: CreateWallet :one
INSERT INTO wallets (
    wallet_name,
    manager_version,
    manager_created_at,
    is_watch_only,
    master_pub_params,
    master_priv_params,
    encrypted_crypto_pub_key,
    encrypted_crypto_priv_key,
    encrypted_crypto_script_key,
    encrypted_master_hd_pub_key,
    encrypted_master_hd_priv_key
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id;

-- name: GetWalletByName :one
SELECT
    id,
    wallet_name,
    manager_version,
    manager_created_at,
    is_watch_only,
    master_pub_params,
    master_priv_params,
    encrypted_crypto_pub_key,
    encrypted_crypto_priv_key,
    encrypted_crypto_script_key,
    encrypted_master_hd_pub_key,
    encrypted_master_hd_priv_key
FROM wallets
WHERE wallet_name = $1;

-- name: GetManagerState :one
SELECT
    manager_version,
    manager_created_at,
    is_watch_only,
    master_pub_params,
    master_priv_params,
    encrypted_crypto_pub_key,
    encrypted_crypto_priv_key,
    encrypted_crypto_script_key,
    encrypted_master_hd_pub_key,
    encrypted_master_hd_priv_key
FROM wallets
WHERE id = $1;

-- name: UpdateWalletEncryption :execrows
UPDATE wallets
SET
    master_pub_params = $1,
    master_priv_params = $2,
    encrypted_crypto_pub_key = $3,
    encrypted_crypto_priv_key = $4,
    encrypted_crypto_script_key = $5,
    encrypted_master_hd_pub_key = $6,
    encrypted_master_hd_priv_key = $7
WHERE id = $8;

-- name: PutManagerState :execrows
UPDATE wallets
SET
    manager_version = $1,
    manager_created_at = $2,
    is_watch_only = $3,
    master_pub_params = $4,
    master_priv_params = $5,
    encrypted_crypto_pub_key = $6,
    encrypted_crypto_priv_key = $7,
    encrypted_crypto_script_key = $8,
    encrypted_master_hd_pub_key = $9,
    encrypted_master_hd_priv_key = $10
WHERE id = $11;

-- name: DeleteManagerPrivateKeys :execrows
UPDATE wallets
SET
    master_priv_params = NULL,
    encrypted_crypto_priv_key = NULL,
    encrypted_crypto_script_key = NULL,
    encrypted_master_hd_priv_key = NULL
WHERE id = $1;

-- name: PutWalletSyncState :exec
INSERT INTO wallet_sync_states (
    wallet_id,
    start_block_height,
    synced_block_height,
    birthday_timestamp,
    birthday_block_height,
    birthday_block_verified
) VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetWalletSyncState :one
SELECT
    s.wallet_id,
    s.start_block_height,
    start_block.header_hash AS start_block_hash,
    start_block.block_timestamp AS start_block_timestamp,
    s.synced_block_height,
    synced_block.header_hash AS synced_block_hash,
    synced_block.block_timestamp AS synced_block_timestamp,
    s.birthday_timestamp,
    s.birthday_block_height,
    birthday_block.header_hash AS birthday_block_hash,
    birthday_block.block_timestamp AS birthday_block_timestamp,
    s.birthday_block_verified
FROM wallet_sync_states AS s
INNER JOIN wallet_blocks AS start_block
    ON start_block.wallet_id = s.wallet_id
    AND start_block.block_height = s.start_block_height
INNER JOIN wallet_blocks AS synced_block
    ON synced_block.wallet_id = s.wallet_id
    AND synced_block.block_height = s.synced_block_height
LEFT JOIN wallet_blocks AS birthday_block
    ON birthday_block.wallet_id = s.wallet_id
    AND birthday_block.block_height = s.birthday_block_height
WHERE s.wallet_id = $1;

-- name: SetWalletBirthday :execrows
UPDATE wallet_sync_states
SET birthday_timestamp = $1
WHERE wallet_id = $2;

-- name: SetWalletBirthdayBlock :execrows
UPDATE wallet_sync_states
SET birthday_block_height = $1
WHERE wallet_id = $2;

-- name: SetWalletBirthdayBlockVerified :execrows
UPDATE wallet_sync_states
SET birthday_block_verified = $1
WHERE wallet_id = $2;

-- name: GetWalletStartBlock :one
SELECT b.block_height, b.header_hash, b.block_timestamp
FROM wallet_sync_states AS s
INNER JOIN wallet_blocks AS b
    ON b.wallet_id = s.wallet_id
    AND b.block_height = s.start_block_height
WHERE s.wallet_id = $1;

-- name: UpdateWalletSyncState :execrows
UPDATE wallet_sync_states
SET
    start_block_height = $1,
    synced_block_height = $2,
    birthday_timestamp = $3,
    birthday_block_height = $4,
    birthday_block_verified = $5
WHERE wallet_id = $6;

-- name: SetWalletSyncedTo :execrows
UPDATE wallet_sync_states
SET synced_block_height = $1
WHERE wallet_id = $2;
