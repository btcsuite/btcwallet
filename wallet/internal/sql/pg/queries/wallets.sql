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
-- Block references resolve from the globally unique header hash, so the blocks
-- must already exist before this insert runs.
INSERT INTO wallet_sync_states (
    wallet_id,
    start_block_id,
    synced_block_id,
    birthday_timestamp,
    birthday_block_id,
    birthday_block_verified
) VALUES (
    sqlc.arg('wallet_id'),
    (SELECT sb.id FROM blocks AS sb WHERE sb.header_hash = sqlc.arg('start_block_hash')),
    (SELECT yb.id FROM blocks AS yb WHERE yb.header_hash = sqlc.arg('synced_block_hash')),
    sqlc.arg('birthday_timestamp'),
    (SELECT bb.id FROM blocks AS bb WHERE bb.header_hash = sqlc.narg('birthday_block_hash')),
    sqlc.arg('birthday_block_verified')
);

-- name: GetWalletSyncState :one
SELECT
    s.wallet_id,
    start_block.block_height AS start_block_height,
    start_block.header_hash AS start_block_hash,
    start_block.block_timestamp AS start_block_timestamp,
    synced_block.block_height AS synced_block_height,
    synced_block.header_hash AS synced_block_hash,
    synced_block.block_timestamp AS synced_block_timestamp,
    s.birthday_timestamp,
    birthday_block.block_height AS birthday_block_height,
    birthday_block.header_hash AS birthday_block_hash,
    birthday_block.block_timestamp AS birthday_block_timestamp,
    s.birthday_block_verified
FROM wallet_sync_states AS s
INNER JOIN blocks AS start_block
    ON start_block.id = s.start_block_id
INNER JOIN blocks AS synced_block
    ON synced_block.id = s.synced_block_id
LEFT JOIN blocks AS birthday_block
    ON birthday_block.id = s.birthday_block_id
WHERE s.wallet_id = $1;

-- name: SetWalletBirthday :execrows
UPDATE wallet_sync_states
SET birthday_timestamp = $1
WHERE wallet_id = $2;

-- name: SetWalletBirthdayBlock :execrows
UPDATE wallet_sync_states
SET birthday_block_id =
    (SELECT id FROM blocks WHERE header_hash = sqlc.narg('block_hash'))
WHERE wallet_id = sqlc.arg('wallet_id');

-- name: SetWalletBirthdayBlockVerified :execrows
UPDATE wallet_sync_states
SET birthday_block_verified = $1
WHERE wallet_id = $2;

-- name: GetWalletStartBlock :one
SELECT b.block_height, b.header_hash, b.block_timestamp
FROM wallet_sync_states AS s
INNER JOIN blocks AS b ON b.id = s.start_block_id
WHERE s.wallet_id = $1;

-- name: UpdateWalletSyncState :execrows
UPDATE wallet_sync_states
SET
    start_block_id =
        (SELECT sb.id FROM blocks AS sb WHERE sb.header_hash = sqlc.arg('start_block_hash')),
    synced_block_id =
        (SELECT yb.id FROM blocks AS yb WHERE yb.header_hash = sqlc.arg('synced_block_hash')),
    birthday_timestamp = sqlc.arg('birthday_timestamp'),
    birthday_block_id =
        (SELECT bb.id FROM blocks AS bb WHERE bb.header_hash = sqlc.narg('birthday_block_hash')),
    birthday_block_verified = sqlc.arg('birthday_block_verified')
WHERE wallet_id = sqlc.arg('wallet_id');

-- name: SetWalletSyncedTo :execrows
UPDATE wallet_sync_states
SET synced_block_id =
    (SELECT id FROM blocks WHERE header_hash = sqlc.arg('block_hash'))
WHERE wallet_id = sqlc.arg('wallet_id');

-- name: AdvanceWalletSyncedTo :execrows
-- AdvanceWalletSyncedTo advances the wallet's synced block to new_block_hash,
-- but only while the current synced block still equals expected_block_hash, so a
-- tip advance is an optimistic compare-and-swap. The new block must already
-- exist. Zero affected rows means the caller's expected tip was stale and no
-- advance was made.
UPDATE wallet_sync_states
SET synced_block_id =
    (SELECT nb.id FROM blocks AS nb WHERE nb.header_hash = sqlc.arg('new_block_hash'))
WHERE wallet_id = sqlc.arg('wallet_id')
    AND synced_block_id =
        (SELECT eb.id FROM blocks AS eb WHERE eb.header_hash = sqlc.arg('expected_block_hash'));
