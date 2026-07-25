-- name: CreateAddress :exec
INSERT INTO addresses (
    wallet_id,
    scope_id,
    address_hash,
    account_number,
    address_type,
    added_at,
    sync_status,
    branch,
    address_index,
    encrypted_pub_key,
    encrypted_priv_key,
    encrypted_hash,
    encrypted_script,
    witness_version,
    is_secret_script,
    used
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAddress :one
SELECT
    wallet_id,
    scope_id,
    address_hash,
    account_number,
    address_type,
    added_at,
    sync_status,
    branch,
    address_index,
    encrypted_pub_key,
    encrypted_priv_key,
    encrypted_hash,
    encrypted_script,
    witness_version,
    is_secret_script,
    used
FROM addresses
WHERE wallet_id = ? AND scope_id = ? AND address_hash = ?;

-- name: GetManagerAddress :one
SELECT
    a.wallet_id,
    a.scope_id,
    a.address_hash,
    a.account_number,
    a.address_type,
    a.added_at,
    a.sync_status,
    a.branch,
    a.address_index,
    a.encrypted_pub_key,
    a.encrypted_priv_key,
    a.encrypted_hash,
    a.encrypted_script,
    a.witness_version,
    a.is_secret_script,
    a.used
FROM addresses AS a
INNER JOIN key_scopes AS s ON s.id = a.scope_id
WHERE s.wallet_id = ? AND s.purpose = ? AND s.coin_type = ?
  AND a.address_hash = ?;

-- name: ListAccountAddresses :many
SELECT
    wallet_id,
    scope_id,
    address_hash,
    account_number,
    address_type,
    added_at,
    sync_status,
    branch,
    address_index,
    encrypted_pub_key,
    encrypted_priv_key,
    encrypted_hash,
    encrypted_script,
    witness_version,
    is_secret_script,
    used
FROM addresses
WHERE scope_id = ? AND account_number = ?
ORDER BY address_hash;

-- name: ListManagerAccountAddresses :many
SELECT
    a.wallet_id,
    a.scope_id,
    a.address_hash,
    a.account_number,
    a.address_type,
    a.added_at,
    a.sync_status,
    a.branch,
    a.address_index,
    a.encrypted_pub_key,
    a.encrypted_priv_key,
    a.encrypted_hash,
    a.encrypted_script,
    a.witness_version,
    a.is_secret_script,
    a.used
FROM addresses AS a
INNER JOIN key_scopes AS s ON s.id = a.scope_id
WHERE s.wallet_id = ? AND s.purpose = ? AND s.coin_type = ?
  AND a.account_number = ?
ORDER BY a.address_hash;

-- name: ListManagerActiveAddresses :many
SELECT
    a.wallet_id,
    a.scope_id,
    a.address_hash,
    a.account_number,
    a.address_type,
    a.added_at,
    a.sync_status,
    a.branch,
    a.address_index,
    a.encrypted_pub_key,
    a.encrypted_priv_key,
    a.encrypted_hash,
    a.encrypted_script,
    a.witness_version,
    a.is_secret_script,
    a.used
FROM addresses AS a
INNER JOIN key_scopes AS s ON s.id = a.scope_id
WHERE s.wallet_id = ? AND s.purpose = ? AND s.coin_type = ?
ORDER BY a.address_hash;

-- name: PutManagerAddress :execrows
INSERT INTO addresses (
    wallet_id,
    scope_id,
    address_hash,
    account_number,
    address_type,
    added_at,
    sync_status,
    branch,
    address_index,
    encrypted_pub_key,
    encrypted_priv_key,
    encrypted_hash,
    encrypted_script,
    witness_version,
    is_secret_script,
    used
)
SELECT
    s.wallet_id,
    s.id,
    sqlc.arg('address_hash'),
    sqlc.arg('account_number'),
    sqlc.arg('address_type'),
    sqlc.arg('added_at'),
    sqlc.arg('sync_status'),
    cast(sqlc.narg('branch') AS INTEGER),
    cast(sqlc.narg('address_index') AS INTEGER),
    sqlc.narg('encrypted_pub_key'),
    sqlc.narg('encrypted_priv_key'),
    sqlc.narg('encrypted_hash'),
    sqlc.narg('encrypted_script'),
    cast(sqlc.narg('witness_version') AS INTEGER),
    sqlc.narg('is_secret_script'),
    sqlc.arg('used')
FROM key_scopes AS s
WHERE s.wallet_id = sqlc.arg('wallet_id')
  AND s.purpose = sqlc.arg('purpose')
  AND s.coin_type = sqlc.arg('coin_type')
ON CONFLICT (wallet_id, scope_id, address_hash) DO UPDATE SET
    account_number = excluded.account_number,
    address_type = excluded.address_type,
    added_at = excluded.added_at,
    sync_status = excluded.sync_status,
    branch = excluded.branch,
    address_index = excluded.address_index,
    encrypted_pub_key = excluded.encrypted_pub_key,
    encrypted_priv_key = excluded.encrypted_priv_key,
    encrypted_hash = excluded.encrypted_hash,
    encrypted_script = excluded.encrypted_script,
    witness_version = excluded.witness_version,
    is_secret_script = excluded.is_secret_script,
    used = excluded.used;

-- name: MarkAddressUsed :execrows
UPDATE addresses
SET used = TRUE
WHERE wallet_id = ? AND scope_id = ? AND address_hash = ?;

-- name: DeleteAddressPrivateKeys :execrows
UPDATE addresses
SET
    encrypted_priv_key = NULL,
    encrypted_script = CASE
        WHEN address_type = 2 THEN NULL
        WHEN address_type IN (3, 4) AND is_secret_script = TRUE THEN NULL
        ELSE encrypted_script
    END
WHERE wallet_id = ?;
