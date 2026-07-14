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
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8,
    $9, $10, $11, $12, $13, $14, $15, $16
);

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
WHERE wallet_id = $1 AND scope_id = $2 AND address_hash = $3;

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
WHERE s.wallet_id = $1 AND s.purpose = $2 AND s.coin_type = $3
  AND a.address_hash = $4;

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
WHERE scope_id = $1 AND account_number = $2
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
WHERE s.wallet_id = $1 AND s.purpose = $2 AND s.coin_type = $3
  AND a.account_number = $4
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
WHERE s.wallet_id = $1 AND s.purpose = $2 AND s.coin_type = $3
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
    sqlc.arg('address_hash')::BYTEA,
    sqlc.arg('account_number')::BIGINT,
    sqlc.arg('address_type')::SMALLINT,
    sqlc.arg('added_at')::BIGINT,
    sqlc.arg('sync_status')::SMALLINT,
    sqlc.narg('branch')::BIGINT,
    sqlc.narg('address_index')::BIGINT,
    sqlc.narg('encrypted_pub_key')::BYTEA,
    sqlc.narg('encrypted_priv_key')::BYTEA,
    sqlc.narg('encrypted_hash')::BYTEA,
    sqlc.narg('encrypted_script')::BYTEA,
    sqlc.narg('witness_version')::SMALLINT,
    sqlc.narg('is_secret_script')::BOOLEAN,
    sqlc.arg('used')::BOOLEAN
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
WHERE wallet_id = $1 AND scope_id = $2 AND address_hash = $3;

-- name: DeleteAddressPrivateKeys :execrows
UPDATE addresses
SET
    encrypted_priv_key = NULL,
    encrypted_script = CASE
        WHEN address_type = 2 THEN NULL
        WHEN address_type = 3 AND is_secret_script = TRUE THEN NULL
        ELSE encrypted_script
    END
WHERE wallet_id = $1;
