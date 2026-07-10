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

-- name: MarkAddressUsed :execrows
UPDATE addresses
SET used = TRUE
WHERE wallet_id = ? AND scope_id = ? AND address_hash = ?;
