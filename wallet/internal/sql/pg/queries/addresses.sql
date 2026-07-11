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

-- name: MarkAddressUsed :execrows
UPDATE addresses
SET used = TRUE
WHERE wallet_id = $1 AND scope_id = $2 AND address_hash = $3;
