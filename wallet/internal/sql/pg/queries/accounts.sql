-- name: CreateAccount :exec
INSERT INTO accounts (
    wallet_id,
    scope_id,
    account_number,
    account_type,
    account_name,
    encrypted_pub_key,
    encrypted_priv_key,
    master_key_fingerprint,
    next_external_index,
    next_internal_index,
    external_addr_type,
    internal_addr_type
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetAccount :one
SELECT
    wallet_id,
    scope_id,
    account_number,
    account_type,
    account_name,
    encrypted_pub_key,
    encrypted_priv_key,
    master_key_fingerprint,
    next_external_index,
    next_internal_index,
    external_addr_type,
    internal_addr_type
FROM accounts
WHERE scope_id = $1 AND account_number = $2;

-- name: ListAccounts :many
SELECT
    wallet_id,
    scope_id,
    account_number,
    account_type,
    account_name,
    encrypted_pub_key,
    encrypted_priv_key,
    master_key_fingerprint,
    next_external_index,
    next_internal_index,
    external_addr_type,
    internal_addr_type
FROM accounts
WHERE scope_id = $1
ORDER BY account_number;

-- name: RenameAccount :execrows
UPDATE accounts
SET account_name = $1
WHERE scope_id = $2 AND account_number = $3;

-- name: UpdateAccountIndexes :execrows
UPDATE accounts
SET next_external_index = $1, next_internal_index = $2
WHERE scope_id = $3 AND account_number = $4;
