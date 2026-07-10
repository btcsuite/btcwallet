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
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

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
WHERE scope_id = ? AND account_number = ?;

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
WHERE scope_id = ?
ORDER BY account_number;

-- name: RenameAccount :execrows
UPDATE accounts
SET account_name = ?
WHERE scope_id = ? AND account_number = ?;

-- name: UpdateAccountIndexes :execrows
UPDATE accounts
SET next_external_index = ?, next_internal_index = ?
WHERE scope_id = ? AND account_number = ?;
