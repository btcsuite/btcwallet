-- name: CreateKeyScope :one
INSERT INTO key_scopes (
    wallet_id,
    purpose,
    coin_type,
    encrypted_coin_pub_key,
    encrypted_coin_priv_key,
    external_addr_type,
    internal_addr_type
) VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: GetKeyScope :one
SELECT
    id,
    wallet_id,
    purpose,
    coin_type,
    encrypted_coin_pub_key,
    encrypted_coin_priv_key,
    last_account_number,
    external_addr_type,
    internal_addr_type
FROM key_scopes
WHERE wallet_id = ? AND purpose = ? AND coin_type = ?;

-- name: UpdateKeyScopeKeys :execrows
UPDATE key_scopes
SET
    encrypted_coin_pub_key = ?,
    encrypted_coin_priv_key = ?
WHERE id = ? AND wallet_id = ?;

-- name: UpdateLastAccountNumber :execrows
UPDATE key_scopes
SET last_account_number = ?
WHERE id = ? AND wallet_id = ?;
