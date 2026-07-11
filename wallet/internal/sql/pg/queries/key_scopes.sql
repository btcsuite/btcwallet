-- name: CreateKeyScope :one
INSERT INTO key_scopes (
    wallet_id,
    purpose,
    coin_type,
    encrypted_coin_pub_key,
    encrypted_coin_priv_key,
    external_addr_type,
    internal_addr_type
) VALUES ($1, $2, $3, $4, $5, $6, $7)
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
WHERE wallet_id = $1 AND purpose = $2 AND coin_type = $3;

-- name: UpdateKeyScopeKeys :execrows
UPDATE key_scopes
SET
    encrypted_coin_pub_key = $1,
    encrypted_coin_priv_key = $2
WHERE id = $3 AND wallet_id = $4;

-- name: UpdateLastAccountNumber :execrows
UPDATE key_scopes
SET last_account_number = $1
WHERE id = $2 AND wallet_id = $3;
