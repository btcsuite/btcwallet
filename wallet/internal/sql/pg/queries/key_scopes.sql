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

-- name: ListKeyScopes :many
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
WHERE wallet_id = $1
ORDER BY purpose, coin_type;

-- name: PutKeyScope :one
INSERT INTO key_scopes (
    wallet_id,
    purpose,
    coin_type,
    encrypted_coin_pub_key,
    encrypted_coin_priv_key,
    last_account_number,
    external_addr_type,
    internal_addr_type
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (wallet_id, purpose, coin_type) DO UPDATE SET
    encrypted_coin_pub_key = excluded.encrypted_coin_pub_key,
    encrypted_coin_priv_key = excluded.encrypted_coin_priv_key,
    last_account_number = excluded.last_account_number,
    external_addr_type = excluded.external_addr_type,
    internal_addr_type = excluded.internal_addr_type
RETURNING id;

-- name: UpdateKeyScopeKeys :execrows
UPDATE key_scopes
SET
    encrypted_coin_pub_key = $1,
    encrypted_coin_priv_key = $2
WHERE id = $3 AND wallet_id = $4;

-- name: DeleteKeyScopePrivateKeys :execrows
UPDATE key_scopes
SET encrypted_coin_priv_key = NULL
WHERE wallet_id = $1;

-- name: UpdateLastAccountNumber :execrows
UPDATE key_scopes
SET last_account_number = $1
WHERE id = $2 AND wallet_id = $3;

-- name: AllocateAccountNumber :execrows
-- AllocateAccountNumber advances the scope's last allocated account to
-- new_account, but only while it still equals expected_account, so allocating a
-- new account number is an optimistic compare-and-swap. The absent last-account
-- sentinel is stored as NULL, so the guard coalesces NULL to the sentinel value
-- 4294967295. It affects no row when the scope is missing or the expected value
-- no longer matches.
UPDATE key_scopes
SET last_account_number = sqlc.arg('new_account')
WHERE wallet_id = sqlc.arg('wallet_id')
    AND purpose = sqlc.arg('purpose')
    AND coin_type = sqlc.arg('coin_type')
    AND coalesce(last_account_number, 4294967295) = sqlc.arg('expected_account');
