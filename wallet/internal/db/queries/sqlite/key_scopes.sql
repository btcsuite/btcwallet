-- name: CreateKeyScope :one
-- Creates a new key scope for a wallet and returns its ID.
INSERT INTO key_scopes (
    wallet_id,
    purpose,
    coin_type,
    encrypted_coin_pub_key,
    internal_type_id,
    external_type_id
) VALUES (
    ?, ?, ?, ?, ?, ?
)
RETURNING id;

-- name: InsertKeyScopeSecrets :exec
-- Inserts secrets for a key scope. encrypted_coin_priv_key may be NULL for
-- watch-only scopes.
INSERT INTO key_scope_secrets (
    scope_id,
    encrypted_coin_priv_key
) VALUES (
    ?, ?
);

-- name: GetKeyScopeByID :one
-- Retrieves a key scope by its ID.
SELECT
    id,
    wallet_id,
    purpose,
    coin_type,
    encrypted_coin_pub_key,
    internal_type_id,
    external_type_id
FROM key_scopes
WHERE id = ?;

-- name: GetKeyScopeByWalletAndScope :one
-- Retrieves a key scope by wallet ID, purpose, and coin type.
SELECT
    id,
    wallet_id,
    purpose,
    coin_type,
    encrypted_coin_pub_key,
    internal_type_id,
    external_type_id
FROM key_scopes
WHERE wallet_id = ? AND purpose = ? AND coin_type = ?;

-- name: ListKeyScopesByWallet :many
-- Lists all key scopes for a wallet, ordered by ID.
SELECT
    id,
    wallet_id,
    purpose,
    coin_type,
    encrypted_coin_pub_key,
    internal_type_id,
    external_type_id
FROM key_scopes
WHERE wallet_id = ?
ORDER BY id;

-- name: GetKeyScopeSecrets :one
-- Retrieves the secrets for a key scope.
SELECT
    scope_id,
    encrypted_coin_priv_key
FROM key_scope_secrets
WHERE scope_id = ?;

-- name: DeleteKeyScopeSecrets :execrows
-- Deletes the secrets for a key scope.
DELETE FROM key_scope_secrets
WHERE scope_id = ?;

-- name: DeleteKeyScope :execrows
-- Deletes a key scope by its ID.
DELETE FROM key_scopes
WHERE id = ?;
