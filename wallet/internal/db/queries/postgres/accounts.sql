-- name: CreateDerivedAccount :one
-- Creates a new derived account under the given scope, allocating a fresh
-- sequential account number from key_scopes.last_account_number.
-- The allocation is atomic: the UPDATE takes the row lock on the scope row,
-- returns the allocated number, and updates the counter for the next call.
WITH allocated_number AS (
    UPDATE key_scopes
    SET last_account_number = last_account_number + 1
    WHERE key_scopes.id = $1
    RETURNING key_scopes.id, last_account_number AS account_number
)

INSERT INTO accounts (
    scope_id,
    account_number,
    account_name,
    origin_id,
    encrypted_public_key,
    master_fingerprint,
    is_watch_only
)
SELECT
    allocated_number.id AS scope_id,
    allocated_number.account_number,
    $2 AS account_name,
    $3 AS origin_id,
    $4 AS encrypted_public_key,
    $5 AS master_fingerprint,
    $6 AS is_watch_only
FROM allocated_number
RETURNING accounts.id, accounts.account_number, accounts.created_at;

-- name: CreateImportedAccount :one
-- Creates a new imported account under the given scope with NULL account
-- number. Imported accounts don't follow BIP44 derivation, so they don't need
-- a sequential account number.
INSERT INTO accounts (
    scope_id,
    account_number,
    account_name,
    origin_id,
    encrypted_public_key,
    master_fingerprint,
    is_watch_only
)
VALUES ($1, NULL, $2, $3, $4, $5, $6)
RETURNING id, created_at;

-- name: CreateAccountSecret :exec
-- Inserts the encrypted private key material for an account.
INSERT INTO account_secrets (
    account_id,
    encrypted_private_key
) VALUES (
    $1, $2
);

-- name: GetAccountByScopeAndName :one
-- Returns a single account by scope id and account name.
SELECT
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE a.scope_id = $1 AND a.account_name = $2;

-- name: GetAccountByScopeAndNumber :one
-- Returns a single account by scope id and account number.
SELECT
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE a.scope_id = $1 AND a.account_number = $2;

-- name: GetAccountByWalletScopeAndName :one
-- Returns a single account by wallet id, scope tuple, and account name.
SELECT
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE
    ks.wallet_id = $1
    AND ks.purpose = $2
    AND ks.coin_type = $3
    AND a.account_name = $4;

-- name: GetAccountByWalletScopeAndNumber :one
-- Returns a single account by wallet id, scope tuple, and account number.
SELECT
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE
    ks.wallet_id = $1
    AND ks.purpose = $2
    AND ks.coin_type = $3
    AND a.account_number = $4;

-- name: GetAccountPropsById :one
-- Returns full account properties by account id.
SELECT
    a.account_number,
    a.account_name,
    a.origin_id,
    a.encrypted_public_key,
    a.master_fingerprint,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    ks.internal_type_id,
    ks.external_type_id
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE a.id = $1;

-- name: ListAccountsByScope :many
-- Lists all accounts in a scope, ordered by account number. Imported accounts
-- (with NULL account_number) appear last.
SELECT
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE a.scope_id = $1
ORDER BY a.account_number NULLS LAST;

-- name: ListAccountsByWalletScope :many
-- Lists all accounts for a wallet and scope tuple, ordered by account number.
-- Imported accounts (with NULL account_number) appear last.
SELECT
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE
    ks.wallet_id = $1
    AND ks.purpose = $2
    AND ks.coin_type = $3
ORDER BY a.account_number NULLS LAST;

-- name: ListAccountsByWalletAndName :many
-- Lists all accounts for a wallet filtered by account name, ordered by account
-- number. Imported accounts (with NULL account_number) appear last.
SELECT
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE ks.wallet_id = $1 AND a.account_name = $2
ORDER BY a.account_number NULLS LAST;

-- name: ListAccountsByWallet :many
-- Lists all accounts for a wallet, ordered by account number. Imported
-- accounts (with NULL account_number) appear last.
SELECT
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE ks.wallet_id = $1
ORDER BY a.account_number NULLS LAST;

-- name: UpdateAccountNameByWalletScopeAndNumber :execrows
-- Renames an account identified by wallet id, scope tuple, and account number.
UPDATE accounts
SET account_name = sqlc.arg(new_name)
WHERE
    scope_id IN (
        SELECT id
        FROM key_scopes
        WHERE
            wallet_id = sqlc.arg(wallet_id)
            AND purpose = sqlc.arg(purpose)
            AND coin_type = sqlc.arg(coin_type)
    )
    AND account_number = sqlc.arg(account_number);

-- name: UpdateAccountNameByWalletScopeAndName :execrows
-- Renames an account identified by wallet id, scope tuple, and current account name.
UPDATE accounts
SET account_name = sqlc.arg(new_name)
WHERE
    scope_id IN (
        SELECT id
        FROM key_scopes
        WHERE
            wallet_id = sqlc.arg(wallet_id)
            AND purpose = sqlc.arg(purpose)
            AND coin_type = sqlc.arg(coin_type)
    )
    AND account_name = sqlc.arg(old_name);
