-- name: CreateDerivedAccount :one
-- Creates a new derived account under the given scope, computing the next
-- account number from existing accounts. SQLite's _txlock=immediate ensures
-- only one writer at a time, preventing concurrent allocation conflicts.
INSERT INTO accounts (
    scope_id,
    account_number,
    account_name,
    origin_id,
    encrypted_public_key,
    master_fingerprint,
    is_watch_only
)
VALUES (
    ?1,
    (
        SELECT coalesce(max(account_number), -1) + 1 FROM accounts
        WHERE scope_id = ?1
    ),
    ?2, ?3, ?4, ?5, ?6
)
RETURNING id, account_number, created_at;

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
VALUES (?, NULL, ?, ?, ?, ?, ?)
RETURNING id, created_at;

-- name: CreateAccountSecret :exec
-- Inserts the encrypted private key material for an account.
INSERT INTO account_secrets (
    account_id,
    encrypted_private_key
) VALUES (
    ?, ?
);

-- name: GetAccountByScopeAndName :one
-- Returns a single account by scope id and account name.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE a.scope_id = ? AND a.account_name = ?;

-- name: GetAccountByScopeAndNumber :one
-- Returns a single account by scope id and account number.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE a.scope_id = ? AND a.account_number = ?;

-- name: GetAccountByWalletScopeAndName :one
-- Returns a single account by wallet id, scope tuple, and account name.
SELECT
    a.id,
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
    ks.wallet_id = ?
    AND ks.purpose = ?
    AND ks.coin_type = ?
    AND a.account_name = ?;

-- name: GetAccountByWalletScopeAndNumber :one
-- Returns a single account by wallet id, scope tuple, and account number.
SELECT
    a.id,
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
    ks.wallet_id = ?
    AND ks.purpose = ?
    AND ks.coin_type = ?
    AND a.account_number = ?;

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
WHERE a.id = ?;

-- name: ListAccountsByScope :many
-- Lists all accounts in a scope, ordered by account number. Imported accounts
-- (with NULL account_number) appear last.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE a.scope_id = ?
ORDER BY a.account_number IS NULL, a.account_number;

-- name: ListAccountsByWalletScope :many
-- Lists all accounts for a wallet and scope tuple, ordered by account number.
-- Imported accounts (with NULL account_number) appear last.
SELECT
    a.id,
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
    ks.wallet_id = ?
    AND ks.purpose = ?
    AND ks.coin_type = ?
ORDER BY a.account_number IS NULL, a.account_number;

-- name: ListAccountsByWalletAndName :many
-- Lists all accounts for a wallet filtered by account name, ordered by account
-- number. Imported accounts (with NULL account_number) appear last.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE ks.wallet_id = ? AND a.account_name = ?
ORDER BY a.account_number IS NULL, a.account_number;

-- name: ListAccountsByWallet :many
-- Lists all accounts for a wallet, ordered by account number. Imported
-- accounts (with NULL account_number) appear last.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
WHERE ks.wallet_id = ?
ORDER BY a.account_number IS NULL, a.account_number;

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

-- name: CreateDerivedAccountWithNumber :one
-- Test-only: Creates a derived account with a specific account number.
-- Used for testing account number overflow without creating billions of accounts.
INSERT INTO accounts (
    scope_id,
    account_number,
    account_name,
    origin_id,
    is_watch_only
)
VALUES (?, ?, ?, ?, ?)
RETURNING id, account_number, created_at;
