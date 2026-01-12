-- name: LockAccountScope :exec
-- Acquires a transaction-level advisory lock to serialize account creation within a scope.
-- The lock is automatically released upon transaction commit or rollback.
-- This MUST be called immediately before 'CreateDerivedAccount' within the same transaction.
--
-- We explicitly use a two-statement pattern because single-statement CTE/Join
-- approaches failed to prevent race conditions during concurrent account generation.
-- The following "one-query" strategies were tested and proven unreliable:
--
-- 1. CTE with CROSS/INNER JOIN: The PostgreSQL optimizer may evaluate the
--    MAX(account_number) subquery using a snapshot taken before the lock CTE
--    is fully processed, leading to duplicate account numbers.
--
-- 2. CTE with OFFSET 0: Designed to force materialization, this still fails to
--    guarantee that the lock is held before the aggregate subquery begins its
--    read operation.
--
-- 3. FOR UPDATE in Subqueries: Since FOR UPDATE targets existing rows, it fails
--    to "lock the gap" for new inserts or handle empty tables, allowing
--    concurrent processes to calculate identical MAX() values.
--
-- Using two separate calls ensures the application pauses until
-- LockAccountScope returns, guaranteeing that the subsequent SELECT MAX()
-- operates inside a strictly serialized execution window for that scope.
SELECT pg_advisory_xact_lock(hashtextextended('account_scope', $1::BIGINT));


-- name: CreateDerivedAccount :one
-- Creates a new derived account under the given scope, computing the next
-- account number atomically. The caller MUST call LockAccountScope first
-- to acquire the advisory lock and prevent race conditions.
-- See LockAccountScope comments for why this is a separate statement.
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
    $1,
    (
        SELECT coalesce(max(account_number), -1) + 1
        FROM accounts
        WHERE scope_id = $1
    ),
    $2, $3, $4, $5, $6
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
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.is_watch_only,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    count(*) FILTER (WHERE addr.address_branch IS NULL AND addr.id IS NOT NULL) AS imported_key_count
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
LEFT JOIN addresses AS addr ON a.id = addr.account_id
WHERE a.scope_id = $1 AND a.account_name = $2
GROUP BY a.id, ks.id;

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
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    count(*) FILTER (WHERE addr.address_branch IS NULL AND addr.id IS NOT NULL) AS imported_key_count
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
LEFT JOIN addresses AS addr ON a.id = addr.account_id
WHERE a.scope_id = $1 AND a.account_number = $2
GROUP BY a.id, ks.id;

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
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    count(*) FILTER (WHERE addr.address_branch IS NULL AND addr.id IS NOT NULL) AS imported_key_count
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
LEFT JOIN addresses AS addr ON a.id = addr.account_id
WHERE
    ks.wallet_id = $1
    AND ks.purpose = $2
    AND ks.coin_type = $3
    AND a.account_name = $4
GROUP BY a.id, ks.id;

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
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    count(*) FILTER (WHERE addr.address_branch IS NULL AND addr.id IS NOT NULL) AS imported_key_count
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
LEFT JOIN addresses AS addr ON a.id = addr.account_id
WHERE
    ks.wallet_id = $1
    AND ks.purpose = $2
    AND ks.coin_type = $3
    AND a.account_number = $4
GROUP BY a.id, ks.id;

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
    ks.external_type_id,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    count(*) FILTER (WHERE addr.address_branch IS NULL AND addr.id IS NOT NULL) AS imported_key_count
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
LEFT JOIN addresses AS addr ON a.id = addr.account_id
WHERE a.id = $1
GROUP BY a.id, ks.id;

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
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    count(*) FILTER (WHERE addr.address_branch IS NULL AND addr.id IS NOT NULL) AS imported_key_count
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
LEFT JOIN addresses AS addr ON a.id = addr.account_id
WHERE a.scope_id = $1
GROUP BY a.id, ks.id
ORDER BY a.account_number NULLS LAST;

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
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    count(*) FILTER (WHERE addr.address_branch IS NULL AND addr.id IS NOT NULL) AS imported_key_count
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
LEFT JOIN addresses AS addr ON a.id = addr.account_id
WHERE
    ks.wallet_id = $1
    AND ks.purpose = $2
    AND ks.coin_type = $3
GROUP BY a.id, ks.id
ORDER BY a.account_number NULLS LAST;

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
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    count(*) FILTER (WHERE addr.address_branch IS NULL AND addr.id IS NOT NULL) AS imported_key_count
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
LEFT JOIN addresses AS addr ON a.id = addr.account_id
WHERE ks.wallet_id = $1 AND a.account_name = $2
GROUP BY a.id, ks.id
ORDER BY a.account_number NULLS LAST;

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
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    count(*) FILTER (WHERE addr.address_branch IS NULL AND addr.id IS NOT NULL) AS imported_key_count
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
LEFT JOIN addresses AS addr ON a.id = addr.account_id
WHERE ks.wallet_id = $1
GROUP BY a.id, ks.id
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
VALUES ($1, $2, $3, $4, $5)
RETURNING id, account_number, created_at;

-- name: GetAndIncrementNextExternalIndex :one
-- Atomically gets the next external address index and increments the counter.
-- Returns the current index value (before incrementing) for the address derivation.
UPDATE accounts
SET next_external_index = next_external_index + 1
WHERE id = $1
RETURNING (next_external_index - 1)::BIGINT AS address_index;

-- name: GetAndIncrementNextInternalIndex :one
-- Atomically gets the next internal/change address index and increments the counter.
-- Returns the current index value (before incrementing) for the address derivation.
UPDATE accounts
SET next_internal_index = next_internal_index + 1
WHERE id = $1
RETURNING (next_internal_index - 1)::BIGINT AS address_index;

-- name: UpdateAccountNextExternalIndex :exec
-- Updates the next_external_index counter for an account. Used in tests
-- to set up specific index scenarios.
UPDATE accounts
SET next_external_index = $2
WHERE id = $1;

-- name: UpdateAccountNextInternalIndex :exec
-- Updates the next_internal_index counter for an account. Used in tests
-- to set up specific index scenarios.
UPDATE accounts
SET next_internal_index = $2
WHERE id = $1;
