-- name: CreateDerivedAccount :one
-- Creates a new derived account under the given scope using a separately
-- allocated account number.
INSERT INTO accounts (
    wallet_id,
    scope_id,
    account_number,
    account_name,
    origin_id,
    public_key,
    master_fingerprint
)
SELECT
    ks.wallet_id,
    ks.id AS scope_id,
    sqlc.arg('account_number') AS account_number,
    sqlc.arg('account_name') AS account_name,
    sqlc.arg('origin_id') AS origin_id,
    sqlc.arg('public_key') AS public_key,
    sqlc.arg('master_fingerprint') AS master_fingerprint
FROM key_scopes AS ks
WHERE ks.id = sqlc.arg('scope_id')
RETURNING id, account_number, created_at;

-- name: CreateImportedAccount :one
-- Creates a new imported account under the given scope with NULL account
-- number. Imported accounts don't follow BIP44 derivation, so they don't need
-- a sequential account number.
INSERT INTO accounts (
    wallet_id,
    scope_id,
    account_number,
    account_name,
    origin_id,
    public_key,
    master_fingerprint
)
SELECT
    ks.wallet_id,
    ks.id AS scope_id,
    NULL AS account_number,
    sqlc.arg('account_name') AS account_name,
    sqlc.arg('origin_id') AS origin_id,
    sqlc.arg('public_key') AS public_key,
    sqlc.arg('master_fingerprint') AS master_fingerprint
FROM key_scopes AS ks
WHERE ks.id = sqlc.arg('scope_id')
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
    a.created_at,
    ks.purpose,
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.imported_key_count,
    a.public_key,
    a.master_fingerprint,
    w.master_hd_pub_key AS wallet_master_hd_pub_key,
    w.is_watch_only AS wallet_is_watch_only,
    CASE
        WHEN w.is_watch_only THEN TRUE
        WHEN a.origin_id = 1 AND acs.account_id IS NULL THEN TRUE
        ELSE FALSE
    END AS is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN account_secrets AS acs ON a.id = acs.account_id
WHERE a.scope_id = $1 AND a.account_name = $2;

-- name: GetAccountByScopeAndNumber :one
-- Returns a single account by scope id and account number.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.imported_key_count,
    a.public_key,
    a.master_fingerprint,
    w.master_hd_pub_key AS wallet_master_hd_pub_key,
    w.is_watch_only AS wallet_is_watch_only,
    CASE
        WHEN w.is_watch_only THEN TRUE
        WHEN a.origin_id = 1 AND acs.account_id IS NULL THEN TRUE
        ELSE FALSE
    END AS is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN account_secrets AS acs ON a.id = acs.account_id
WHERE a.scope_id = $1 AND a.account_number = $2;

-- name: GetAccountByWalletScopeAndName :one
-- Returns a single account by wallet id, scope tuple, and account name.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.imported_key_count,
    a.public_key,
    a.master_fingerprint,
    w.master_hd_pub_key AS wallet_master_hd_pub_key,
    w.is_watch_only AS wallet_is_watch_only,
    CASE
        WHEN w.is_watch_only THEN TRUE
        WHEN a.origin_id = 1 AND acs.account_id IS NULL THEN TRUE
        ELSE FALSE
    END AS is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN account_secrets AS acs ON a.id = acs.account_id
WHERE
    ks.wallet_id = $1
    AND ks.purpose = $2
    AND ks.coin_type = $3
    AND a.account_name = $4;

-- name: GetAccountByWalletScopeAndNumber :one
-- Returns a single account by wallet id, scope tuple, and account number.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.imported_key_count,
    a.public_key,
    a.master_fingerprint,
    w.master_hd_pub_key AS wallet_master_hd_pub_key,
    w.is_watch_only AS wallet_is_watch_only,
    CASE
        WHEN w.is_watch_only THEN TRUE
        WHEN a.origin_id = 1 AND acs.account_id IS NULL THEN TRUE
        ELSE FALSE
    END AS is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN account_secrets AS acs ON a.id = acs.account_id
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
    a.public_key,
    a.master_fingerprint,
    w.master_hd_pub_key AS wallet_master_hd_pub_key,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.imported_key_count,
    CASE
        WHEN w.is_watch_only THEN TRUE
        WHEN a.origin_id = 1 AND acs.account_id IS NULL THEN TRUE
        ELSE FALSE
    END AS is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN account_secrets AS acs ON a.id = acs.account_id
WHERE a.id = $1;

-- name: ListAccountsByScope :many
-- Lists all accounts in a scope, ordered by account number. Imported accounts
-- (with NULL account_number) appear last.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.imported_key_count,
    a.public_key,
    a.master_fingerprint,
    w.master_hd_pub_key AS wallet_master_hd_pub_key,
    w.is_watch_only AS wallet_is_watch_only,
    CASE
        WHEN w.is_watch_only THEN TRUE
        WHEN a.origin_id = 1 AND acs.account_id IS NULL THEN TRUE
        ELSE FALSE
    END AS is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN account_secrets AS acs ON a.id = acs.account_id
WHERE a.scope_id = $1
ORDER BY a.account_number NULLS LAST;

-- name: ListAccountsByWalletScope :many
-- Lists all accounts for a wallet and scope tuple, ordered by account number.
-- Imported accounts (with NULL account_number) appear last.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.imported_key_count,
    a.public_key,
    a.master_fingerprint,
    w.master_hd_pub_key AS wallet_master_hd_pub_key,
    w.is_watch_only AS wallet_is_watch_only,
    CASE
        WHEN w.is_watch_only THEN TRUE
        WHEN a.origin_id = 1 AND acs.account_id IS NULL THEN TRUE
        ELSE FALSE
    END AS is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN account_secrets AS acs ON a.id = acs.account_id
WHERE
    ks.wallet_id = $1
    AND ks.purpose = $2
    AND ks.coin_type = $3
ORDER BY a.account_number NULLS LAST;

-- name: ListAccountsByWalletAndName :many
-- Lists all accounts for a wallet filtered by account name, ordered by account
-- number. Imported accounts (with NULL account_number) appear last.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.imported_key_count,
    a.public_key,
    a.master_fingerprint,
    w.master_hd_pub_key AS wallet_master_hd_pub_key,
    w.is_watch_only AS wallet_is_watch_only,
    CASE
        WHEN w.is_watch_only THEN TRUE
        WHEN a.origin_id = 1 AND acs.account_id IS NULL THEN TRUE
        ELSE FALSE
    END AS is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN account_secrets AS acs ON a.id = acs.account_id
WHERE ks.wallet_id = $1 AND a.account_name = $2
ORDER BY a.account_number NULLS LAST;

-- name: ListAccountsByWallet :many
-- Lists all accounts for a wallet, ordered by account number. Imported
-- accounts (with NULL account_number) appear last.
SELECT
    a.id,
    a.account_number,
    a.account_name,
    a.origin_id,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.imported_key_count,
    a.public_key,
    a.master_fingerprint,
    w.master_hd_pub_key AS wallet_master_hd_pub_key,
    w.is_watch_only AS wallet_is_watch_only,
    CASE
        WHEN w.is_watch_only THEN TRUE
        WHEN a.origin_id = 1 AND acs.account_id IS NULL THEN TRUE
        ELSE FALSE
    END AS is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN account_secrets AS acs ON a.id = acs.account_id
WHERE ks.wallet_id = $1
ORDER BY a.account_number NULLS LAST;

-- name: UpdateAccountNameByWalletScopeAndNumber :execrows
-- Renames an account identified by wallet id, scope tuple, and account number.
UPDATE accounts
SET account_name = sqlc.arg(new_name)
WHERE
    scope_id IN (
        SELECT key_scopes.id
        FROM key_scopes
        WHERE
            key_scopes.wallet_id = sqlc.arg('wallet_id')
            AND key_scopes.purpose = sqlc.arg('purpose')
            AND key_scopes.coin_type = sqlc.arg('coin_type')
    )
    AND account_number = sqlc.arg(account_number);

-- name: UpdateAccountNameByWalletScopeAndName :execrows
-- Renames an account identified by wallet id, scope tuple, and current account name.
UPDATE accounts
SET account_name = sqlc.arg(new_name)
WHERE
    scope_id IN (
        SELECT key_scopes.id
        FROM key_scopes
        WHERE
            key_scopes.wallet_id = sqlc.arg('wallet_id')
            AND key_scopes.purpose = sqlc.arg('purpose')
            AND key_scopes.coin_type = sqlc.arg('coin_type')
    )
    AND account_name = sqlc.arg(old_name);

-- name: CreateDerivedAccountWithNumber :one
-- Test-only: Creates a derived account with a specific account number.
-- Used for testing account number overflow without creating billions of accounts.
INSERT INTO accounts (
    wallet_id,
    scope_id,
    account_number,
    account_name,
    origin_id
)
SELECT
    ks.wallet_id,
    ks.id AS scope_id,
    sqlc.arg('account_number') AS account_number,
    sqlc.arg('account_name') AS account_name,
    sqlc.arg('origin_id') AS origin_id
FROM key_scopes AS ks
WHERE ks.id = sqlc.arg('scope_id')
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

-- name: AccountBalance :one
-- AccountBalance returns the confirmed/unconfirmed balance for one
-- account, summed from the wallet's UTXO set at read time. Confirmed
-- means the funding tx is in a block at or below the wallet's synced
-- height; unconfirmed covers unmined and above-synced-tip outputs.
-- Spent outputs (`u.spent_by_tx_id IS NOT NULL`) are excluded.
SELECT
    coalesce(sum(
        CASE
            WHEN
                t.block_height IS NOT NULL
                AND s.synced_height IS NOT NULL
                AND t.block_height <= s.synced_height
                THEN u.amount
            ELSE 0
        END
    ), 0)::BIGINT AS confirmed_balance,
    coalesce(sum(
        CASE
            WHEN
                t.block_height IS NULL
                OR s.synced_height IS NULL
                OR t.block_height > s.synced_height
                THEN u.amount
            ELSE 0
        END
    ), 0)::BIGINT AS unconfirmed_balance
FROM utxos AS u
INNER JOIN transactions AS t ON u.tx_id = t.id
INNER JOIN addresses AS addr ON u.address_id = addr.id
LEFT JOIN wallet_sync_states AS s ON t.wallet_id = s.wallet_id
WHERE
    addr.wallet_id = $1
    AND addr.account_id = $2
    AND u.spent_by_tx_id IS NULL
    AND t.tx_status IN (0, 1);

-- name: AccountBalancesByIDs :many
-- AccountBalancesByIDs returns the confirmed/unconfirmed balance for each
-- account in account_ids that has funded UTXOs, grouped by account_id. Accounts with no
-- spendable outputs do not appear in the result; the Go caller defaults
-- missing entries to zero. The confirmation predicate matches
-- AccountBalance.
SELECT
    addr.account_id,
    coalesce(sum(
        CASE
            WHEN
                t.block_height IS NOT NULL
                AND s.synced_height IS NOT NULL
                AND t.block_height <= s.synced_height
                THEN u.amount
            ELSE 0
        END
    ), 0)::BIGINT AS confirmed_balance,
    coalesce(sum(
        CASE
            WHEN
                t.block_height IS NULL
                OR s.synced_height IS NULL
                OR t.block_height > s.synced_height
                THEN u.amount
            ELSE 0
        END
    ), 0)::BIGINT AS unconfirmed_balance
FROM utxos AS u
INNER JOIN transactions AS t ON u.tx_id = t.id
INNER JOIN addresses AS addr ON u.address_id = addr.id
LEFT JOIN wallet_sync_states AS s ON t.wallet_id = s.wallet_id
WHERE
    addr.wallet_id = sqlc.arg('wallet_id')
    AND addr.account_id = any(sqlc.arg('account_ids')::BIGINT [])
    AND u.spent_by_tx_id IS NULL
    AND t.tx_status IN (0, 1)
GROUP BY addr.account_id;
