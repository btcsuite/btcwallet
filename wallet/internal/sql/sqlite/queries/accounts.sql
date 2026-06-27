-- name: CreateDerivedAccount :one
-- Creates the parent row for a wallet-derived account under the given scope.
-- The caller inserts the BIP44 account number into derived_accounts in the same
-- transaction after this row returns its ID.
INSERT INTO accounts (
    wallet_id,
    scope_id,
    account_name,
    is_derived,
    public_key,
    master_fingerprint
)
SELECT
    ks.wallet_id,
    ks.id AS scope_id,
    sqlc.arg('account_name') AS account_name,
    TRUE AS is_derived,
    sqlc.arg('public_key') AS public_key,
    sqlc.arg('master_fingerprint') AS master_fingerprint
FROM key_scopes AS ks
WHERE ks.id = sqlc.arg('scope_id')
RETURNING id, created_at;

-- name: CreateDerivedAccountNumber :one
-- Stores the BIP44 account number for a wallet-derived account.
INSERT INTO derived_accounts (
    account_id,
    scope_id,
    account_number
)
SELECT
    a.id AS account_id,
    a.scope_id,
    sqlc.arg('account_number') AS account_number
FROM accounts AS a
WHERE a.id = sqlc.arg('account_id')
RETURNING account_number;

-- name: CreateImportedAccount :one
-- Creates a new imported xpub account under the given scope. Imported xpub
-- accounts are HD account-like rows but do not have BIP44 account numbers.
INSERT INTO accounts (
    wallet_id,
    scope_id,
    account_name,
    is_derived,
    public_key,
    master_fingerprint
)
SELECT
    ks.wallet_id,
    ks.id AS scope_id,
    sqlc.arg('account_name') AS account_name,
    FALSE AS is_derived,
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
    ?, ?
);

-- name: GetAccountByScopeAndName :one
-- Returns a single account by scope id and account name.
SELECT
    a.id,
    da.account_number,
    a.account_name,
    a.is_derived,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    ks.internal_type_id,
    ks.external_type_id,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.public_key,
    a.master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN derived_accounts AS da ON a.id = da.account_id
WHERE a.scope_id = ? AND a.account_name = ?;

-- name: GetAccountByScopeAndNumber :one
-- Returns a single derived account by scope id and account number.
SELECT
    a.id,
    da.account_number,
    a.account_name,
    a.is_derived,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    ks.internal_type_id,
    ks.external_type_id,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.public_key,
    a.master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN derived_accounts AS da ON a.id = da.account_id
WHERE a.scope_id = ? AND da.account_number = ? AND a.is_derived;

-- name: GetAccountByWalletScopeAndName :one
-- Returns a single account by wallet id, scope tuple, and account name.
SELECT
    a.id,
    da.account_number,
    a.account_name,
    a.is_derived,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    ks.internal_type_id,
    ks.external_type_id,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.public_key,
    a.master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN derived_accounts AS da ON a.id = da.account_id
WHERE
    ks.wallet_id = ?
    AND ks.purpose = ?
    AND ks.coin_type = ?
    AND a.account_name = ?;

-- name: GetAccountByWalletScopeAndNumber :one
-- Returns a single derived account by wallet id, scope tuple, and account number.
SELECT
    a.id,
    da.account_number,
    a.account_name,
    a.is_derived,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    ks.internal_type_id,
    ks.external_type_id,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.public_key,
    a.master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN derived_accounts AS da ON a.id = da.account_id
WHERE
    ks.wallet_id = ?
    AND ks.purpose = ?
    AND ks.coin_type = ?
    AND da.account_number = ?
    AND a.is_derived;

-- name: GetAccountPropsById :one
-- Returns full account properties by account id.
SELECT
    da.account_number,
    a.account_name,
    a.is_derived,
    a.public_key,
    a.master_fingerprint,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    ks.internal_type_id,
    ks.external_type_id,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    w.is_watch_only AS wallet_is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN derived_accounts AS da ON a.id = da.account_id
WHERE a.id = ?;

-- name: ListAccountsByScope :many
-- Lists all accounts in a scope. Accounts without BIP44 numbers appear last.
SELECT
    a.id,
    da.account_number,
    a.account_name,
    a.is_derived,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    ks.internal_type_id,
    ks.external_type_id,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.public_key,
    a.master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN derived_accounts AS da ON a.id = da.account_id
WHERE a.scope_id = ?
ORDER BY da.account_number IS NULL, da.account_number, a.account_name;

-- name: ListAccountsByWalletScope :many
-- Lists all accounts for a wallet and scope tuple.
SELECT
    a.id,
    da.account_number,
    a.account_name,
    a.is_derived,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    ks.internal_type_id,
    ks.external_type_id,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.public_key,
    a.master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN derived_accounts AS da ON a.id = da.account_id
WHERE
    ks.wallet_id = ?
    AND ks.purpose = ?
    AND ks.coin_type = ?
ORDER BY da.account_number IS NULL, da.account_number, a.account_name;

-- name: ListAccountsByWalletAndName :many
-- Lists all accounts for a wallet filtered by account name.
SELECT
    a.id,
    da.account_number,
    a.account_name,
    a.is_derived,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    ks.internal_type_id,
    ks.external_type_id,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.public_key,
    a.master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN derived_accounts AS da ON a.id = da.account_id
WHERE ks.wallet_id = ? AND a.account_name = ?
ORDER BY da.account_number IS NULL, da.account_number, a.account_name;

-- name: ListAccountsByWallet :many
-- Lists all accounts for a wallet.
SELECT
    a.id,
    da.account_number,
    a.account_name,
    a.is_derived,
    a.created_at,
    ks.purpose,
    ks.coin_type,
    ks.internal_type_id,
    ks.external_type_id,
    a.next_external_index AS external_key_count,
    a.next_internal_index AS internal_key_count,
    a.public_key,
    a.master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only
FROM accounts AS a
INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN derived_accounts AS da ON a.id = da.account_id
WHERE ks.wallet_id = ?
ORDER BY da.account_number IS NULL, da.account_number, a.account_name;

-- name: UpdateAccountNameByWalletScopeAndNumber :execrows
-- Renames a derived account identified by wallet id, scope tuple, and number.
UPDATE accounts
SET account_name = sqlc.arg(new_name)
WHERE
    id IN (
        SELECT da.account_id
        FROM derived_accounts AS da
        INNER JOIN accounts AS a ON da.account_id = a.id
        INNER JOIN key_scopes AS ks ON a.scope_id = ks.id
        WHERE
            ks.wallet_id = sqlc.arg('wallet_id')
            AND ks.purpose = sqlc.arg('purpose')
            AND ks.coin_type = sqlc.arg('coin_type')
            AND da.account_number = sqlc.arg('account_number')
            AND a.is_derived
    );

-- name: UpdateAccountNameByWalletScopeAndName :execrows
-- Renames an account identified by wallet id, scope tuple, and current name.
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

-- name: GetAndIncrementNextExternalIndex :one
-- Atomically gets the next external address index and increments the counter.
-- Returns the current index value (before incrementing) for the address derivation.
UPDATE accounts
SET next_external_index = next_external_index + 1
WHERE id = ?
RETURNING next_external_index - 1 AS address_index;

-- name: GetAndIncrementNextInternalIndex :one
-- Atomically gets the next internal/change address index and increments the counter.
-- Returns the current index value (before incrementing) for the address derivation.
UPDATE accounts
SET next_internal_index = next_internal_index + 1
WHERE id = ?
RETURNING next_internal_index - 1 AS address_index;

-- name: AccountBalance :one
-- AccountBalance returns the confirmed/unconfirmed balance for one account,
-- summed from the wallet's well-formed derived-address UTXO set at read time.
SELECT
    cast(coalesce(sum(
        CASE
            WHEN
                t.block_height IS NOT NULL
                AND s.synced_height IS NOT NULL
                AND t.block_height <= s.synced_height
                THEN u.amount
            ELSE 0
        END
    ), 0) AS INTEGER) AS confirmed_balance,
    cast(coalesce(sum(
        CASE
            WHEN
                t.block_height IS NULL
                OR s.synced_height IS NULL
                OR t.block_height > s.synced_height
                THEN u.amount
            ELSE 0
        END
    ), 0) AS INTEGER) AS unconfirmed_balance
FROM utxos AS u
INNER JOIN transactions AS t ON u.tx_id = t.id
INNER JOIN addresses AS a ON u.address_id = a.id
INNER JOIN derived_addresses AS da ON a.id = da.address_id
INNER JOIN accounts AS acc ON da.account_id = acc.id
LEFT JOIN derived_accounts AS dacct ON acc.id = dacct.account_id
LEFT JOIN wallet_sync_states AS s ON t.wallet_id = s.wallet_id
WHERE
    t.wallet_id = sqlc.arg('wallet_id')
    AND a.wallet_id = sqlc.arg('wallet_id')
    AND da.wallet_id = sqlc.arg('wallet_id')
    AND acc.wallet_id = sqlc.arg('wallet_id')
    AND da.account_id = sqlc.arg('account_id')
    AND u.spent_by_tx_id IS NULL
    AND t.tx_status IN (0, 1)
    AND a.is_derived
    AND da.address_id IS NOT NULL
    AND acc.id IS NOT NULL
    AND (
        (acc.is_derived AND dacct.account_number IS NOT NULL)
        OR (acc.is_derived = FALSE AND dacct.account_number IS NULL)
    );

-- name: AccountBalancesByIDs :many
-- AccountBalancesByIDs returns the confirmed/unconfirmed balance for each
-- account in account_ids that has well-formed funded UTXOs, grouped by
-- account_id.
SELECT
    da.account_id,
    cast(coalesce(sum(
        CASE
            WHEN
                t.block_height IS NOT NULL
                AND s.synced_height IS NOT NULL
                AND t.block_height <= s.synced_height
                THEN u.amount
            ELSE 0
        END
    ), 0) AS INTEGER) AS confirmed_balance,
    cast(coalesce(sum(
        CASE
            WHEN
                t.block_height IS NULL
                OR s.synced_height IS NULL
                OR t.block_height > s.synced_height
                THEN u.amount
            ELSE 0
        END
    ), 0) AS INTEGER) AS unconfirmed_balance
FROM utxos AS u
INNER JOIN transactions AS t ON u.tx_id = t.id
INNER JOIN addresses AS a ON u.address_id = a.id
INNER JOIN derived_addresses AS da ON a.id = da.address_id
INNER JOIN accounts AS acc ON da.account_id = acc.id
LEFT JOIN derived_accounts AS dacct ON acc.id = dacct.account_id
LEFT JOIN wallet_sync_states AS s ON t.wallet_id = s.wallet_id
WHERE
    t.wallet_id = sqlc.arg('wallet_id')
    AND a.wallet_id = sqlc.arg('wallet_id')
    AND da.wallet_id = sqlc.arg('wallet_id')
    AND acc.wallet_id = sqlc.arg('wallet_id')
    AND da.account_id IN (sqlc.slice('account_ids'))
    AND u.spent_by_tx_id IS NULL
    AND t.tx_status IN (0, 1)
    AND a.is_derived
    AND da.address_id IS NOT NULL
    AND acc.id IS NOT NULL
    AND (
        (acc.is_derived AND dacct.account_number IS NOT NULL)
        OR (acc.is_derived = FALSE AND dacct.account_number IS NULL)
    )
GROUP BY da.account_id;
