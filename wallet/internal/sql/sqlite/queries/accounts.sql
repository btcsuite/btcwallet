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

-- name: GetManagerAccount :one
SELECT
    a.wallet_id,
    a.scope_id,
    a.account_number,
    a.account_type,
    a.account_name,
    a.encrypted_pub_key,
    a.encrypted_priv_key,
    a.master_key_fingerprint,
    a.next_external_index,
    a.next_internal_index,
    a.external_addr_type,
    a.internal_addr_type
FROM accounts AS a
INNER JOIN key_scopes AS s ON s.id = a.scope_id
WHERE s.wallet_id = ? AND s.purpose = ? AND s.coin_type = ?
  AND a.account_number = ?;

-- name: GetManagerAccountByName :one
SELECT
    a.wallet_id,
    a.scope_id,
    a.account_number,
    a.account_type,
    a.account_name,
    a.encrypted_pub_key,
    a.encrypted_priv_key,
    a.master_key_fingerprint,
    a.next_external_index,
    a.next_internal_index,
    a.external_addr_type,
    a.internal_addr_type
FROM accounts AS a
INNER JOIN key_scopes AS s ON s.id = a.scope_id
WHERE s.wallet_id = ? AND s.purpose = ? AND s.coin_type = ?
  AND a.account_name = ?;

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

-- name: ListManagerAccounts :many
SELECT
    a.wallet_id,
    a.scope_id,
    a.account_number,
    a.account_type,
    a.account_name,
    a.encrypted_pub_key,
    a.encrypted_priv_key,
    a.master_key_fingerprint,
    a.next_external_index,
    a.next_internal_index,
    a.external_addr_type,
    a.internal_addr_type
FROM accounts AS a
INNER JOIN key_scopes AS s ON s.id = a.scope_id
WHERE s.wallet_id = ? AND s.purpose = ? AND s.coin_type = ?
ORDER BY a.account_number;

-- name: PutManagerAccount :execrows
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
)
SELECT
    s.wallet_id,
    s.id,
    sqlc.arg('account_number'),
    sqlc.arg('account_type'),
    sqlc.arg('account_name'),
    sqlc.arg('encrypted_pub_key'),
    sqlc.narg('encrypted_priv_key'),
    cast(sqlc.narg('master_key_fingerprint') AS INTEGER),
    sqlc.arg('next_external_index'),
    sqlc.arg('next_internal_index'),
    cast(sqlc.narg('external_addr_type') AS INTEGER),
    cast(sqlc.narg('internal_addr_type') AS INTEGER)
FROM key_scopes AS s
WHERE s.wallet_id = sqlc.arg('wallet_id')
  AND s.purpose = sqlc.arg('purpose')
  AND s.coin_type = sqlc.arg('coin_type')
ON CONFLICT (scope_id, account_number) DO UPDATE SET
    account_type = excluded.account_type,
    account_name = excluded.account_name,
    encrypted_pub_key = excluded.encrypted_pub_key,
    encrypted_priv_key = excluded.encrypted_priv_key,
    master_key_fingerprint = excluded.master_key_fingerprint,
    next_external_index = excluded.next_external_index,
    next_internal_index = excluded.next_internal_index,
    external_addr_type = excluded.external_addr_type,
    internal_addr_type = excluded.internal_addr_type;

-- name: RenameAccount :execrows
UPDATE accounts
SET account_name = ?
WHERE scope_id = ? AND account_number = ?;

-- name: DeleteAccountPrivateKeys :execrows
UPDATE accounts
SET encrypted_priv_key = NULL
WHERE wallet_id = ?;

-- name: UpdateAccountIndexes :execrows
UPDATE accounts
SET next_external_index = ?, next_internal_index = ?
WHERE scope_id = ? AND account_number = ?;

-- name: AdvanceExternalBranchIndex :one
-- AdvanceExternalBranchIndex sets the external branch's next index to new_index,
-- but only while it still equals expected_index, so an address allocation is an
-- optimistic compare-and-swap. It returns no row when the account is missing or
-- the expected index no longer matches.
UPDATE accounts
SET next_external_index = sqlc.arg('new_index')
WHERE scope_id = sqlc.arg('scope_id')
    AND account_number = sqlc.arg('account_number')
    AND next_external_index = sqlc.arg('expected_index')
RETURNING next_external_index;

-- name: AdvanceInternalBranchIndex :one
-- AdvanceInternalBranchIndex sets the internal branch's next index to new_index,
-- but only while it still equals expected_index. It returns no row when the
-- account is missing or the expected index no longer matches.
UPDATE accounts
SET next_internal_index = sqlc.arg('new_index')
WHERE scope_id = sqlc.arg('scope_id')
    AND account_number = sqlc.arg('account_number')
    AND next_internal_index = sqlc.arg('expected_index')
RETURNING next_internal_index;
