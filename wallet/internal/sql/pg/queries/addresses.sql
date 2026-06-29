-- name: InsertAddressSecret :exec
-- Inserts address secret information (private key and/or script) for imported
-- addresses.
-- Not used for derived addresses (their keys are derived from account key).
INSERT INTO address_secrets (
    address_id,
    encrypted_priv_key,
    encrypted_script
) VALUES (
    $1, $2, $3
);

-- name: GetAddressByScriptPubKey :one
-- Retrieves an address by its script pubkey and account wallet.
SELECT
    a.id,
    acc.account_number,
    a.type_id,
    da.address_branch,
    da.address_index,
    a.is_derived,
    a.script_pub_key,
    a.pub_key,
    a.created_at,
    acc.master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only,
    coalesce(da.address_id, 0)::BIGINT AS derived_address_id,
    coalesce(da.account_id, 0)::BIGINT AS account_id,
    coalesce(acc.account_name, '')::TEXT AS account_name,
    coalesce(ks.purpose, 0)::BIGINT AS purpose,
    coalesce(ks.coin_type, 0)::BIGINT AS coin_type,
    CASE
        WHEN a.is_derived THEN coalesce(acc.origin_id, 0)
        ELSE 1
    END::SMALLINT AS origin_id,
    (s.encrypted_script IS NOT NULL)::BOOLEAN AS has_script,
    exists(
        SELECT 1
        FROM utxos AS u
        WHERE u.address_id = a.id
    ) AS is_used
FROM addresses AS a
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN derived_addresses AS da ON a.id = da.address_id
LEFT JOIN accounts AS acc ON da.account_id = acc.id
LEFT JOIN key_scopes AS ks ON acc.scope_id = ks.id
LEFT JOIN address_secrets AS s ON a.id = s.address_id
WHERE a.script_pub_key = $1 AND a.wallet_id = $2;

-- name: ListAddressesByScriptPubKeys :many
-- Resolves a batch of script pubkeys to the wallet-owned address rows in a
-- single query. Returns one row per matching script; scripts with no matching
-- address are simply absent from the result. The Go caller is responsible for
-- short-circuiting an empty script set before issuing this query.
SELECT
    a.id,
    acc.account_number,
    a.type_id,
    da.address_branch,
    da.address_index,
    a.is_derived,
    a.script_pub_key,
    a.pub_key,
    a.created_at,
    acc.master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only,
    coalesce(da.address_id, 0)::BIGINT AS derived_address_id,
    coalesce(da.account_id, 0)::BIGINT AS account_id,
    coalesce(acc.account_name, '')::TEXT AS account_name,
    coalesce(ks.purpose, 0)::BIGINT AS purpose,
    coalesce(ks.coin_type, 0)::BIGINT AS coin_type,
    CASE
        WHEN a.is_derived THEN coalesce(acc.origin_id, 0)
        ELSE 1
    END::SMALLINT AS origin_id,
    (s.encrypted_script IS NOT NULL)::BOOLEAN AS has_script,
    exists(
        SELECT 1
        FROM utxos AS u
        WHERE u.address_id = a.id
    ) AS is_used
FROM addresses AS a
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN derived_addresses AS da ON a.id = da.address_id
LEFT JOIN accounts AS acc ON da.account_id = acc.id
LEFT JOIN key_scopes AS ks ON acc.scope_id = ks.id
LEFT JOIN address_secrets AS s ON a.id = s.address_id
WHERE
    a.wallet_id = sqlc.arg('wallet_id')
    AND a.script_pub_key = any(sqlc.arg('script_pub_keys')::BYTEA []);

-- name: GetAddressSecret :one
-- Retrieves secret information for an address. Uses LEFT JOIN to distinguish:
-- - Address exists with secret: returns full row
-- - Address exists without secret row: returns row with NULL secret fields
-- - Address does not exist: returns no rows (sql.ErrNoRows)
SELECT
    a.id AS address_id,
    s.encrypted_priv_key,
    s.encrypted_script
FROM addresses AS a
LEFT JOIN address_secrets AS s ON a.id = s.address_id
WHERE a.wallet_id = $1 AND a.id = $2;

-- name: CreateDerivedAddress :one
-- Creates a derived address with the given index and derived data.
-- The index is allocated separately via GetAndIncrementNextExternalIndex
-- or GetAndIncrementNextInternalIndex.
INSERT INTO addresses (
    wallet_id,
    account_id,
    is_derived,
    script_pub_key,
    type_id,
    address_branch,
    address_index,
    pub_key
) VALUES ($1, $2, TRUE, $3, $4, $5, $6, $7)
RETURNING id, created_at;

-- name: CreateDerivedAddressPath :exec
-- Stores normalized account ownership and BIP44 path data for an HD-derived
-- address while legacy address columns remain populated during migration.
INSERT INTO derived_addresses (
    address_id,
    wallet_id,
    account_id,
    address_branch,
    address_index
)
SELECT
    a.id AS address_id,
    a.wallet_id,
    sqlc.arg('account_id') AS account_id,
    sqlc.arg('address_branch') AS address_branch,
    sqlc.arg('address_index') AS address_index
FROM addresses AS a
WHERE
    a.id = sqlc.arg('address_id')
    AND a.wallet_id = sqlc.arg('wallet_id');

-- name: CreateImportedAddress :one
-- Creates an imported address (no derivation path, has script/pubkey).
INSERT INTO addresses (
    wallet_id,
    account_id,
    is_derived,
    script_pub_key,
    type_id,
    address_branch,
    address_index,
    pub_key
) VALUES (
    $1, $2, FALSE, $3, $4, NULL, NULL, $5
)
RETURNING id, created_at;

-- name: ListAddressesByAccount :many
-- Lists addresses for an account identified by wallet_id, key scope
-- (purpose/coin_type), and account name, ordered by address ID.
-- When cursor_id is provided, only rows strictly after that address ID are
-- returned. Returns up to page_limit rows.
SELECT
    a.id,
    acc.account_number,
    a.type_id,
    da.address_branch,
    da.address_index,
    a.is_derived,
    a.script_pub_key,
    a.pub_key,
    a.created_at,
    acc.master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only,
    coalesce(da.address_id, 0)::BIGINT AS derived_address_id,
    coalesce(da.account_id, 0)::BIGINT AS account_id,
    coalesce(acc.account_name, '')::TEXT AS account_name,
    coalesce(ks.purpose, 0)::BIGINT AS purpose,
    coalesce(ks.coin_type, 0)::BIGINT AS coin_type,
    CASE
        WHEN a.is_derived THEN coalesce(acc.origin_id, 0)
        ELSE 1
    END::SMALLINT AS origin_id,
    (s.encrypted_script IS NOT NULL)::BOOLEAN AS has_script,
    exists(
        SELECT 1
        FROM utxos AS u
        WHERE u.address_id = a.id
    ) AS is_used
FROM derived_addresses AS da
INNER JOIN addresses AS a ON da.address_id = a.id
INNER JOIN accounts AS acc ON da.account_id = acc.id
INNER JOIN wallets AS w ON a.wallet_id = w.id
INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
LEFT JOIN address_secrets AS s ON a.id = s.address_id
WHERE
    ks.wallet_id = sqlc.arg('wallet_id')
    AND ks.purpose = sqlc.arg('purpose')
    AND ks.coin_type = sqlc.arg('coin_type')
    AND acc.account_name = sqlc.arg('account_name')
    -- sqlc.arg()/sqlc.narg() calls are bind parameters, not column
    -- references; the RF02 suppression below silences a false-positive
    -- from sqlfluff, which cannot distinguish sqlc pseudo-functions
    -- from column names in a multi-table JOIN context.
    AND (
        sqlc.narg('cursor_id')::BIGINT IS NULL -- noqa: RF02
        OR da.address_id > sqlc.narg('cursor_id')::BIGINT -- noqa: RF02
    )
ORDER BY da.address_id
LIMIT sqlc.arg('page_limit')::BIGINT;

-- name: ListRawImportedAddresses :many
-- Lists raw imported addresses in a wallet, ordered by address ID.
SELECT
    a.id,
    NULL::BIGINT AS account_number,
    a.type_id,
    NULL::SMALLINT AS address_branch,
    NULL::BIGINT AS address_index,
    a.is_derived,
    a.script_pub_key,
    a.pub_key,
    a.created_at,
    NULL::BIGINT AS master_fingerprint,
    w.is_watch_only AS wallet_is_watch_only,
    0::BIGINT AS derived_address_id,
    0::BIGINT AS account_id,
    ''::TEXT AS account_name,
    0::BIGINT AS purpose,
    0::BIGINT AS coin_type,
    1::SMALLINT AS origin_id,
    (s.encrypted_script IS NOT NULL)::BOOLEAN AS has_script,
    exists(
        SELECT 1
        FROM utxos AS u
        WHERE u.address_id = a.id
    ) AS is_used
FROM addresses AS a
INNER JOIN wallets AS w ON a.wallet_id = w.id
LEFT JOIN address_secrets AS s ON a.id = s.address_id
WHERE
    a.wallet_id = sqlc.arg('wallet_id')
    AND a.is_derived = FALSE
    AND (
        sqlc.narg('cursor_id')::BIGINT IS NULL -- noqa: RF02
        OR a.id > sqlc.narg('cursor_id')::BIGINT -- noqa: RF02
    )
ORDER BY a.id
LIMIT sqlc.arg('page_limit')::BIGINT;
