-- name: InsertAddressSecret :exec
-- Inserts address secret information (private key, script) for imported addresses.
-- Not used for derived addresses (their keys are derived from account key).
INSERT INTO address_secrets (
    address_id,
    encrypted_priv_key,
    encrypted_script
) VALUES (
    ?, ?, ?
);

-- name: GetAddressByScriptPubKey :one
-- Retrieves an address by its script pubkey and account wallet.
SELECT
    a.id,
    a.account_id,
    a.type_id,
    a.address_branch,
    a.address_index,
    a.script_pub_key,
    a.pub_key,
    a.created_at,
    acc.origin_id,
    s.encrypted_priv_key IS NOT NULL AS has_private_key,
    s.encrypted_script IS NOT NULL AS has_script
FROM addresses AS a
INNER JOIN accounts AS acc ON a.account_id = acc.id
INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
LEFT JOIN address_secrets AS s ON a.id = s.address_id
WHERE a.script_pub_key = ? AND ks.wallet_id = ?;

-- name: GetAddressSecret :one
-- Retrieves secret information for an address. Uses LEFT JOIN to distinguish:
-- - Address exists with secret: returns full row
-- - Address exists without secret (watch-only/derived): returns row with NULL secret fields
-- - Address does not exist: returns no rows (sql.ErrNoRows)
SELECT
    a.id AS address_id,
    s.encrypted_priv_key,
    s.encrypted_script
FROM addresses AS a
LEFT JOIN address_secrets AS s ON a.id = s.address_id
WHERE a.id = ?;

-- name: CreateDerivedAddress :one
-- Creates a derived address with the given index and derived data.
-- The index is allocated separately via GetAndIncrementNextExternalIndex
-- or GetAndIncrementNextInternalIndex.
INSERT INTO addresses (
    account_id,
    script_pub_key,
    type_id,
    address_branch,
    address_index,
    pub_key
) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
RETURNING id, created_at;

-- name: CreateImportedAddress :one
-- Creates an imported address (no derivation path, has script/pubkey).
INSERT INTO addresses (
    account_id,
    script_pub_key,
    type_id,
    address_branch,
    address_index,
    pub_key
) VALUES (
    ?1, ?2, ?3, NULL, NULL, ?4
)
RETURNING id, created_at;

-- name: ListAddressesByAccount :many
-- Lists all addresses for a given account identified by wallet_id, key scope
-- (purpose/coin_type), and account name. Returns all address columns for
-- filtering and processing by the application.
SELECT
    a.id,
    a.account_id,
    a.type_id,
    a.address_branch,
    a.address_index,
    a.script_pub_key,
    a.pub_key,
    a.created_at,
    acc.origin_id,
    s.encrypted_priv_key IS NOT NULL AS has_private_key,
    s.encrypted_script IS NOT NULL AS has_script
FROM addresses AS a
INNER JOIN accounts AS acc ON a.account_id = acc.id
INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
LEFT JOIN address_secrets AS s ON a.id = s.address_id
WHERE
    ks.wallet_id = ? AND ks.purpose = ? AND ks.coin_type = ?
    AND acc.account_name = ?
ORDER BY a.id;
