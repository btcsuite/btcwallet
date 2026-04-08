-- name: ListAddressTypes :many
-- Returns all address types ordered by ID.
SELECT
    id,
    description
FROM address_types
ORDER BY id;

-- name: GetAddressTypeByID :one
-- Returns a single address type by its ID.
SELECT
    id,
    description
FROM address_types
WHERE id = ?;
