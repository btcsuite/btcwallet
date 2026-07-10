-- name: ListAddressTypes :many
SELECT id, type_name
FROM address_types
ORDER BY id;
