-- name: GetDummyById :one
SELECT id FROM dummy WHERE id = $1;

-- name: InsertDummy :exec
INSERT INTO dummy (id) VALUES ($1);

-- name: DeleteDummy :exec
DELETE FROM dummy WHERE id = $1;
