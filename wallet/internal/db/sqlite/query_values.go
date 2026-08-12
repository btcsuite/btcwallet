package sqlite

import (
	"database/sql"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// nullableInt64 converts a SQLite nullable integer into the shared
// driver-neutral representation.
func nullableInt64(value sql.NullInt64) db.Nullable[int64] {
	if !value.Valid {
		return db.Null[int64]()
	}

	return db.NewNullable(value.Int64)
}

// nullableString converts a SQLite nullable string into the shared
// driver-neutral representation.
func nullableString(value sql.NullString) db.Nullable[string] {
	if !value.Valid {
		return db.Null[string]()
	}

	return db.NewNullable(value.String)
}

// nullableBool converts a SQLite nullable boolean into the shared
// driver-neutral representation.
func nullableBool(value sql.NullBool) db.Nullable[bool] {
	if !value.Valid {
		return db.Null[bool]()
	}

	return db.NewNullable(value.Bool)
}
