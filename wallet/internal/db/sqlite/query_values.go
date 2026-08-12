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
