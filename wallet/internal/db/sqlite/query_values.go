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

// nullableInt64FromInt32 converts an optional int32 query value.
func nullableInt64FromInt32(value *int32) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{Int64: int64(*value), Valid: true}
}

// nullableInt64FromUint32 converts an optional uint32 query value.
func nullableInt64FromUint32(value *uint32) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{Int64: int64(*value), Valid: true}
}

// nullableStringFromPtr converts an optional string query value.
func nullableStringFromPtr(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}

	return sql.NullString{String: *value, Valid: true}
}

// scopeFilter converts an optional key scope into SQLite query values.
func scopeFilter(scope *db.KeyScope) (sql.NullInt64, sql.NullInt64) {
	purpose, coinType := db.ScopeFilter(scope)

	return sql.NullInt64{Int64: purpose.Value, Valid: purpose.Valid},
		sql.NullInt64{Int64: coinType.Value, Valid: coinType.Valid}
}
