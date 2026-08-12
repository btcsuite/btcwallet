package pg

import (
	"database/sql"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// nullableInt64 converts a PostgreSQL nullable integer into the shared
// driver-neutral representation.
func nullableInt64(value sql.NullInt64) db.Nullable[int64] {
	if !value.Valid {
		return db.Null[int64]()
	}

	return db.NewNullable(value.Int64)
}

// nullableInt16 converts a PostgreSQL nullable small integer into the shared
// driver-neutral integer representation.
func nullableInt16(value sql.NullInt16) db.Nullable[int64] {
	if !value.Valid {
		return db.Null[int64]()
	}

	return db.NewNullable(int64(value.Int16))
}

// nullableString converts a PostgreSQL nullable string into the shared
// driver-neutral representation.
func nullableString(value sql.NullString) db.Nullable[string] {
	if !value.Valid {
		return db.Null[string]()
	}

	return db.NewNullable(value.String)
}

// nullableBool converts a PostgreSQL nullable boolean into the shared
// driver-neutral representation.
func nullableBool(value sql.NullBool) db.Nullable[bool] {
	if !value.Valid {
		return db.Null[bool]()
	}

	return db.NewNullable(value.Bool)
}

// nullableInt32FromPtr converts an optional int32 query value.
func nullableInt32FromPtr(value *int32) sql.NullInt32 {
	if value == nil {
		return sql.NullInt32{}
	}

	return sql.NullInt32{Int32: *value, Valid: true}
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

// nullableInt32FromUint32 safely converts a uint32 query value.
func nullableInt32FromUint32(value uint32) (sql.NullInt32, error) {
	converted, err := db.Uint32ToInt32(value)
	if err != nil {
		return sql.NullInt32{}, err
	}

	return sql.NullInt32{Int32: converted, Valid: true}, nil
}

// nullableInt32ToUint32 converts a present int32 result value.
func nullableInt32ToUint32(value sql.NullInt32) (uint32, error) {
	if !value.Valid {
		return 0, db.ErrInvalidNullInt
	}

	return db.Int32ToUint32(value.Int32)
}

// scopeFilter converts an optional key scope into PostgreSQL query values.
func scopeFilter(scope *db.KeyScope) (sql.NullInt64, sql.NullInt64) {
	purpose, coinType := db.ScopeFilter(scope)

	return sql.NullInt64{Int64: purpose.Value, Valid: purpose.Valid},
		sql.NullInt64{Int64: coinType.Value, Valid: coinType.Valid}
}
