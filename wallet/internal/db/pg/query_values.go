package pg

import (
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/jackc/pgx/v5/pgtype"
)

// timestamp converts a time value into a present PostgreSQL timestamp.
func timestamp(value time.Time) pgtype.Timestamp {
	return pgtype.Timestamp{Time: value, Valid: true}
}

// nullableInt64 converts a PostgreSQL nullable integer into the shared
// driver-neutral representation.
func nullableInt64(value pgtype.Int8) db.Nullable[int64] {
	if !value.Valid {
		return db.Null[int64]()
	}

	return db.NewNullable(value.Int64)
}

// nullableInt16 converts a PostgreSQL nullable small integer into the shared
// driver-neutral integer representation.
func nullableInt16(value pgtype.Int2) db.Nullable[int64] {
	if !value.Valid {
		return db.Null[int64]()
	}

	return db.NewNullable(int64(value.Int16))
}

// nullableString converts a PostgreSQL nullable string into the shared
// driver-neutral representation.
func nullableString(value pgtype.Text) db.Nullable[string] {
	if !value.Valid {
		return db.Null[string]()
	}

	return db.NewNullable(value.String)
}

// nullableBool converts a PostgreSQL nullable boolean into the shared
// driver-neutral representation.
func nullableBool(value pgtype.Bool) db.Nullable[bool] {
	if !value.Valid {
		return db.Null[bool]()
	}

	return db.NewNullable(value.Bool)
}

// nullableInt32FromPtr converts an optional int32 query value.
func nullableInt32FromPtr(value *int32) pgtype.Int4 {
	if value == nil {
		return pgtype.Int4{}
	}

	return pgtype.Int4{Int32: *value, Valid: true}
}

// nullableInt64FromUint32 converts an optional uint32 query value.
func nullableInt64FromUint32(value *uint32) pgtype.Int8 {
	if value == nil {
		return pgtype.Int8{}
	}

	return pgtype.Int8{Int64: int64(*value), Valid: true}
}

// nullableStringFromPtr converts an optional string query value.
func nullableStringFromPtr(value *string) pgtype.Text {
	if value == nil {
		return pgtype.Text{}
	}

	return pgtype.Text{String: *value, Valid: true}
}

// nullableInt32FromUint32 safely converts a uint32 query value.
func nullableInt32FromUint32(value uint32) (pgtype.Int4, error) {
	converted, err := db.Uint32ToInt32(value)
	if err != nil {
		return pgtype.Int4{}, err
	}

	return pgtype.Int4{Int32: converted, Valid: true}, nil
}

// nullableInt32ToUint32 converts a present int32 result value.
func nullableInt32ToUint32(value pgtype.Int4) (uint32, error) {
	if !value.Valid {
		return 0, db.ErrInvalidNullInt
	}

	return db.Int32ToUint32(value.Int32)
}

// scopeFilter converts an optional key scope into PostgreSQL query values.
func scopeFilter(scope *db.KeyScope) (pgtype.Int8, pgtype.Int8) {
	purpose, coinType := db.ScopeFilter(scope)

	return pgtype.Int8{Int64: purpose.Value, Valid: purpose.Valid},
		pgtype.Int8{Int64: coinType.Value, Valid: coinType.Valid}
}
