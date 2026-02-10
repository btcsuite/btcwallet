package db

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
)

var (
	// ErrCastingOverflow is returned when a value cannot be safely
	// cast to the desired type.
	ErrCastingOverflow = errors.New("casting overflow")

	// ErrInvalidNullInt is returned when an invalid sql.NullInt is
	// tried to be cast to an integer type.
	ErrInvalidNullInt = errors.New("invalid NullInt")
)

// int64ToUint32 safely casts an int64 to an uint32, returning an error
// if the value is out of range.
func int64ToUint32(v int64) (uint32, error) {
	if v < 0 || v > math.MaxUint32 {
		return 0, fmt.Errorf("could not cast %d to uint32: %w", v,
			ErrCastingOverflow)
	}

	return uint32(v), nil
}

// int64ToInt32 safely casts an int64 to an int32, returning an error
// if the value is out of range.
func int64ToInt32(v int64) (int32, error) {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, fmt.Errorf("could not cast %d to int32: %w", v,
			ErrCastingOverflow)
	}

	return int32(v), nil
}

// int64ToUint8 safely casts an int64 to an uint8, returning an error
// if the value is out of range.
func int64ToUint8(v int64) (uint8, error) {
	if v < 0 || v > math.MaxUint8 {
		return 0, fmt.Errorf("could not cast %d to uint8: %w", v,
			ErrCastingOverflow)
	}

	return uint8(v), nil
}

// int16ToUint8 safely casts an int16 to an uint8, returning an error
// if the value is out of range.
func int16ToUint8(v int16) (uint8, error) {
	if v < 0 || v > math.MaxUint8 {
		return 0, fmt.Errorf("could not cast %d to uint8: %w", v,
			ErrCastingOverflow)
	}

	return uint8(v), nil
}

// uint32ToInt32 safely casts an uint32 to an int32, returning an error
// if the value is out of range.
func uint32ToInt32(v uint32) (int32, error) {
	if v > math.MaxInt32 {
		return 0, fmt.Errorf("could not cast %d to int32: %w", v,
			ErrCastingOverflow)
	}

	return int32(v), nil
}

// uint32ToInt16 safely casts an uint32 to an int16, returning an error
// if the value is out of range.
func uint32ToInt16(v uint32) (int16, error) {
	if v > math.MaxInt16 {
		return 0, fmt.Errorf("could not cast %d to int16: %w", v,
			ErrCastingOverflow)
	}

	return int16(v), nil
}

// uint32ToNullInt32 safely casts an uint32 to a sql.NullInt32, returning
// an error if the value is out of range.
func uint32ToNullInt32(v uint32) (sql.NullInt32, error) {
	toInt32, err := uint32ToInt32(v)
	if err != nil {
		return sql.NullInt32{}, err
	}

	return sql.NullInt32{Int32: toInt32, Valid: true}, nil
}

// nullInt32ToUint32 safely casts a sql.NullInt32 to an uint32, returning
// an error if the value is out of range or invalid.
func nullInt32ToUint32(n sql.NullInt32) (uint32, error) {
	if !n.Valid {
		return 0, fmt.Errorf("could not cast invalid NullInt32 to uint32: %w",
			ErrInvalidNullInt)
	}

	if n.Int32 < 0 {
		return 0, fmt.Errorf("could not cast %d to uint32: %w", n.Int32,
			ErrCastingOverflow)
	}

	return uint32(n.Int32), nil
}
