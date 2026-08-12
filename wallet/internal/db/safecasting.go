package db

import (
	"errors"
	"fmt"
	"math"
)

var (
	// ErrCastingOverflow is returned when a value cannot be safely
	// cast to the desired type.
	ErrCastingOverflow = errors.New("casting overflow")

	// ErrInvalidNullInt is returned when an invalid nullable integer is
	// tried to be cast to an integer type.
	ErrInvalidNullInt = errors.New("invalid NullInt")
)

// Int64ToUint32 safely casts an int64 to an uint32, returning an error
// if the value is out of range.
func Int64ToUint32(v int64) (uint32, error) {
	if v < 0 || v > math.MaxUint32 {
		return 0, fmt.Errorf("could not cast %d to uint32: %w", v,
			ErrCastingOverflow)
	}

	return uint32(v), nil
}

// Int64ToInt32 safely casts an int64 to an int32, returning an error
// if the value is out of range.
func Int64ToInt32(v int64) (int32, error) {
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

// Int16ToUint8 safely casts an int16 to an uint8, returning an error
// if the value is out of range.
func Int16ToUint8(v int16) (uint8, error) {
	if v < 0 || v > math.MaxUint8 {
		return 0, fmt.Errorf("could not cast %d to uint8: %w", v,
			ErrCastingOverflow)
	}

	return uint8(v), nil
}

// Uint32ToInt32 safely casts an uint32 to an int32, returning an error
// if the value is out of range.
func Uint32ToInt32(v uint32) (int32, error) {
	if v > math.MaxInt32 {
		return 0, fmt.Errorf("could not cast %d to int32: %w", v,
			ErrCastingOverflow)
	}

	return int32(v), nil
}

// Uint32ToInt16 safely casts an uint32 to an int16, returning an error
// if the value is out of range.
func Uint32ToInt16(v uint32) (int16, error) {
	if v > math.MaxInt16 {
		return 0, fmt.Errorf("could not cast %d to int16: %w", v,
			ErrCastingOverflow)
	}

	return int16(v), nil
}

// Int32ToUint32 safely casts an int32 to a uint32, returning an error if the
// value is negative.
func Int32ToUint32(v int32) (uint32, error) {
	if v < 0 {
		return 0, fmt.Errorf("could not cast %d to uint32: %w", v,
			ErrCastingOverflow)
	}

	return uint32(v), nil
}

// ScopeFilter unpacks an optional *KeyScope into the (purpose, coin_type)
// nullable values that scoped predicates expect. Both are absent when scope is
// nil so the caller's query falls back to wallet-wide aggregation.
func ScopeFilter(scope *KeyScope) (Nullable[int64], Nullable[int64]) {
	if scope == nil {
		return Null[int64](), Null[int64]()
	}

	return NewNullable(int64(scope.Purpose)),
		NewNullable(int64(scope.Coin))
}
