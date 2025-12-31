package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// errInvalidAddressType is returned when an address type ID from the database
// does not fit in AddressType (uint8). In practice, this should never happen,
// but it's possible if the database is modified incorrectly or the query is
// incorrect.
var errInvalidAddressType = errors.New("invalid address type")

// idToAddressType safely converts an integer to AddressType. It returns an
// error if the value does not correspond to a known AddressType value.
func idToAddressType[T ~int16 | ~int64](v T) (AddressType, error) {
	if v < 0 || v > T(Anchor) {
		return 0, fmt.Errorf("%w: %d", errInvalidAddressType, v)
	}

	return AddressType(v), nil
}

// listAddressTypes is a generic helper that retrieves all address types from
// the database and converts them to AddressTypeInfo structs.
func listAddressTypes[Row any](ctx context.Context,
	lister func(context.Context) ([]Row, error),
	toInfo func(Row) (AddressTypeInfo, error)) ([]AddressTypeInfo, error) {

	rows, err := lister(ctx)
	if err != nil {
		return nil, fmt.Errorf("list address types: %w", err)
	}

	types := make([]AddressTypeInfo, len(rows))

	for i, row := range rows {
		info, err := toInfo(row)
		if err != nil {
			return nil, err
		}

		types[i] = info
	}

	return types, nil
}

// getAddressTypeByID is a generic helper that retrieves a single address type
// by its ID and converts it to an AddressTypeInfo struct. It returns
// ErrAddressTypeNotFound if no matching type is found.
func getAddressTypeByID[Row any, ID any](ctx context.Context,
	getter func(context.Context, ID) (Row, error), queryID ID, id AddressType,
	toInfo func(Row) (AddressTypeInfo, error)) (AddressTypeInfo, error) {

	row, err := getter(ctx, queryID)
	if err == nil {
		return toInfo(row)
	}

	if errors.Is(err, sql.ErrNoRows) {
		return AddressTypeInfo{}, fmt.Errorf("address type %d: %w", id,
			ErrAddressTypeNotFound)
	}

	return AddressTypeInfo{}, fmt.Errorf("get address type: %w", err)
}
