package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func addressTypeInfosFromRows[T any](rows []T,
	toInfo func(T) (AddressTypeInfo, error)) ([]AddressTypeInfo, error) {

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

func listAddressTypes[T any](ctx context.Context,
	list func(context.Context) ([]T, error),
	toInfo func(T) (AddressTypeInfo, error)) ([]AddressTypeInfo, error) {

	rows, err := list(ctx)
	if err != nil {
		return nil, fmt.Errorf("list address types: %w", err)
	}

	return addressTypeInfosFromRows(rows, toInfo)
}

func getAddressTypeByID[T any, ID any](ctx context.Context,
	get func(context.Context, ID) (T, error), queryID ID,
	id AddressType, toInfo func(T) (AddressTypeInfo, error)) (
	AddressTypeInfo, error) {

	row, err := get(ctx, queryID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AddressTypeInfo{}, fmt.Errorf(
				"address type %d: %w", id,
				ErrAddressTypeNotFound,
			)
		}

		return AddressTypeInfo{}, fmt.Errorf("get address type: %w",
			err)
	}

	info, err := toInfo(row)
	if err != nil {
		return AddressTypeInfo{}, fmt.Errorf("get address type: %w",
			err)
	}

	return info, nil
}
