package db

import (
	"context"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// sqliteAddressTypeRowToInfo converts a SQLite address type row to an
// AddressTypeInfo struct.
func sqliteAddressTypeRowToInfo(row sqlcsqlite.AddressType) (AddressTypeInfo,
	error) {

	addrType, err := idToAddressType(row.ID)
	if err != nil {
		return AddressTypeInfo{}, err
	}

	return AddressTypeInfo{
		Type:        addrType,
		Description: row.Description,
	}, nil
}

// ListAddressTypes returns all supported address types along with their
// readable descriptions, wrapped in AddressTypeInfo values.
func (s *SqliteStore) ListAddressTypes(ctx context.Context) (
	[]AddressTypeInfo, error) {

	return listAddressTypes(
		ctx, s.queries.ListAddressTypes, sqliteAddressTypeRowToInfo,
	)
}

// GetAddressType returns the AddressTypeInfo associated with the given address
// type identifier. An error is returned if the type is unknown.
func (s *SqliteStore) GetAddressType(ctx context.Context,
	id AddressType) (AddressTypeInfo, error) {

	return getAddressTypeByID(
		ctx, s.queries.GetAddressTypeByID, int64(id), id,
		sqliteAddressTypeRowToInfo,
	)
}
