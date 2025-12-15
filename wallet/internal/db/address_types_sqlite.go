package db

import (
	"context"
	"fmt"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

func sqliteAddressTypeToInfo(row sqlcsqlite.AddressType) (AddressTypeInfo,
	error) {

	id, err := int64ToUint8(row.ID)
	if err != nil {
		return AddressTypeInfo{}, fmt.Errorf("address type id %d: %w",
			row.ID, err)
	}

	return AddressTypeInfo{
		Type:        AddressType(id),
		Description: row.Description,
	}, nil
}

// ListAddressTypes returns all supported address types along with their
// readable descriptions, wrapped in AddressTypeInfo values.
func (w *SQLiteWalletDB) ListAddressTypes(ctx context.Context) (
	[]AddressTypeInfo, error) {

	return listAddressTypes(ctx, w.queries.ListAddressTypes,
		sqliteAddressTypeToInfo)
}

// GetAddressType returns the AddressTypeInfo associated with the given address
// type identifier. An error is returned if the type is unknown.
func (w *SQLiteWalletDB) GetAddressType(ctx context.Context,
	id AddressType) (AddressTypeInfo, error) {

	return getAddressTypeByID(ctx, w.queries.GetAddressTypeByID,
		int64(id), id, sqliteAddressTypeToInfo)
}
