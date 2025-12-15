package db

import (
	"context"
	"fmt"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

func pgAddressTypeToInfo(row sqlcpg.AddressType) (AddressTypeInfo, error) {
	id, err := int16ToUint8(row.ID)
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
func (w *PostgresWalletDB) ListAddressTypes(ctx context.Context) (
	[]AddressTypeInfo, error) {

	return listAddressTypes(ctx, w.queries.ListAddressTypes,
		pgAddressTypeToInfo)
}

// GetAddressType returns the AddressTypeInfo associated with the given address
// type identifier. An error is returned if the type is unknown.
func (w *PostgresWalletDB) GetAddressType(ctx context.Context,
	id AddressType) (AddressTypeInfo, error) {

	return getAddressTypeByID(ctx, w.queries.GetAddressTypeByID,
		int16(id), id, pgAddressTypeToInfo)
}
