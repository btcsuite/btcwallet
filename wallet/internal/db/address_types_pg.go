package db

import (
	"context"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// pgAddressTypeRowToInfo converts a PostgreSQL address type row to an
// AddressTypeInfo struct.
func pgAddressTypeRowToInfo(row sqlcpg.AddressType) (AddressTypeInfo, error) {
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
func (w *PostgresWalletDB) ListAddressTypes(ctx context.Context) (
	[]AddressTypeInfo, error) {

	return listAddressTypes(
		ctx, w.queries.ListAddressTypes, pgAddressTypeRowToInfo,
	)
}

// GetAddressType returns the AddressTypeInfo associated with the given address
// type identifier. An error is returned if the type is unknown.
func (w *PostgresWalletDB) GetAddressType(ctx context.Context,
	id AddressType) (AddressTypeInfo, error) {

	return getAddressTypeByID(
		ctx, w.queries.GetAddressTypeByID, int16(id), id,
		pgAddressTypeRowToInfo,
	)
}
