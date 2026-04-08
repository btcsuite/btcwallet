package pg

import (
	"context"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// pgAddressTypeRowToInfo converts a PostgreSQL address type row to an
// AddressTypeInfo struct.
func pgAddressTypeRowToInfo(row sqlcpg.AddressType) (db.AddressTypeInfo, error) {
	addrType, err := db.IDToAddressType(row.ID)
	if err != nil {
		return db.AddressTypeInfo{}, err
	}

	return db.AddressTypeInfo{
		Type:        addrType,
		Description: row.Description,
	}, nil
}

// ListAddressTypes returns all supported address types along with their
// readable descriptions, wrapped in AddressTypeInfo values.
func (s *PostgresStore) ListAddressTypes(ctx context.Context) (
	[]db.AddressTypeInfo, error) {

	return db.ListAddressTypes(
		ctx, s.queries.ListAddressTypes, pgAddressTypeRowToInfo,
	)
}

// GetAddressType returns the AddressTypeInfo associated with the given address
// type identifier. An error is returned if the type is unknown.
func (s *PostgresStore) GetAddressType(ctx context.Context,
	id db.AddressType) (db.AddressTypeInfo, error) {

	return db.GetAddressTypeByID(
		ctx, s.queries.GetAddressTypeByID, int16(id), id,
		pgAddressTypeRowToInfo,
	)
}
