package sqlite

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// addressTypeRowToInfo converts a SQLite address type row to an
// AddressTypeInfo struct.
func addressTypeRowToInfo(row sqlc.AddressType) (db.AddressTypeInfo,
	error) {

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
func (s *Store) ListAddressTypes(ctx context.Context) (
	[]db.AddressTypeInfo, error) {

	return db.ListAddressTypes(
		ctx, s.queries.ListAddressTypes, addressTypeRowToInfo,
	)
}

// GetAddressType returns the AddressTypeInfo associated with the given address
// type identifier. An error is returned if the type is unknown.
func (s *Store) GetAddressType(ctx context.Context,
	id db.AddressType) (db.AddressTypeInfo, error) {

	return db.GetAddressTypeByID(
		ctx, s.queries.GetAddressTypeByID, int64(id), id,
		addressTypeRowToInfo,
	)
}
