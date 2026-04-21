package pg

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// addressTypeRowToInfo converts a PostgreSQL address type row to an
// AddressTypeInfo struct.
func addressTypeRowToInfo(row sqlc.AddressType) (db.AddressTypeInfo, error) {
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

	var infos []db.AddressTypeInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		var err error

		infos, err = db.ListAddressTypes(
			ctx, q.ListAddressTypes, addressTypeRowToInfo,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return infos, nil
}

// GetAddressType returns the AddressTypeInfo associated with the given address
// type identifier. An error is returned if the type is unknown.
func (s *Store) GetAddressType(ctx context.Context,
	id db.AddressType) (db.AddressTypeInfo, error) {

	var info db.AddressTypeInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		var err error

		info, err = db.GetAddressTypeByID(
			ctx, q.GetAddressTypeByID, int16(id), id,
			addressTypeRowToInfo,
		)

		return err
	})
	if err != nil {
		return db.AddressTypeInfo{}, err
	}

	return info, nil
}
