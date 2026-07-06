package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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
		rows, err := q.ListAddressTypes(ctx)
		if err != nil {
			return fmt.Errorf("list address types: %w", err)
		}

		infos = make([]db.AddressTypeInfo, len(rows))
		for i, row := range rows {
			info, err := addressTypeRowToInfo(row)
			if err != nil {
				return err
			}

			infos[i] = info
		}

		return nil
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
		row, err := q.GetAddressTypeByID(ctx, int16(id))
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("address type %d: %w", id,
				db.ErrAddressTypeNotFound)
		}

		if err != nil {
			return fmt.Errorf("get address type: %w", err)
		}

		info, err = addressTypeRowToInfo(row)

		return err
	})
	if err != nil {
		return db.AddressTypeInfo{}, err
	}

	return info, nil
}
