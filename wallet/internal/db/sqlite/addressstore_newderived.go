package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// NewDerivedAddress creates a new address for a given account and key scope.
func (s *Store) NewDerivedAddress(ctx context.Context,
	params db.NewDerivedAddressParams) (*db.AddressInfo, error) {

	var info *db.AddressInfo

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		var err error

		info, err = db.NewDerivedAddressWithOps(
			ctx, params, newDerivedAddressOps{q: qtx}, s.deriveAddress,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// newDerivedAddressOps adapts SQLite sqlc queries to the shared
// NewDerivedAddress workflow.
type newDerivedAddressOps struct {
	q *sqlc.Queries
}

// Verify newDerivedAddressOps implements db.NewDerivedAddressOps.
var _ db.NewDerivedAddressOps = newDerivedAddressOps{}

// GetAccount implements db.NewDerivedAddressOps.
func (o newDerivedAddressOps) GetAccount(ctx context.Context,
	key db.AccountLookupKey) (db.DerivedAddressAccount, error) {

	row, err := o.q.GetAccountByWalletScopeAndName(
		ctx, sqlc.GetAccountByWalletScopeAndNameParams{
			WalletID:    key.WalletID,
			Purpose:     key.Purpose,
			CoinType:    key.CoinType,
			AccountName: key.AccountName,
		},
	)
	if errors.Is(err, sql.ErrNoRows) {
		return db.DerivedAddressAccount{}, db.ErrAccountNotFound
	}

	if err != nil {
		return db.DerivedAddressAccount{}, err
	}

	addrSchema, err := db.DerivedAddressAccountSchema(
		row.InternalTypeID, row.ExternalTypeID,
	)
	if err != nil {
		return db.DerivedAddressAccount{}, err
	}

	return db.DerivedAddressAccount{
		AccountID:         row.ID,
		AccountNumber:     nullableInt64(row.AccountNumber),
		AccountName:       row.AccountName,
		MasterFingerprint: nullableInt64(row.MasterFingerprint),
		Purpose:           row.Purpose,
		CoinType:          row.CoinType,
		IsDerived:         row.IsDerived,
		WalletWatchOnly:   row.WalletIsWatchOnly,
		AddrSchema:        addrSchema,
		PubKey:            row.PublicKey,
	}, nil
}

// NextIndex implements db.NewDerivedAddressOps.
func (o newDerivedAddressOps) NextIndex(ctx context.Context, accountID int64,
	change bool) (int64, error) {

	if change {
		return o.q.GetAndIncrementNextInternalIndex(ctx, accountID)
	}

	return o.q.GetAndIncrementNextExternalIndex(ctx, accountID)
}

// CreateDerivedAddress implements db.NewDerivedAddressOps.
func (o newDerivedAddressOps) CreateDerivedAddress(ctx context.Context,
	req db.CreateDerivedAddressRequest) (db.CreateDerivedAddressRow, error) {

	row, err := o.q.CreateDerivedAddress(
		ctx, buildDerivedAddressParams(
			req.WalletID, req.AccountID, req.AddrType, req.ScriptPubKey,
			req.PubKey,
		),
	)
	if err != nil {
		return db.CreateDerivedAddressRow{}, err
	}

	err = o.q.CreateDerivedAddressPath(
		ctx, sqlc.CreateDerivedAddressPathParams{
			AddressID:     row.ID,
			AccountID:     req.AccountID,
			AddressBranch: int64(req.Branch),
			AddressIndex:  int64(req.Index),
		},
	)
	if err != nil {
		return db.CreateDerivedAddressRow{}, fmt.Errorf(
			"create derived address path: %w", err,
		)
	}

	return db.CreateDerivedAddressRow{
		ID:        row.ID,
		CreatedAt: row.CreatedAt,
	}, nil
}

// buildDerivedAddressParams maps common derived-address inputs to SQLite sqlc
// insert params.
func buildDerivedAddressParams(walletID int64, accountID int64,
	addrType db.AddressType, scriptPubKey []byte,
	pubKey []byte) sqlc.CreateDerivedAddressParams {

	return sqlc.CreateDerivedAddressParams{
		WalletID:     walletID,
		AccountID:    accountID,
		ScriptPubKey: scriptPubKey,
		ScriptTypeID: int64(addrType),
		PubKey:       pubKey,
	}
}
