package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
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

// NewDerivedAddresses commits batches under the counter lock, skipping owned
// scripts in the same transaction to preserve raw-import metadata.
func (s *Store) NewDerivedAddresses(ctx context.Context,
	params db.NewDerivedAddressParams, count uint32) ([]db.AddressInfo, error) {

	var (
		addresses []db.AddressInfo
		exhausted bool
	)

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		// Leave nil callbacks to the shared admission check. Otherwise skip
		// scripts already owned without modifying their rows or secrets.
		derive := s.deriveAddress
		if derive != nil {
			derive = func(ctx context.Context,
				input db.AddressDerivationParams) (
				*db.DerivedAddressData, error) {

				data, err := s.deriveAddress(ctx, input)
				if err != nil || data == nil {
					return data, err
				}

				_, err = qtx.GetAddressByScriptPubKey(
					ctx, sqlc.GetAddressByScriptPubKeyParams{
						WalletID:     int64(params.WalletID),
						ScriptPubKey: data.ScriptPubKey,
					},
				)
				if err == nil {
					return nil, db.ErrAddressChildUnavailable
				}

				if !errors.Is(err, sql.ErrNoRows) {
					return nil, err
				}

				return data, nil
			}
		}

		var err error

		addresses, exhausted, err = db.NewDerivedAddressesWithOps(
			ctx, params, count, newDerivedAddressOps{q: qtx}, derive,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	if exhausted {
		return nil, db.ErrMaxAddressIndexReached
	}

	return addresses, nil
}

// newDerivedAddressOps adapts PostgreSQL sqlc queries to the shared
// NewDerivedAddress workflow.
type newDerivedAddressOps struct {
	q *sqlc.Queries
}

// Verify newDerivedAddressOps implements db.NewDerivedAddressOps.
var _ db.NewDerivedAddressOps = newDerivedAddressOps{}

// GetAccount implements db.NewDerivedAddressOps.
func (o newDerivedAddressOps) GetAccount(ctx context.Context,
	key db.AccountLookupKey) (db.DerivedAddressAccount, error) {

	// A numbered selector is resolved under the same transaction as the
	// counter update; renaming the account cannot redirect allocation.
	var (
		row sqlc.GetAccountByWalletScopeAndNameRow
		err error
	)
	if key.AccountNumber != nil {
		var numbered sqlc.GetAccountByWalletScopeAndNumberRow

		numbered, err = o.q.GetAccountByWalletScopeAndNumber(
			ctx, sqlc.GetAccountByWalletScopeAndNumberParams{
				WalletID:      key.WalletID,
				Purpose:       key.Purpose,
				CoinType:      key.CoinType,
				AccountNumber: db.NullableUint32ToSQLInt64(key.AccountNumber),
			},
		)

		row = sqlc.GetAccountByWalletScopeAndNameRow(numbered)
	} else {
		row, err = o.q.GetAccountByWalletScopeAndName(
			ctx, sqlc.GetAccountByWalletScopeAndNameParams{
				WalletID:    key.WalletID,
				Purpose:     key.Purpose,
				CoinType:    key.CoinType,
				AccountName: key.AccountName,
			},
		)
	}

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

	// Receiving admission uses this same account read before allocating,
	// avoiding a separate policy lookup in the public API.
	return db.DerivedAddressAccount{
		NoChainSync:       row.NoChainSync,
		AccountID:         row.ID,
		AccountNumber:     row.AccountNumber,
		AccountName:       row.AccountName,
		MasterFingerprint: row.MasterFingerprint,
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

	branchNum, err := db.Uint32ToInt16(req.Branch)
	if err != nil {
		return db.CreateDerivedAddressRow{},
			fmt.Errorf("address branch: %w", err)
	}

	err = o.q.CreateDerivedAddressPath(
		ctx, sqlc.CreateDerivedAddressPathParams{
			AddressID:     row.ID,
			AccountID:     req.AccountID,
			AddressBranch: branchNum,
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

// buildDerivedAddressParams maps common derived-address inputs to PostgreSQL
// sqlc insert params.
func buildDerivedAddressParams(walletID int64, accountID int64,
	addrType db.AddressType, scriptPubKey []byte,
	pubKey []byte) sqlc.CreateDerivedAddressParams {

	return sqlc.CreateDerivedAddressParams{
		WalletID:     walletID,
		AccountID:    accountID,
		ScriptPubKey: scriptPubKey,
		ScriptTypeID: int16(addrType),
		PubKey:       pubKey,
	}
}
