package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

var _ db.AddressStore = (*Store)(nil)

// NewDerivedAddress creates a new address for a given account and key
// scope.
func (s *Store) NewDerivedAddress(ctx context.Context,
	params db.NewDerivedAddressParams) (*db.AddressInfo, error) {

	adapters := db.DerivedAddressAdapters[
		*sqlc.Queries,
		sqlc.GetAccountByWalletScopeAndNameRow,
		db.AccountLookupKey,
		sqlc.CreateDerivedAddressRow]{
		GetAccount:    getAccountFromKey,
		AccountParams: db.AccountKeyFromParams,
		GetAccountID: func(row sqlc.GetAccountByWalletScopeAndNameRow) int64 {
			return row.ID
		},
		GetAccountNumber: func(row sqlc.GetAccountByWalletScopeAndNameRow) (
			uint32, error) {

			return db.DerivedAddressAccountNumber(row.AccountNumber)
		},
		GetAccountIsDerived: func(
			row sqlc.GetAccountByWalletScopeAndNameRow) bool {

			return row.IsDerived
		},
		GetWalletWatchOnly: func(
			row sqlc.GetAccountByWalletScopeAndNameRow) bool {

			return row.WalletIsWatchOnly
		},
		GetAccountAddrSchema: func(
			row sqlc.GetAccountByWalletScopeAndNameRow) (
			db.ScopeAddrSchema, error) {

			return db.DerivedAddressAccountSchema(
				row.InternalTypeID, row.ExternalTypeID,
			)
		},
		GetAccountPubKey: func(
			row sqlc.GetAccountByWalletScopeAndNameRow) []byte {

			return row.PublicKey
		},
		GetExtIndex:          derivedAddressGetExtIndex,
		GetIntIndex:          derivedAddressGetIntIndex,
		CreateAddr:           derivedAddressCreateAddr,
		RowID:                derivedAddressRowID,
		RowCreatedAt:         derivedAddressRowCreatedAt,
		ApplyAccountMetadata: applyAddressAccountMetadata,
	}

	return db.NewDerivedAddressWithTx(
		ctx, params, s.execWrite, adapters, s.deriveAddress,
	)
}

// getAccountFromKey returns a helper to look up accounts by key.
func getAccountFromKey(qtx *sqlc.Queries) func(context.Context,
	db.AccountLookupKey) (sqlc.GetAccountByWalletScopeAndNameRow, error) {

	return func(ctx context.Context,
		key db.AccountLookupKey) (sqlc.GetAccountByWalletScopeAndNameRow,
		error) {

		return qtx.GetAccountByWalletScopeAndName(
			ctx, sqlc.GetAccountByWalletScopeAndNameParams{
				WalletID:    key.WalletID,
				Purpose:     key.Purpose,
				CoinType:    key.CoinType,
				AccountName: key.AccountName,
			},
		)
	}
}

// derivedAddressGetExtIndex returns the external index query.
func derivedAddressGetExtIndex(qtx *sqlc.Queries) func(context.Context,
	int64) (int64, error) {

	return qtx.GetAndIncrementNextExternalIndex
}

// derivedAddressGetIntIndex returns the internal index query.
func derivedAddressGetIntIndex(qtx *sqlc.Queries) func(context.Context,
	int64) (int64, error) {

	return qtx.GetAndIncrementNextInternalIndex
}

// derivedAddressCreateAddr returns the derived address insert helper.
func derivedAddressCreateAddr(qtx *sqlc.Queries) func(
	context.Context, int64, int64, db.AddressType, uint32, uint32, []byte,
	[]byte) (sqlc.CreateDerivedAddressRow, error) {

	return func(ctx context.Context, walletID int64, accountID int64,
		addrType db.AddressType, branch uint32, index uint32,
		scriptPubKey []byte, pubKey []byte) (sqlc.CreateDerivedAddressRow,
		error) {

		row, err := qtx.CreateDerivedAddress(
			ctx, buildDerivedAddressParams(
				walletID, accountID, addrType, scriptPubKey, pubKey,
			),
		)
		if err != nil {
			return sqlc.CreateDerivedAddressRow{}, err
		}

		branchNum, err := db.Uint32ToInt16(branch)
		if err != nil {
			return sqlc.CreateDerivedAddressRow{},
				fmt.Errorf("address branch: %w", err)
		}

		err = qtx.CreateDerivedAddressPath(
			ctx, sqlc.CreateDerivedAddressPathParams{
				AddressID:     row.ID,
				AccountID:     accountID,
				AddressBranch: branchNum,
				AddressIndex:  int64(index),
			},
		)
		if err != nil {
			return sqlc.CreateDerivedAddressRow{}, fmt.Errorf(
				"create derived address path: %w", err,
			)
		}

		return row, nil
	}
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

// derivedAddressRowID returns the created address ID.
func derivedAddressRowID(row sqlc.CreateDerivedAddressRow) int64 {
	return row.ID
}

// derivedAddressRowCreatedAt returns the CreatedAt timestamp.
func derivedAddressRowCreatedAt(
	row sqlc.CreateDerivedAddressRow) time.Time {

	return row.CreatedAt
}

// applyAddressAccountMetadata copies account metadata from the account lookup
// row onto an address creation result before the write transaction commits.
func applyAddressAccountMetadata(info *db.AddressInfo,
	row sqlc.GetAccountByWalletScopeAndNameRow) error {

	return db.ApplyAddressAccountMetadata(
		info, row.AccountNumber, row.AccountName,
		row.MasterFingerprint, row.Purpose, row.CoinType,
		!row.IsDerived,
	)
}
