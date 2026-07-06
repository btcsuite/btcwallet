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

// NewImportedAddress imports a new address, script, or private key.
func (s *Store) NewImportedAddress(ctx context.Context,
	params db.NewImportedAddressParams) (*db.AddressInfo, error) {

	err := params.ValidateBasic()
	if err != nil {
		return nil, err
	}

	var info *db.AddressInfo

	err = s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		created, err := s.createImportedAddress(ctx, qtx, params)
		if err != nil {
			return err
		}

		info = created

		return nil
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// createImportedAddress performs the imported-address write within an existing
// transaction and returns the resulting address info.
func (s *Store) createImportedAddress(ctx context.Context, qtx *sqlc.Queries,
	params db.NewImportedAddressParams) (*db.AddressInfo, error) {

	walletIsWatchOnly, err := getWalletWatchOnly(ctx, qtx, params.WalletID)
	if err != nil {
		return nil, err
	}

	err = params.ValidateWatchOnly(walletIsWatchOnly)
	if err != nil {
		return nil, err
	}

	err = db.RequireAddressPrivKeyOnSpendable(
		params.WalletID, walletIsWatchOnly, params.HasPrivateKey(),
	)
	if err != nil {
		return nil, err
	}

	row, err := qtx.CreateImportedAddress(
		ctx, createImportedAddressParams(params),
	)
	if err != nil {
		return nil, fmt.Errorf("create imported address: %w", err)
	}

	if params.HasSecretMaterial() {
		err = qtx.InsertAddressSecret(
			ctx, insertAddressSecretParams(row.ID, params),
		)
		if err != nil {
			return nil, fmt.Errorf("insert address secret: %w", err)
		}
	}

	addrID, err := db.Int64ToUint32(row.ID)
	if err != nil {
		return nil, fmt.Errorf("address ID: %w", err)
	}

	return &db.AddressInfo{
		ID:           addrID,
		AddrType:     params.AddressType,
		CreatedAt:    row.CreatedAt,
		IsImported:   true,
		ScriptPubKey: params.ScriptPubKey,
		PubKey:       params.PubKey,
		HasScript:    params.HasScript(),
		IsWatchOnly:  walletIsWatchOnly,
		IsUsed:       false,
	}, nil
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

// createImportedAddressParams maps imported params to sqlc params.
func createImportedAddressParams(
	params db.NewImportedAddressParams) sqlc.CreateImportedAddressParams {

	return sqlc.CreateImportedAddressParams{
		WalletID:     int64(params.WalletID),
		ScriptPubKey: params.ScriptPubKey,
		ScriptTypeID: int16(params.AddressType),
		PubKey:       params.PubKey,
	}
}

// insertAddressSecretParams maps imported params to secret params.
func insertAddressSecretParams(addressID int64,
	params db.NewImportedAddressParams) sqlc.InsertAddressSecretParams {

	return sqlc.InsertAddressSecretParams{
		AddressID: addressID,
		EncryptedPrivKey: db.NilIfEmptyBytes(
			params.EncryptedPrivateKey,
		),
		EncryptedScript: db.NilIfEmptyBytes(
			params.EncryptedScript,
		),
	}
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
