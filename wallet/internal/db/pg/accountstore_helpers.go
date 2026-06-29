package pg

import (
	"errors"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// Ensure Store satisfies the AccountStore interface.
var _ db.AccountStore = (*Store)(nil)

var (
	errDryRunRollback = errors.New("postgres imported account dry run rollback")
)

// accountInfoRow is a type constraint for PostgreSQL account info row types
// that share the same field structure. This enables a single generic conversion
// function to handle all account query result types.
type accountInfoRow interface {
	sqlc.GetAccountByScopeAndNameRow |
		sqlc.GetAccountByScopeAndNumberRow |
		sqlc.GetAccountByWalletScopeAndNameRow |
		sqlc.GetAccountByWalletScopeAndNumberRow |
		sqlc.ListAccountsByWalletRow |
		sqlc.ListAccountsByWalletScopeRow |
		sqlc.ListAccountsByWalletAndNameRow
}

// derivedAddressGetAccountID extracts the account ID from a row.
func derivedAddressGetAccountID(
	row sqlc.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// derivedAddressGetAccountNumber extracts the derived account number from a
// row.
func derivedAddressGetAccountNumber(
	row sqlc.GetAccountByWalletScopeAndNameRow) (uint32, error) {

	return db.DerivedAddressAccountNumber(row.AccountNumber)
}

// derivedAddressGetAccountIsDerived reports whether the account row is
// wallet-derived.
func derivedAddressGetAccountIsDerived(
	row sqlc.GetAccountByWalletScopeAndNameRow) bool {

	return row.IsDerived
}

// derivedAddressGetWalletWatchOnly extracts the wallet-level watch-only state
// from a row.
func derivedAddressGetWalletWatchOnly(
	row sqlc.GetAccountByWalletScopeAndNameRow) bool {

	return row.WalletIsWatchOnly
}

// derivedAddressGetAccountAddrSchema returns the address schema persisted for
// the account's key scope.
func derivedAddressGetAccountAddrSchema(
	row sqlc.GetAccountByWalletScopeAndNameRow) (db.ScopeAddrSchema,
	error) {

	return db.DerivedAddressAccountSchema(
		row.InternalTypeID, row.ExternalTypeID,
	)
}

// derivedAddressGetAccountPubKey extracts the account public key from a row.
func derivedAddressGetAccountPubKey(
	row sqlc.GetAccountByWalletScopeAndNameRow) []byte {

	return row.PublicKey
}

// importedAddressGetAccountID extracts the account ID from a row.
func importedAddressGetAccountID(
	row sqlc.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// importedAddressGetWalletWatchOnly extracts the wallet-level watch-only state
// from a row.
func importedAddressGetWalletWatchOnly(
	row sqlc.GetAccountByWalletScopeAndNameRow) bool {

	return row.WalletIsWatchOnly
}

// accountRowToInfo converts a PostgreSQL account row to an AccountInfo
// struct. It uses type conversion since all accountInfoRow types have
// identical fields.
func accountRowToInfo[T accountInfoRow](row T) (*db.AccountInfo, error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlc.GetAccountByScopeAndNameRow(row)

	return db.AccountRowToInfo(
		db.AccountInfoRow[int16]{
			RowID:             base.ID,
			AccountNumber:     base.AccountNumber,
			AccountName:       base.AccountName,
			IsDerived:         base.IsDerived,
			ExternalKeyCount:  base.ExternalKeyCount,
			InternalKeyCount:  base.InternalKeyCount,
			ImportedKeyCount:  base.ImportedKeyCount,
			PublicKey:         base.PublicKey,
			MasterFingerprint: base.MasterFingerprint,
			IsWatchOnly:       base.WalletIsWatchOnly,
			CreatedAt:         base.CreatedAt,
			Purpose:           base.Purpose,
			CoinType:          base.CoinType,
			InternalTypeID:    base.InternalTypeID,
			ExternalTypeID:    base.ExternalTypeID,
		},
	)
}
