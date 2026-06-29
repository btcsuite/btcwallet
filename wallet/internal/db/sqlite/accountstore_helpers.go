package sqlite

import (
	"errors"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// Ensure Store satisfies the AccountStore interface.
var _ db.AccountStore = (*Store)(nil)

var (
	errDryRunRollback = errors.New("sqlite imported account dry run rollback")
)

// accountInfoRow is a type constraint for SQLite account info row types
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

// accountRowToInfo converts a SQLite account row to an AccountInfo
// struct. It uses type conversion since all accountInfoRow types have
// identical fields.
func accountRowToInfo[T accountInfoRow](row T) (*db.AccountInfo,
	error) {

	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlc.GetAccountByScopeAndNameRow(row)

	return db.AccountRowToInfo(db.AccountInfoRow[int64]{
		RowID:             base.ID,
		AccountNumber:     base.AccountNumber,
		AccountName:       base.AccountName,
		IsDerived:         base.IsDerived,
		ExternalKeyCount:  base.ExternalKeyCount,
		InternalKeyCount:  base.InternalKeyCount,
		PublicKey:         base.PublicKey,
		MasterFingerprint: base.MasterFingerprint,
		IsWatchOnly:       base.WalletIsWatchOnly,
		CreatedAt:         base.CreatedAt,
		Purpose:           base.Purpose,
		CoinType:          base.CoinType,
		InternalTypeID:    base.InternalTypeID,
		ExternalTypeID:    base.ExternalTypeID,
	})
}
