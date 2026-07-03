package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// errUnknownAddressRowType is returned when an address row has an
// unrecognized concrete type.
var errUnknownAddressRowType = errors.New("unknown address row type")

// addressSecretRowToSecret converts a SQLite address secret row to an
// AddressSecret struct.
func addressSecretRowToSecret(
	row sqlc.GetAddressSecretRow) (*db.AddressSecret, error) {

	return db.AddressSecretRowToSecret(db.AddressSecretRow{
		AddressID:        row.AddressID,
		EncryptedPrivKey: row.EncryptedPrivKey,
		EncryptedScript:  row.EncryptedScript,
	})
}

// addressInfoRow is a type constraint union that represents all SQLite
// address row types that share the same field structure. This enables a
// single generic conversion function to handle all address query result types.
type addressInfoRow interface {
	sqlc.GetAddressByScriptPubKeyRow |
		sqlc.ListAddressesByAccountRow |
		sqlc.ListAddressesByScriptPubKeysRow |
		sqlc.ListRawImportedAddressesRow
}

// addressRowToInfo converts a SQLite address row to an AddressInfo struct.
func addressRowToInfo[T addressInfoRow](row T) (*db.AddressInfo, error) {
	switch base := any(row).(type) {
	case sqlc.GetAddressByScriptPubKeyRow:
		return addressFieldsToInfo(
			base.ID, base.DerivedAddressID, base.AccountID,
			base.AccountNumber, base.AccountName, base.MasterFingerprint,
			base.Purpose, base.CoinType, base.ScriptTypeID,
			base.AddressBranch, base.AddressIndex, base.IsDerived,
			base.AccountIsDerived, base.ScriptPubKey,
			base.PubKey, base.CreatedAt,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	case sqlc.ListAddressesByScriptPubKeysRow:
		return addressFieldsToInfo(
			base.ID, base.DerivedAddressID, base.AccountID,
			base.AccountNumber, base.AccountName, base.MasterFingerprint,
			base.Purpose, base.CoinType, base.ScriptTypeID,
			base.AddressBranch, base.AddressIndex, base.IsDerived,
			base.AccountIsDerived, base.ScriptPubKey,
			base.PubKey, base.CreatedAt,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	case sqlc.ListRawImportedAddressesRow:
		return addressFieldsToInfo(
			base.ID, sql.NullInt64{}, sql.NullInt64{},
			sql.NullInt64{}, sql.NullString{}, sql.NullInt64{},
			sql.NullInt64{}, sql.NullInt64{}, base.ScriptTypeID,
			sql.NullInt64{}, sql.NullInt64{}, base.IsDerived,
			sql.NullBool{}, base.ScriptPubKey,
			base.PubKey, base.CreatedAt,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	case sqlc.ListAddressesByAccountRow:
		return addressFieldsToInfo(
			base.ID,
			sql.NullInt64{Int64: base.DerivedAddressID, Valid: true},
			sql.NullInt64{Int64: base.AccountID, Valid: true},
			base.AccountNumber,
			sql.NullString{String: base.AccountName, Valid: true},
			base.MasterFingerprint,
			sql.NullInt64{Int64: base.Purpose, Valid: true},
			sql.NullInt64{Int64: base.CoinType, Valid: true},
			base.ScriptTypeID,
			sql.NullInt64{Int64: base.AddressBranch, Valid: true},
			sql.NullInt64{Int64: base.AddressIndex, Valid: true},
			base.IsDerived,
			sql.NullBool{Bool: base.AccountIsDerived, Valid: true},
			base.ScriptPubKey, base.PubKey, base.CreatedAt,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	default:
		return nil, fmt.Errorf("%w: %T", errUnknownAddressRowType, row)
	}
}

// addressFieldsToInfo converts common SQLite address query fields to
// AddressInfo.
func addressFieldsToInfo(id int64, derivedAddressID sql.NullInt64,
	accountID sql.NullInt64, accountNumber sql.NullInt64,
	accountName sql.NullString, masterFingerprint sql.NullInt64,
	purpose sql.NullInt64, coinType sql.NullInt64,
	scriptTypeID int64, addressBranch sql.NullInt64,
	addressIndex sql.NullInt64, isDerived bool,
	accountIsDerived sql.NullBool, scriptPubKey []byte, pubKey []byte,
	createdAt time.Time, walletIsWatchOnly bool,
	hasScript bool, isUsed bool) (*db.AddressInfo, error) {

	return db.AddressRowToInfo(db.AddressInfoRow[int64]{
		ID:                id,
		DerivedAddressID:  derivedAddressID,
		AccountID:         accountID,
		AccountNumber:     accountNumber,
		AccountName:       accountName,
		MasterFingerprint: masterFingerprint,
		Purpose:           purpose,
		CoinType:          coinType,
		TypeID:            scriptTypeID,
		IsDerived:         isDerived,
		AccountIsDerived:  accountIsDerived,
		WalletIsWatchOnly: walletIsWatchOnly,
		HasScript:         hasScript,
		CreatedAt:         createdAt,
		AddressBranch:     addressBranch,
		AddressIndex:      addressIndex,
		ScriptPubKey:      scriptPubKey,
		PubKey:            pubKey,
		IsUsed:            isUsed,
		IDToAddrType:      db.IDToAddressType[int64],
	})
}
