package pg

import (
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5/pgtype"
)

// Verify the PostgreSQL Store implements the full db.AddressStore interface.
var _ db.AddressStore = (*Store)(nil)

// errUnknownAddressRowType is returned when an address row has an
// unrecognized concrete type.
var errUnknownAddressRowType = errors.New("unknown address row type")

// addressSecretRowToSecret converts a PostgreSQL address secret row to an
// AddressSecret struct.
func addressSecretRowToSecret(
	row sqlc.GetAddressSecretRow) (*db.AddressSecret, error) {

	return db.AddressSecretRowToSecret(db.AddressSecretRow{
		AddressID:        row.AddressID,
		EncryptedPrivKey: row.EncryptedPrivKey,
		EncryptedScript:  row.EncryptedScript,

		// SQL script ciphertext is always encrypted under the script
		// key; only kvdb records a per-row choice.
		ScriptIsSecret: true,
	})
}

// addressSecretByIDRowToSecret converts a PostgreSQL ID-selected secret row to
// the shared database type.
func addressSecretByIDRowToSecret(
	row sqlc.GetAddressSecretByIDRow) (*db.AddressSecret, error) {

	return db.AddressSecretRowToSecret(db.AddressSecretRow{
		AddressID:        row.AddressID,
		EncryptedPrivKey: row.EncryptedPrivKey,
		EncryptedScript:  row.EncryptedScript,
		ScriptIsSecret:   true,
	})
}

// addressInfoRow is a type constraint that unifies all PostgreSQL address
// row types that share the same field structure. This enables a single
// generic conversion function to handle all address query result types.
type addressInfoRow interface {
	sqlc.GetAddressByScriptPubKeyRow |
		sqlc.ListAddressesByAccountRow |
		sqlc.ListAddressesByScriptPubKeysRow |
		sqlc.ListRawImportedAddressesRow
}

// addressRowToInfo converts a PostgreSQL address row to an AddressInfo struct.
func addressRowToInfo[T addressInfoRow](row T) (*db.AddressInfo, error) {
	switch base := any(row).(type) {
	case sqlc.GetAddressByScriptPubKeyRow:
		return addressFieldsToInfo(
			base.ID, base.DerivedAddressID, base.AccountID,
			base.AccountNumber, base.AccountName, base.MasterFingerprint,
			base.Purpose, base.CoinType, base.ScriptTypeID,
			base.AddressBranch, base.AddressIndex, base.IsDerived,
			base.AccountIsDerived, base.ScriptPubKey,
			base.PubKey, base.CreatedAt.Time,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	case sqlc.ListAddressesByScriptPubKeysRow:
		return addressFieldsToInfo(
			base.ID, base.DerivedAddressID, base.AccountID,
			base.AccountNumber, base.AccountName, base.MasterFingerprint,
			base.Purpose, base.CoinType, base.ScriptTypeID,
			base.AddressBranch, base.AddressIndex, base.IsDerived,
			base.AccountIsDerived, base.ScriptPubKey,
			base.PubKey, base.CreatedAt.Time,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	case sqlc.ListRawImportedAddressesRow:
		return addressFieldsToInfo(
			base.ID, base.DerivedAddressID, base.AccountID,
			base.AccountNumber, base.AccountName, base.MasterFingerprint,
			base.Purpose, base.CoinType, base.ScriptTypeID,
			base.AddressBranch, base.AddressIndex, base.IsDerived,
			base.AccountIsDerived, base.ScriptPubKey,
			base.PubKey, base.CreatedAt.Time,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	case sqlc.ListAddressesByAccountRow:
		return addressFieldsToInfo(
			base.ID,
			pgtype.Int8{Int64: base.DerivedAddressID, Valid: true},
			pgtype.Int8{Int64: base.AccountID, Valid: true},
			base.AccountNumber,
			pgtype.Text{String: base.AccountName, Valid: true},
			base.MasterFingerprint,
			pgtype.Int8{Int64: base.Purpose, Valid: true},
			pgtype.Int8{Int64: base.CoinType, Valid: true},
			base.ScriptTypeID,
			pgtype.Int2{Int16: base.AddressBranch, Valid: true},
			pgtype.Int8{Int64: base.AddressIndex, Valid: true},
			base.IsDerived,
			pgtype.Bool{Bool: base.AccountIsDerived, Valid: true},
			base.ScriptPubKey, base.PubKey, base.CreatedAt.Time,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	default:
		return nil, fmt.Errorf("%w: %T", errUnknownAddressRowType, row)
	}
}

// addressFieldsToInfo converts common PostgreSQL address query fields to
// AddressInfo.
func addressFieldsToInfo(id int64, derivedAddressID pgtype.Int8,
	accountID pgtype.Int8, accountNumber pgtype.Int8,
	accountName pgtype.Text, masterFingerprint pgtype.Int8,
	purpose pgtype.Int8, coinType pgtype.Int8,
	scriptTypeID int16, addressBranch pgtype.Int2,
	addressIndex pgtype.Int8, isDerived bool,
	accountIsDerived pgtype.Bool, scriptPubKey []byte, pubKey []byte,
	createdAt time.Time, walletIsWatchOnly bool,
	hasScript bool, isUsed bool) (*db.AddressInfo, error) {

	return db.AddressRowToInfo(db.AddressInfoRow[int16]{
		ID:                id,
		DerivedAddressID:  nullableInt64(derivedAddressID),
		AccountID:         nullableInt64(accountID),
		AccountNumber:     nullableInt64(accountNumber),
		AccountName:       nullableString(accountName),
		MasterFingerprint: nullableInt64(masterFingerprint),
		Purpose:           nullableInt64(purpose),
		CoinType:          nullableInt64(coinType),
		TypeID:            scriptTypeID,
		IsDerived:         isDerived,
		AccountIsDerived:  nullableBool(accountIsDerived),
		WalletIsWatchOnly: walletIsWatchOnly,
		HasScript:         hasScript,
		CreatedAt:         createdAt,
		AddressBranch:     nullableInt16(addressBranch),
		AddressIndex:      nullableInt64(addressIndex),
		ScriptPubKey:      scriptPubKey,
		PubKey:            pubKey,
		IsUsed:            isUsed,
		IDToAddrType:      db.IDToAddressType[int16],
	})
}
