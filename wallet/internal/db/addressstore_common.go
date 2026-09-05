package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	// errInvalidDerivationPath is returned when the database contains an
	// invalid derivation path, such as a missing index or branch for a
	// derived address. This should never happen, but it's possible if the
	// database is modified incorrectly or the query is incorrect.
	errInvalidDerivationPath = errors.New("invalid derivation path")

	// errAddressShapeCorruption is returned when an address parent row and its
	// derived_addresses child row disagree about the structural shape.
	errAddressShapeCorruption = errors.New("address subtype invariant violated")
)

// ValidateAddressShape checks that the persisted address shape and
// derived_addresses child row agree with the nullable branch/index path columns
// selected from that row.
func ValidateAddressShape(isDerived bool, derivedAddressID sql.NullInt64,
	branch, index sql.NullInt64) error {

	hasChild := derivedAddressID.Valid

	switch {
	case isDerived && !hasChild:
		return fmt.Errorf("%w: derived address missing path row",
			errAddressShapeCorruption)

	case !isDerived && hasChild:
		return fmt.Errorf("%w: raw imported address has path row",
			errAddressShapeCorruption)

	default:
		return validateAddressPathColumns(hasChild, branch, index)
	}
}

// validateAddressPathColumns checks the branch/index path columns are
// consistent with whether the address has a derived_addresses child row.
func validateAddressPathColumns(hasChild bool, branch,
	index sql.NullInt64) error {

	hasPath := branch.Valid || index.Valid

	switch {
	case hasChild && (!branch.Valid || !index.Valid):
		return fmt.Errorf("%w: derived address missing path row",
			errAddressShapeCorruption)

	case !hasChild && hasPath:
		return fmt.Errorf("%w: raw imported address has path columns",
			errAddressShapeCorruption)

	default:
		return nil
	}
}

// AccountLookupKey contains the fields needed to look up an account.
type AccountLookupKey struct {
	WalletID    int64
	Purpose     int64
	CoinType    int64
	AccountName string
}

// AccountKeyFromParams extracts account lookup fields from params.
func AccountKeyFromParams(params NewDerivedAddressParams) AccountLookupKey {
	return AccountLookupKey{
		WalletID:    int64(params.WalletID),
		Purpose:     int64(params.Scope.Purpose),
		CoinType:    int64(params.Scope.Coin),
		AccountName: params.AccountName,
	}
}

// AddressInfoRow captures common fields from all address row types across
// PostgreSQL and SQLite backends. Uses generic type parameters to handle
// different ID types (int16 for PostgreSQL, int64 for SQLite).
type AddressInfoRow[TypeID any] struct {
	// ID is the database unique identifier for the address.
	ID int64

	// DerivedAddressID is the derived_addresses row ID when the address is an
	// HD child. Raw imported addresses leave this NULL.
	DerivedAddressID sql.NullInt64

	// AccountID is the database unique identifier for the account when the
	// address is an HD child. Raw imported addresses leave this NULL.
	AccountID sql.NullInt64

	// AccountNumber is the BIP44 account index of the owning account when the
	// account is derived. Imported accounts leave this NULL.
	AccountNumber sql.NullInt64

	// AccountName is the human-readable name of the owning account.
	// Raw imported addresses leave this NULL.
	AccountName sql.NullString

	// MasterFingerprint is the root fingerprint stored on the owning account.
	MasterFingerprint sql.NullInt64

	// AccountProps contains account metadata fetched separately when the
	// address query does not join all account fields.
	AccountProps *AccountInfo

	// Purpose is the BIP43 purpose component of the owning scope.
	// Raw imported addresses leave this NULL.
	Purpose sql.NullInt64

	// CoinType is the BIP44 coin type component of the owning scope.
	// Raw imported addresses leave this NULL.
	CoinType sql.NullInt64

	// TypeID is the database identifier for the address type.
	TypeID TypeID

	// IsDerived reports whether the address should have path/account data in
	// derived_addresses.
	IsDerived bool

	// AccountIsDerived reports the owning account's structural shape when the
	// address is derived. Raw imported addresses leave this NULL.
	AccountIsDerived sql.NullBool

	// WalletIsWatchOnly indicates whether the wallet is watch-only.
	WalletIsWatchOnly bool

	// HasScript indicates whether the address has an encrypted script.
	HasScript bool

	// CreatedAt is when the address was created in the wallet database.
	CreatedAt time.Time

	// AddressBranch is the BIP44 branch number (0=external, 1=internal/change),
	// or NULL for imported addresses.
	AddressBranch sql.NullInt64

	// AddressIndex is the BIP44 index within the branch, or NULL for imported
	// addresses.
	AddressIndex sql.NullInt64

	// ScriptPubKey is the script pubkey stored for the address.
	ScriptPubKey []byte

	// PubKey is the public key when the address is public-key based.
	PubKey []byte

	// IsUsed reports whether the address has a non-abandoned
	// on-chain transaction the wallet has observed. See ADR 0011.
	IsUsed bool

	// IDToAddrType converts TypeID to AddressType with validation.
	IDToAddrType func(TypeID) (AddressType, error)
}

// AddressSecretRow captures fields shared by address secret row types across
// backends.
type AddressSecretRow struct {
	// AddressID is the database unique identifier for the address.
	AddressID int64

	// EncryptedPrivKey is the encrypted private key for imported addresses.
	EncryptedPrivKey []byte

	// EncryptedScript is the encrypted script for script-based addresses.
	EncryptedScript []byte

	// ScriptIsSecret reports which key encrypted EncryptedScript. See
	// AddressSecret.ScriptIsSecret.
	ScriptIsSecret bool
}

// AddressSecretRowToSecret converts raw secret row fields into an AddressSecret
// with validation and ID conversion.
func AddressSecretRowToSecret(row AddressSecretRow) (*AddressSecret, error) {
	hasKey := len(row.EncryptedPrivKey) > 0
	hasScript := len(row.EncryptedScript) > 0

	if !hasKey && !hasScript {
		return nil, fmt.Errorf("address %d: %w", row.AddressID,
			ErrSecretNotFound)
	}

	addrID, err := Int64ToUint32(row.AddressID)
	if err != nil {
		return nil, fmt.Errorf("address ID: %w", err)
	}

	return &AddressSecret{
		AddressID:        addrID,
		EncryptedPrivKey: row.EncryptedPrivKey,
		EncryptedScript:  row.EncryptedScript,
		ScriptIsSecret:   row.ScriptIsSecret,
	}, nil
}

// convertAddressID converts a database address ID to uint32 with error
// handling.
func convertAddressID(id int64) (uint32, error) {
	addrID, err := Int64ToUint32(id)
	if err != nil {
		return 0, fmt.Errorf("address ID: %w", err)
	}

	return addrID, nil
}

// convertAccountMetadata converts account-level row data into wallet-facing
// fields on AddressInfo.
func convertAccountMetadata(accountNumber sql.NullInt64,
	masterFingerprint sql.NullInt64, purpose int64, coinType int64) (*uint32,
	uint32, KeyScope, error) {

	account, err := optionalAccountNumber(accountNumber)
	if err != nil {
		return nil, 0, KeyScope{}, err
	}

	var fingerprint uint32
	if masterFingerprint.Valid {
		converted, err := Int64ToUint32(masterFingerprint.Int64)
		if err != nil {
			return nil, 0, KeyScope{},
				fmt.Errorf("master fingerprint: %w", err)
		}

		fingerprint = converted
	}

	convertedPurpose, err := Int64ToUint32(purpose)
	if err != nil {
		return nil, 0, KeyScope{}, fmt.Errorf("scope purpose: %w", err)
	}

	convertedCoin, err := Int64ToUint32(coinType)
	if err != nil {
		return nil, 0, KeyScope{}, fmt.Errorf("scope coin type: %w", err)
	}

	return account, fingerprint, KeyScope{
		Purpose: convertedPurpose,
		Coin:    convertedCoin,
	}, nil
}

// convertAddressAccountMetadata converts the owning account metadata for an
// address row. SQL backends may fetch account properties separately to avoid
// widening address queries.
func convertAddressAccountMetadata[TypeID any](
	row AddressInfoRow[TypeID]) (*uint32, string, uint32,
	KeyScope, error) {

	if row.AccountProps != nil {
		var masterFingerprint uint32
		if row.AccountProps.MasterKeyFingerprint != nil {
			masterFingerprint = *row.AccountProps.MasterKeyFingerprint
		}

		return row.AccountProps.AccountNumber, row.AccountProps.AccountName,
			masterFingerprint,
			row.AccountProps.KeyScope, nil
	}

	if !row.IsDerived {
		return nil, "", 0, KeyScope{}, nil
	}

	if !row.AccountName.Valid || !row.Purpose.Valid || !row.CoinType.Valid {
		return nil, "", 0, KeyScope{}, fmt.Errorf("%w: derived address "+
			"missing account scope metadata", errAddressShapeCorruption)
	}

	accountNumber, masterFingerprint, keyScope, err :=
		convertAccountMetadata(
			row.AccountNumber, row.MasterFingerprint, row.Purpose.Int64,
			row.CoinType.Int64,
		)
	if err != nil {
		return nil, "", 0, KeyScope{}, err
	}

	return accountNumber, row.AccountName.String, masterFingerprint, keyScope,
		nil
}

// validateAddressAccountShape checks that derived address rows expose account
// metadata consistent with the owning account's importedness.
func validateAddressAccountShape[TypeID any](
	row AddressInfoRow[TypeID]) error {

	if !row.IsDerived {
		return validateRawAddressAccountShape(row)
	}

	if !row.AccountID.Valid || !row.AccountIsDerived.Valid {
		return fmt.Errorf("%w: derived address missing account metadata",
			errAddressShapeCorruption)
	}

	return validateAddressAccountNumberShape(
		row.AccountIsDerived.Bool, row.AccountNumber,
	)
}

// validateRawAddressAccountShape verifies raw imported address rows do not
// carry account metadata.
func validateRawAddressAccountShape[TypeID any](
	row AddressInfoRow[TypeID]) error {

	if row.AccountID.Valid || row.AccountIsDerived.Valid ||
		row.AccountNumber.Valid || row.AccountName.Valid ||
		row.MasterFingerprint.Valid || row.Purpose.Valid ||
		row.CoinType.Valid {

		return fmt.Errorf("%w: raw imported address has account metadata",
			errAddressShapeCorruption)
	}

	return nil
}

// validateAddressAccountNumberShape verifies address account metadata uses
// account numbers only for wallet-derived accounts.
func validateAddressAccountNumberShape(accountIsDerived bool,
	accountNumber sql.NullInt64) error {

	if !accountIsDerived {
		if accountNumber.Valid {
			return fmt.Errorf("%w: non-derived account has derived "+
				"account number", errAccountShapeCorruption)
		}

		return nil
	}

	if !accountNumber.Valid {
		return fmt.Errorf("%w: derived account missing account number",
			errAccountShapeCorruption)
	}

	return nil
}

// ApplyAddressAccountMetadata converts and copies raw account metadata onto an
// address info returned by a create path.
func ApplyAddressAccountMetadata(info *AddressInfo,
	accountNumber sql.NullInt64, accountName string,
	masterFingerprint sql.NullInt64, purpose, coinType int64,
	isImported bool) error {

	accountNum, fingerprint, keyScope, err := convertAccountMetadata(
		accountNumber, masterFingerprint, purpose, coinType,
	)
	if err != nil {
		return err
	}

	info.AccountNumber = accountNum
	info.AccountName = accountName
	info.KeyScope = keyScope
	info.MasterKeyFingerprint = fingerprint
	info.IsImported = isImported

	return nil
}

// convertAddressMetadata converts address type IDs with error handling.
func convertAddressMetadata[TypeID any](
	row AddressInfoRow[TypeID]) (AddressType, error) {

	addrType, err := row.IDToAddrType(row.TypeID)
	if err != nil {
		return 0, fmt.Errorf("address type: %w", err)
	}

	return addrType, nil
}

// convertAddressPath converts BIP44 branch/index values into uint32 fields.
// Imported addresses must have both branch/index unset and return zero values.
// Derived addresses must have both fields set and convertible to uint32.
func convertAddressPath(hasDerivedPath bool, branch,
	index sql.NullInt64) (uint32, uint32, error) {

	if !hasDerivedPath {
		if branch.Valid || index.Valid {
			return 0, 0, errInvalidDerivationPath
		}

		return 0, 0, nil
	}

	if !branch.Valid || !index.Valid {
		return 0, 0, errInvalidDerivationPath
	}

	addrBranch, err := Int64ToUint32(branch.Int64)
	if err != nil {
		return 0, 0, fmt.Errorf("address branch: %w", err)
	}

	addrIndex, err := Int64ToUint32(index.Int64)
	if err != nil {
		return 0, 0, fmt.Errorf("address index: %w", err)
	}

	return addrBranch, addrIndex, nil
}

// AddressRowToInfo converts raw database field values into an AddressInfo
// struct. It handles type conversion and validation for each field.
//
// Watch-only state is copied directly from the wallet-level flag. Address
// secret presence is not used to infer public watch-only state.
func AddressRowToInfo[TypeID any](
	row AddressInfoRow[TypeID]) (*AddressInfo, error) {

	id, err := convertAddressID(row.ID)
	if err != nil {
		return nil, err
	}

	err = ValidateAddressShape(
		row.IsDerived, row.DerivedAddressID, row.AddressBranch,
		row.AddressIndex,
	)
	if err != nil {
		return nil, err
	}

	err = validateAddressAccountShape(row)
	if err != nil {
		return nil, err
	}

	var accountID *uint32
	if row.AccountID.Valid {
		accountID, err = optionalAccountID(row.AccountID.Int64)
		if err != nil {
			return nil, err
		}
	}

	accountNumber, accountName, masterFingerprint, keyScope, err :=
		convertAddressAccountMetadata(row)
	if err != nil {
		return nil, err
	}

	addrType, err := convertAddressMetadata(row)
	if err != nil {
		return nil, err
	}

	addrBranch, addrIndex, err := convertAddressPath(
		row.IsDerived, row.AddressBranch, row.AddressIndex,
	)
	if err != nil {
		return nil, err
	}

	isImported := !row.IsDerived
	if row.IsDerived {
		isImported = !row.AccountIsDerived.Bool
	}

	return &AddressInfo{
		ID:                   id,
		AccountID:            accountID,
		AccountNumber:        accountNumber,
		AccountName:          accountName,
		KeyScope:             keyScope,
		MasterKeyFingerprint: masterFingerprint,
		AddrType:             addrType,
		CreatedAt:            row.CreatedAt,
		IsImported:           isImported,
		HasDerivationPath:    row.IsDerived,
		Branch:               addrBranch,
		Index:                addrIndex,
		ScriptPubKey:         row.ScriptPubKey,
		PubKey:               row.PubKey,
		HasScript:            row.HasScript,
		IsWatchOnly:          row.WalletIsWatchOnly,
		IsUsed:               row.IsUsed,
	}, nil
}
