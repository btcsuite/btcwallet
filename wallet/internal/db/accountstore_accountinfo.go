package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

var (
	// ErrNilDBAccountNumber is returned when the database returns a nil account
	// number. In practice, this should never happen, but it's possible if the
	// database is modified incorrectly or the query is incorrect.
	ErrNilDBAccountNumber = errors.New("database returned nil account number")

	// errAccountShapeCorruption is returned when an account row's shape marker
	// and nullable account number disagree about its structural shape.
	errAccountShapeCorruption = errors.New("account subtype invariant violated")
)

// AccountPropsRow represents the raw database fields needed to construct
// AccountInfo.
type AccountPropsRow[AddrTypeId ~int16 | ~int64] struct {
	// RowID is the backend-local account row identifier.
	RowID int64

	// AccountNumber is the nullable BIP44 number for derived accounts.
	AccountNumber sql.NullInt64

	// AccountName is the human-readable account name.
	AccountName string

	// IsDerived reports whether the row represents a wallet-derived account.
	IsDerived bool

	// ExternalKeyCount is the number of external keys derived so far.
	ExternalKeyCount int64

	// InternalKeyCount is the number of internal keys derived so far.
	InternalKeyCount int64

	// PublicKey is the serialized account public key when one is available.
	PublicKey []byte

	// MasterFingerprint is the nullable account master key fingerprint.
	MasterFingerprint sql.NullInt64

	// IsWatchOnly reports the wallet-level watch-only state.
	IsWatchOnly bool

	// CreatedAt is the account creation timestamp.
	CreatedAt time.Time

	// Purpose is the key-scope purpose value.
	Purpose int64

	// CoinType is the key-scope coin type value.
	CoinType int64

	// InternalTypeID is the SQL address type ID for change addresses.
	InternalTypeID AddrTypeId

	// ExternalTypeID is the SQL address type ID for receiving addresses.
	ExternalTypeID AddrTypeId
}

// validateAccountNumber converts a database account number to uint32 while
// enforcing the wallet-compatible derived account ceiling.
func validateAccountNumber(accountNumber int64) (uint32, error) {
	if accountNumber > int64(MaxAccountNumber) {
		return 0, fmt.Errorf("%w: account number %d exceeds max %d",
			ErrMaxAccountNumberReached, accountNumber, MaxAccountNumber)
	}

	return Int64ToUint32(accountNumber)
}

// optionalAccountID converts a positive SQL account row ID to a pointer.
func optionalAccountID(rowID int64) (*uint32, error) {
	var accountID *uint32
	if rowID != 0 {
		converted, err := Int64ToUint32(rowID)
		if err != nil {
			return nil, fmt.Errorf("account ID: %w", err)
		}

		accountID = &converted
	}

	return accountID, nil
}

// optionalAccountNumber converts a nullable SQL account number to a pointer.
func optionalAccountNumber(accountNumber sql.NullInt64) (*uint32, error) {
	var result *uint32
	if accountNumber.Valid {
		converted, err := validateAccountNumber(accountNumber.Int64)
		if err != nil {
			return nil, fmt.Errorf("account number: %w", err)
		}

		result = &converted
	}

	return result, nil
}

// getKeyCounts converts external, internal, and imported key counts from
// int64 to uint32 and handles errors.
func getKeyCounts(external, internal, imported int64) (uint32, uint32,
	uint32, error) {

	externalKeyCount, err := Int64ToUint32(external)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("external key count: %w", err)
	}

	internalKeyCount, err := Int64ToUint32(internal)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("internal key count: %w", err)
	}

	importedKeyCount, err := Int64ToUint32(imported)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("imported key count: %w", err)
	}

	return externalKeyCount, internalKeyCount, importedKeyCount, nil
}

// validateAccountShape checks that account shape agrees with account-number
// presence.
func validateAccountShape(isDerived bool,
	accountNumber sql.NullInt64) error {

	switch {
	case isDerived && !accountNumber.Valid:
		return fmt.Errorf("%w: derived account missing account number",
			errAccountShapeCorruption)

	case !isDerived && accountNumber.Valid:
		return fmt.Errorf("%w: non-derived account has derived account number",
			errAccountShapeCorruption)

	default:
		return nil
	}
}

// DerivedAddressAccountNumber converts a derived account number from an
// account lookup row to the wallet-compatible uint32 account number.
func DerivedAddressAccountNumber(accountNumber sql.NullInt64) (uint32,
	error) {

	if !accountNumber.Valid {
		return 0, ErrNilDBAccountNumber
	}

	return validateAccountNumber(accountNumber.Int64)
}

// DerivedAddressAccountSchema builds the effective address schema from the
// key-scope address-type IDs materialized by an account lookup row.
func DerivedAddressAccountSchema[AddrTypeID ~int16 | ~int64](
	internalTypeID AddrTypeID, externalTypeID AddrTypeID) (ScopeAddrSchema,
	error) {

	internalType, err := IDToAddressType(internalTypeID)
	if err != nil {
		return ScopeAddrSchema{}, fmt.Errorf("internal address type: %w", err)
	}

	externalType, err := IDToAddressType(externalTypeID)
	if err != nil {
		return ScopeAddrSchema{}, fmt.Errorf("external address type: %w", err)
	}

	return ScopeAddrSchema{
		InternalAddrType: internalType,
		ExternalAddrType: externalType,
	}, nil
}

// AccountPropsRowToInfo converts a database row containing full account
// properties into an AccountInfo struct.
func AccountPropsRowToInfo[AddrTypeId ~int16 | ~int64](
	row AccountPropsRow[AddrTypeId]) (*AccountInfo, error) {

	err := validateAccountShape(row.IsDerived, row.AccountNumber)
	if err != nil {
		return nil, err
	}

	accountID, err := optionalAccountID(row.RowID)
	if err != nil {
		return nil, err
	}

	accountNum, err := optionalAccountNumber(row.AccountNumber)
	if err != nil {
		return nil, err
	}

	purposeNum, err := Int64ToUint32(row.Purpose)
	if err != nil {
		return nil, fmt.Errorf("purpose: %w", err)
	}

	coinTypeNum, err := Int64ToUint32(row.CoinType)
	if err != nil {
		return nil, fmt.Errorf("coin type: %w", err)
	}

	var fingerprint uint32
	if row.MasterFingerprint.Valid {
		fingerprint, err = Int64ToUint32(row.MasterFingerprint.Int64)
		if err != nil {
			return nil, fmt.Errorf("master fingerprint: %w", err)
		}
	}

	// Normalized SQL account rows track HD branch counters only. Individually
	// imported address counts are a legacy kvdb/waddrmgr account property.
	externalKeyCount, internalKeyCount, importedKeyCount, err := getKeyCounts(
		row.ExternalKeyCount, row.InternalKeyCount, 0,
	)
	if err != nil {
		return nil, err
	}

	addrSchema, err := DerivedAddressAccountSchema(
		row.InternalTypeID, row.ExternalTypeID,
	)
	if err != nil {
		return nil, fmt.Errorf("address schema: %w", err)
	}

	return &AccountInfo{
		AccountID:            accountID,
		AccountNumber:        accountNum,
		AccountName:          row.AccountName,
		IsImported:           !row.IsDerived,
		ExternalKeyCount:     externalKeyCount,
		InternalKeyCount:     internalKeyCount,
		ImportedKeyCount:     importedKeyCount,
		PublicKey:            row.PublicKey,
		MasterKeyFingerprint: fingerprint,
		KeyScope: KeyScope{
			Purpose: purposeNum,
			Coin:    coinTypeNum,
		},
		AddrSchema:  addrSchema,
		IsWatchOnly: row.IsWatchOnly,
		CreatedAt:   row.CreatedAt,
	}, nil
}

// addrTypeFromWaddrmgr maps a legacy waddrmgr.AddressType to the database
// AddressType. The two enums share names but not ordinal values, so a direct
// cast would corrupt the schema (e.g. waddrmgr.PubKeyHash=0 collides with
// db.RawPubKey=0). Script-bearing variants are folded into their hashing
// counterparts because ScopeAddrSchema does not carry script metadata.
func addrTypeFromWaddrmgr(t waddrmgr.AddressType) (AddressType, error) {
	switch t {
	case waddrmgr.RawPubKey:
		return RawPubKey, nil

	case waddrmgr.PubKeyHash:
		return PubKeyHash, nil

	case waddrmgr.Script:
		return ScriptHash, nil

	case waddrmgr.NestedWitnessPubKey:
		return NestedWitnessPubKey, nil

	case waddrmgr.WitnessPubKey:
		return WitnessPubKey, nil

	case waddrmgr.WitnessScript:
		return WitnessScript, nil

	case waddrmgr.TaprootPubKey:
		return TaprootPubKey, nil

	case waddrmgr.TaprootScript:
		// ScopeAddrSchema does not carry script metadata; collapse the
		// script-bearing taproot type onto its pubkey-hash counterpart
		// so the schema round-trip stays lossless for the type axis.
		return TaprootPubKey, nil

	default:
		return 0, fmt.Errorf("%w: waddrmgr address type %d",
			ErrInvalidParam, t)
	}
}

// ScopeAddrSchemaFromWaddrmgr converts a legacy address-manager schema into
// the database account schema shape. An unknown address type is surfaced as
// ErrInvalidParam rather than coerced to a different enum value.
func ScopeAddrSchemaFromWaddrmgr(
	schema waddrmgr.ScopeAddrSchema) (ScopeAddrSchema, error) {

	external, err := addrTypeFromWaddrmgr(schema.ExternalAddrType)
	if err != nil {
		return ScopeAddrSchema{}, fmt.Errorf("external: %w", err)
	}

	internal, err := addrTypeFromWaddrmgr(schema.InternalAddrType)
	if err != nil {
		return ScopeAddrSchema{}, fmt.Errorf("internal: %w", err)
	}

	return ScopeAddrSchema{
		ExternalAddrType: external,
		InternalAddrType: internal,
	}, nil
}

// BuildAccountInfo creates an AccountInfo with the provided values.
// confirmedBalance and unconfirmedBalance are populated verbatim from
// the caller; create paths pass zero (a fresh account has no UTXOs)
// while the read paths feed real values from the dedicated
// AccountBalance / AccountBalances queries.
func BuildAccountInfo(accountID *uint32, accountNum *uint32,
	accountName string,
	isImported bool, externalKeyCount, internalKeyCount,
	importedKeyCount uint32, isWatchOnly bool, createdAt time.Time,
	scope KeyScope, addrSchema ScopeAddrSchema, publicKey []byte,
	masterKeyFingerprint uint32,
	confirmedBalance, unconfirmedBalance btcutil.Amount) *AccountInfo {

	return &AccountInfo{
		AccountID:            accountID,
		AccountNumber:        accountNum,
		AccountName:          accountName,
		IsImported:           isImported,
		ExternalKeyCount:     externalKeyCount,
		InternalKeyCount:     internalKeyCount,
		ImportedKeyCount:     importedKeyCount,
		ConfirmedBalance:     confirmedBalance,
		UnconfirmedBalance:   unconfirmedBalance,
		IsWatchOnly:          isWatchOnly,
		CreatedAt:            createdAt,
		KeyScope:             scope,
		AddrSchema:           addrSchema,
		PublicKey:            publicKey,
		MasterKeyFingerprint: masterKeyFingerprint,
	}
}

// AccountInfoRow represents the raw database fields needed to construct
// AccountInfo.
type AccountInfoRow[AccOriginId ~int16 | ~int64] struct {
	// RowID is the backend-local account row identifier.
	RowID int64

	// AccountNumber is the nullable BIP44 number for derived accounts.
	AccountNumber sql.NullInt64

	// AccountName is the human-readable account name.
	AccountName string

	// IsDerived reports whether the row represents a wallet-derived account.
	IsDerived bool

	// ExternalKeyCount is the number of external keys derived so far.
	ExternalKeyCount int64

	// InternalKeyCount is the number of internal keys derived so far.
	InternalKeyCount int64

	// PublicKey is the serialized account public key when one is available.
	PublicKey []byte

	// MasterFingerprint is the nullable account master key fingerprint.
	MasterFingerprint sql.NullInt64

	// IsWatchOnly reports the wallet-level watch-only state.
	IsWatchOnly bool

	// CreatedAt is the account creation timestamp.
	CreatedAt time.Time

	// Purpose is the key-scope purpose value.
	Purpose int64

	// CoinType is the key-scope coin type value.
	CoinType int64

	// InternalTypeID is the SQL address type ID for change addresses.
	InternalTypeID AccOriginId

	// ExternalTypeID is the SQL address type ID for receiving addresses.
	ExternalTypeID AccOriginId

	// ConfirmedBalance is the confirmed account balance in satoshis.
	ConfirmedBalance int64

	// UnconfirmedBalance is the unconfirmed account balance in satoshis.
	UnconfirmedBalance int64
}

// AccountRowToInfo converts raw database field values into an AccountInfo
// struct. It handles type conversion and validation for each field.
func AccountRowToInfo[AccOriginId ~int16 | ~int64](
	row AccountInfoRow[AccOriginId]) (*AccountInfo, error) {

	err := validateAccountShape(row.IsDerived, row.AccountNumber)
	if err != nil {
		return nil, err
	}

	accountID, err := optionalAccountID(row.RowID)
	if err != nil {
		return nil, err
	}

	accountNum, err := optionalAccountNumber(row.AccountNumber)
	if err != nil {
		return nil, err
	}

	purposeNum, err := Int64ToUint32(row.Purpose)
	if err != nil {
		return nil, fmt.Errorf("purpose: %w", err)
	}

	coinTypeNum, err := Int64ToUint32(row.CoinType)
	if err != nil {
		return nil, fmt.Errorf("coin type: %w", err)
	}

	// Normalized SQL account rows track HD branch counters only. Individually
	// imported address counts are a legacy kvdb/waddrmgr account property.
	externalKeyCount, internalKeyCount, importedKeyCount, err := getKeyCounts(
		row.ExternalKeyCount, row.InternalKeyCount, 0,
	)
	if err != nil {
		return nil, err
	}

	var fingerprint uint32
	if row.MasterFingerprint.Valid {
		fingerprint, err = Int64ToUint32(row.MasterFingerprint.Int64)
		if err != nil {
			return nil, fmt.Errorf("master fingerprint: %w", err)
		}
	}

	addrSchema, err := DerivedAddressAccountSchema(
		row.InternalTypeID, row.ExternalTypeID,
	)
	if err != nil {
		return nil, fmt.Errorf("address schema: %w", err)
	}

	info := BuildAccountInfo(
		accountID, accountNum, row.AccountName, !row.IsDerived,
		externalKeyCount,
		internalKeyCount, importedKeyCount, row.IsWatchOnly,
		row.CreatedAt,
		KeyScope{Purpose: purposeNum, Coin: coinTypeNum}, addrSchema,
		row.PublicKey, fingerprint,
		btcutil.Amount(row.ConfirmedBalance),
		btcutil.Amount(row.UnconfirmedBalance),
	)
	info.rowID = row.RowID

	return info, nil
}
