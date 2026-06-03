package db

import (
	"context"
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

	// errInvalidAccountOrigin is returned when an account origin ID from the
	// database does not correspond to a known AccountOrigin value. In practice,
	// this should never happen, but it's possible if the database is modified
	// incorrectly or the query is incorrect.
	errInvalidAccountOrigin = errors.New("invalid account origin")
)

// AccountPropsRow represents the raw database fields needed to construct
// AccountInfo.
type AccountPropsRow[AddrTypeId ~int16 | ~int64, AccOriginId any] struct {
	AccountNumber     sql.NullInt64
	AccountName       string
	OriginID          AccOriginId
	ExternalKeyCount  int64
	InternalKeyCount  int64
	ImportedKeyCount  int64
	PublicKey         []byte
	MasterFingerprint sql.NullInt64
	IsWatchOnly       bool
	CreatedAt         time.Time
	Purpose           int64
	CoinType          int64
	InternalTypeID    AddrTypeId
	ExternalTypeID    AddrTypeId
	IDToOriginType    func(AccOriginId) (AccountOrigin, error)
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
func AccountPropsRowToInfo[AddrTypeId ~int16 | ~int64, AccOriginId any](
	row AccountPropsRow[AddrTypeId, AccOriginId]) (*AccountInfo, error) {

	var accountNum uint32
	if row.AccountNumber.Valid {
		var err error

		accountNum, err = validateAccountNumber(row.AccountNumber.Int64)
		if err != nil {
			return nil, fmt.Errorf("account number: %w", err)
		}
	}

	origin, err := row.IDToOriginType(row.OriginID)
	if err != nil {
		return nil, fmt.Errorf("origin: %w", err)
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

	externalKeyCount, internalKeyCount, importedKeyCount, err := getKeyCounts(
		row.ExternalKeyCount, row.InternalKeyCount, row.ImportedKeyCount,
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
		AccountNumber:        accountNum,
		AccountName:          row.AccountName,
		Origin:               origin,
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
func BuildAccountInfo(accountNum uint32, accountName string,
	origin AccountOrigin, externalKeyCount, internalKeyCount,
	importedKeyCount uint32, isWatchOnly bool, createdAt time.Time,
	scope KeyScope, addrSchema ScopeAddrSchema, publicKey []byte,
	masterKeyFingerprint uint32,
	confirmedBalance, unconfirmedBalance btcutil.Amount) *AccountInfo {

	return &AccountInfo{
		AccountNumber:        accountNum,
		AccountName:          accountName,
		Origin:               origin,
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

// IDToAccountOrigin safely converts an integer to AccountOrigin. It returns an
// error if the value does not correspond to a known AccountOrigin value.
func IDToAccountOrigin[T ~int16 | ~int64](v T) (AccountOrigin, error) {
	if v < 0 || v > T(ImportedAccount) {
		return 0, fmt.Errorf("%w: %d", errInvalidAccountOrigin, v)
	}

	return AccountOrigin(v), nil
}

// AccountInfoRow represents the raw database fields needed to construct
// AccountInfo.
type AccountInfoRow[AccOriginId ~int16 | ~int64] struct {
	AccountNumber      sql.NullInt64
	AccountName        string
	OriginID           AccOriginId
	ExternalKeyCount   int64
	InternalKeyCount   int64
	ImportedKeyCount   int64
	PublicKey          []byte
	MasterFingerprint  sql.NullInt64
	IsWatchOnly        bool
	CreatedAt          time.Time
	Purpose            int64
	CoinType           int64
	InternalTypeID     AccOriginId
	ExternalTypeID     AccOriginId
	ConfirmedBalance   int64
	UnconfirmedBalance int64
	IDToOriginType     func(AccOriginId) (AccountOrigin, error)
}

// AccountRowToInfo converts raw database field values into an AccountInfo
// struct. It handles type conversion and validation for each field.
func AccountRowToInfo[AccOriginId ~int16 | ~int64](
	row AccountInfoRow[AccOriginId]) (*AccountInfo, error) {

	var accountNum uint32
	if row.AccountNumber.Valid {
		var err error

		accountNum, err = validateAccountNumber(row.AccountNumber.Int64)
		if err != nil {
			return nil, fmt.Errorf("account number: %w", err)
		}
	}

	origin, err := row.IDToOriginType(row.OriginID)
	if err != nil {
		return nil, fmt.Errorf("origin: %w", err)
	}

	purposeNum, err := Int64ToUint32(row.Purpose)
	if err != nil {
		return nil, fmt.Errorf("purpose: %w", err)
	}

	coinTypeNum, err := Int64ToUint32(row.CoinType)
	if err != nil {
		return nil, fmt.Errorf("coin type: %w", err)
	}

	externalKeyCount, internalKeyCount, importedKeyCount, err := getKeyCounts(
		row.ExternalKeyCount, row.InternalKeyCount, row.ImportedKeyCount,
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

	return BuildAccountInfo(
		accountNum, row.AccountName, origin, externalKeyCount, internalKeyCount,
		importedKeyCount, row.IsWatchOnly, row.CreatedAt,
		KeyScope{Purpose: purposeNum, Coin: coinTypeNum}, addrSchema,
		row.PublicKey, fingerprint,
		btcutil.Amount(row.ConfirmedBalance),
		btcutil.Amount(row.UnconfirmedBalance),
	), nil
}

// ProcessAccountRows converts a batch of dialect-specific account rows into
// AccountInfo pointers (ordered as input). The convert closure produces both
// the AccountInfo and the SQL row ID for each row; ProcessAccountRows stores
// the row ID on the returned AccountInfo via the unexported rowID field so
// AttachBalances can pair per-account balance rows back to their AccountInfo
// without threading a parallel ids slice.
func ProcessAccountRows[T any](rows []T,
	convert func(T) (*AccountInfo, int64, error)) ([]*AccountInfo, error) {

	infos := make([]*AccountInfo, len(rows))
	for i := range rows {
		info, id, err := convert(rows[i])
		if err != nil {
			return nil, err
		}

		info.rowID = id
		infos[i] = info
	}

	return infos, nil
}

// AccountBalance is the dialect-agnostic shape of a per-account balance row.
// Backends translate their sqlc balance rows into AccountBalance values when
// calling AttachBalances; the wire-level AccountBalancesByIDs query lives in
// each backend, and AccountBalance is the common contract its results land
// in for the shared merge logic.
type AccountBalance struct {
	// AccountID is the SQL row ID of the account this balance belongs to;
	// it matches the rowID populated on AccountInfo by ProcessAccountRows.
	AccountID int64

	// Confirmed is the sum of UTXO amounts (in satoshis) that are
	// considered confirmed by the wallet's confirmation policy.
	Confirmed int64

	// Unconfirmed is the sum of UTXO amounts (in satoshis) that are
	// unconfirmed.
	Unconfirmed int64
}

// AttachBalances merges per-account balances into a batch of AccountInfo
// values. The queryBalances callback executes the backend-specific
// AccountBalancesByIDs and returns its results as []AccountBalance. The
// merge step uses each AccountInfo's rowID (populated by ProcessAccountRows)
// to map balance rows back to their AccountInfo in a single pass. The
// returned slice preserves the input order of infos.
//
// When skipBalance is true or infos is empty, the query dispatch is skipped
// and every returned AccountInfo keeps zero balance fields. The query
// callback is invoked at most once per AttachBalances call.
func AttachBalances(ctx context.Context, walletID uint32, skipBalance bool,
	infos []*AccountInfo,
	queryBalances func(ctx context.Context, walletID uint32,
		ids []int64) ([]AccountBalance, error)) ([]AccountInfo, error) {

	out := make([]AccountInfo, len(infos))
	for i := range infos {
		out[i] = *infos[i]
	}

	if skipBalance || len(infos) == 0 {
		return out, nil
	}

	indexByID := make(map[int64]int, len(infos))
	ids := make([]int64, len(infos))

	for i := range infos {
		indexByID[infos[i].rowID] = i
		ids[i] = infos[i].rowID
	}

	balances, err := queryBalances(ctx, walletID, ids)
	if err != nil {
		return nil, fmt.Errorf("account balances: %w", err)
	}

	for _, bal := range balances {
		idx, ok := indexByID[bal.AccountID]
		if !ok {
			continue
		}

		out[idx].ConfirmedBalance = btcutil.Amount(bal.Confirmed)
		out[idx].UnconfirmedBalance = btcutil.Amount(bal.Unconfirmed)
	}

	return out, nil
}
