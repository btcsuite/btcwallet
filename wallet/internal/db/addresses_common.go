package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"
)

// DefaultImportedAccountName is the default account name for imported
// addresses.
const DefaultImportedAccountName = "imported"

var (
	// errInvalidOriginID is returned when an origin ID from the database is
	// outside the valid range [DerivedAccount, ImportedAccount]. In practice,
	// this should never happen, but it's possible if the database is modified
	// incorrectly or the query is incorrect.
	errInvalidOriginID = errors.New("invalid origin ID: must be 0 or 1")

	// errInvalidDerivationPath is returned when the database contains an
	// invalid derivation path, such as a missing index or branch for a
	// derived address. This should never happen, but it's possible if the
	// database is modified incorrectly or the query is incorrect.
	errInvalidDerivationPath = errors.New("invalid derivation path")
)

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

// AccountKeyFromImportedParams extracts account lookup fields from imported
// params using DefaultImportedAccountName.
func AccountKeyFromImportedParams(
	params NewImportedAddressParams) AccountLookupKey {

	return AccountLookupKey{
		WalletID:    int64(params.WalletID),
		Purpose:     int64(params.Scope.Purpose),
		CoinType:    int64(params.Scope.Coin),
		AccountName: DefaultImportedAccountName,
	}
}

// GetAddressSecret is a generic helper that retrieves address secret
// information using the provided getter function and converts it to an
// AddressSecret with error handling.
func GetAddressSecret[Row any](ctx context.Context,
	getter func(context.Context, int64) (Row, error), addressID uint32,
	toSecret func(Row) (*AddressSecret, error)) (*AddressSecret, error) {

	row, err := getter(ctx, int64(addressID))
	if err == nil {
		return toSecret(row)
	}

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("address secret for address %d: %w",
			addressID, ErrAddressNotFound)
	}

	return nil, fmt.Errorf("get address secret: %w", err)
}

// validate validates the required fields for creating an imported address.
// Returns sentinel errors on failure.
func (p NewImportedAddressParams) validate() error {
	if len(p.ScriptPubKey) == 0 {
		return ErrMissingScriptPubKey
	}

	return nil
}

// isWatchOnly returns true if the params include neither a private key nor
// a redeem or witness script.
func (p NewImportedAddressParams) isWatchOnly() bool {
	noPrivKey := len(p.EncryptedPrivateKey) == 0
	noScript := len(p.EncryptedScript) == 0

	if noPrivKey && noScript {
		return true
	}

	return false
}

// IDToOrigin safely converts an integer to AccountOrigin. It returns an error
// if the value is outside [DerivedAccount, ImportedAccount].
func IDToOrigin[T ~int16 | ~int64](v T) (AccountOrigin, error) {
	if v < 0 || v > T(ImportedAccount) {
		return 0, fmt.Errorf("address origin: %d: %w", v, errInvalidOriginID)
	}

	return AccountOrigin(uint8(v)), nil
}

// AddressInfoRow captures common fields from all address row types across
// PostgreSQL and SQLite backends. Uses generic type parameters to handle
// different ID types (int16 for PostgreSQL, int64 for SQLite).
type AddressInfoRow[TypeID, OriginIDType any] struct {
	// ID is the database unique identifier for the address.
	ID int64

	// AccountID is the database unique identifier for the account.
	AccountID int64

	// TypeID is the database identifier for the address type.
	TypeID TypeID

	// OriginID is the database identifier for address origin (derived=0,
	// imported=1).
	OriginID OriginIDType

	// HasPrivateKey indicates whether the address has an encrypted private key.
	HasPrivateKey bool

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

	// ScriptPubKey is the script pubkey. Zero value for derived addresses.
	ScriptPubKey []byte

	// PubKey is the public key. Zero value for derived addresses.
	PubKey []byte

	// IDToAddrType converts TypeID to AddressType with validation.
	IDToAddrType func(TypeID) (AddressType, error)

	// IDToOrigin converts OriginIDType to AccountOrigin with validation.
	IDToOrigin func(OriginIDType) (AccountOrigin, error)
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
	}, nil
}

// convertAddressIDs converts database IDs to their respective uint32 values
// with error handling.
func convertAddressIDs(id, accountID int64) (uint32, uint32, error) {
	addrID, err := Int64ToUint32(id)
	if err != nil {
		return 0, 0, fmt.Errorf("address ID: %w", err)
	}

	acctID, err := Int64ToUint32(accountID)
	if err != nil {
		return 0, 0, fmt.Errorf("account ID: %w", err)
	}

	return addrID, acctID, nil
}

// newImportedAddressTx handles the shared transaction flow for creating an
// imported address across database backends.
func newImportedAddressTx[QTX any, Row any, CreateArgs any, InsertArgs any](
	ctx context.Context, create func(context.Context, CreateArgs) (Row, error),
	createArgs CreateArgs,
	insertFn func(QTX) func(context.Context, InsertArgs) error, qtx QTX,
	insertArgs func(int64, NewImportedAddressParams) InsertArgs,
	params NewImportedAddressParams, accountID int64,
	rowID func(Row) int64, rowCreatedAt func(Row) time.Time) (*AddressInfo,
	error) {

	addrRow, err := create(ctx, createArgs)
	if err != nil {
		return nil, fmt.Errorf("create imported address: %w", err)
	}

	addrID := rowID(addrRow)
	if !params.isWatchOnly() {
		err = insertFn(qtx)(ctx, insertArgs(addrID, params))
		if err != nil {
			return nil, fmt.Errorf("insert address secret: %w", err)
		}
	}

	id, acctID, err := convertAddressIDs(addrID, accountID)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		ID:           id,
		AccountID:    acctID,
		AddrType:     params.AddressType,
		CreatedAt:    rowCreatedAt(addrRow),
		Origin:       ImportedAccount,
		ScriptPubKey: params.ScriptPubKey,
		PubKey:       params.PubKey,
		IsWatchOnly:  params.isWatchOnly(),
	}, nil
}

// convertAddressMetadata converts address type and origin IDs with error
// handling.
func convertAddressMetadata[TypeID, OriginIDType any](
	row AddressInfoRow[TypeID, OriginIDType]) (AddressType, AccountOrigin,
	error) {

	addrType, err := row.IDToAddrType(row.TypeID)
	if err != nil {
		return 0, 0, fmt.Errorf("address type: %w", err)
	}

	origin, err := row.IDToOrigin(row.OriginID)
	if err != nil {
		return 0, 0, fmt.Errorf("address origin: %w", err)
	}

	return addrType, origin, nil
}

// convertAddressPath converts BIP44 branch/index values into uint32 fields.
// Imported addresses must have both branch/index unset and return zero values.
// Derived addresses must have both fields set and convertible to uint32.
func convertAddressPath(origin AccountOrigin, branch,
	index sql.NullInt64) (uint32, uint32, error) {

	if origin == ImportedAccount {
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

// addressRowToInfo converts raw database field values into an AddressInfo
// struct. It handles type conversion and validation for each field.
func addressRowToInfo[TypeID, OriginIDType any](
	row AddressInfoRow[TypeID, OriginIDType]) (*AddressInfo, error) {

	id, accountID, err := convertAddressIDs(row.ID, row.AccountID)
	if err != nil {
		return nil, err
	}

	addrType, origin, err := convertAddressMetadata(row)
	if err != nil {
		return nil, err
	}

	addrBranch, addrIndex, err := convertAddressPath(
		origin, row.AddressBranch, row.AddressIndex,
	)
	if err != nil {
		return nil, err
	}

	isWatchOnly := origin == ImportedAccount && !row.HasPrivateKey &&
		!row.HasScript

	return &AddressInfo{
		ID:           id,
		AccountID:    accountID,
		AddrType:     addrType,
		CreatedAt:    row.CreatedAt,
		Origin:       origin,
		Branch:       addrBranch,
		Index:        addrIndex,
		ScriptPubKey: row.ScriptPubKey,
		PubKey:       row.PubKey,
		IsWatchOnly:  isWatchOnly,
	}, nil
}

// GetAddress is a generic helper that retrieves a single address using the
// provided getter function. It handles sql.ErrNoRows mapping and delegates
// conversion to the toInfo function.
func GetAddress[T any, Args any](ctx context.Context,
	getter func(context.Context, Args) (T, error), args Args,
	toInfo func(T) (*AddressInfo, error)) (*AddressInfo, error) {

	row, err := getter(ctx, args)
	if err == nil {
		return toInfo(row)
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("get address: %w", err)
	}

	return nil, ErrAddressNotFound
}

// NextListAddressesQuery returns a query with its pagination cursor advanced to
// the provided value.
func NextListAddressesQuery(q ListAddressesQuery,
	cursor uint32) ListAddressesQuery {

	q.Page = q.Page.WithAfter(cursor)

	return q
}

// DerivedAddressAdapters groups the functions needed to create a
// derived address across different database backends.
type DerivedAddressAdapters[QTX any, AccountRow any, AccountParams any,
	AddrRow any] struct {

	// GetAccount retrieves an account by the provided parameters.
	GetAccount func(context.Context, AccountParams) (AccountRow, error)

	// AccountParams converts params to account lookup parameters.
	AccountParams func(NewDerivedAddressParams) AccountParams

	// GetAccountID extracts the account ID from an account row.
	GetAccountID func(AccountRow) int64

	// GetExtIndex returns a function to get the external index.
	GetExtIndex func(QTX) func(context.Context, int64) (int64, error)

	// GetIntIndex returns a function to get the internal index.
	GetIntIndex func(QTX) func(context.Context, int64) (int64, error)

	// CreateAddr returns a function to create an address row.
	CreateAddr func(QTX) func(context.Context, int64, AddressType, uint32,
		uint32, []byte) (AddrRow, error)

	// RowID extracts the ID from an address row.
	RowID func(AddrRow) int64

	// RowCreatedAt extracts the creation time from an address row.
	RowCreatedAt func(AddrRow) time.Time
}

// ImportedAddressAdapters groups the functions needed to create an
// imported address across different database backends.
type ImportedAddressAdapters[QTX any, AccountRow any,
	AccountParams any, CreateArgs any, AddrRow any,
	SecretParams any] struct {

	// GetAccount retrieves an account by the provided parameters.
	GetAccount func(context.Context, AccountParams) (AccountRow, error)

	// AccountParams converts params to account lookup parameters.
	AccountParams func(NewImportedAddressParams) AccountParams

	// GetAccountID extracts the account ID from an account row.
	GetAccountID func(AccountRow) int64

	// CreateAddr returns a function to create an address row.
	CreateAddr func(QTX) func(context.Context, CreateArgs) (AddrRow, error)

	// CreateParams converts accountID and params to address creation
	// parameters.
	CreateParams func(int64, NewImportedAddressParams) CreateArgs

	// InsertSecret returns a function to insert address secret.
	InsertSecret func(QTX) func(context.Context, SecretParams) error

	// SecretParams converts address ID and params to secret parameters.
	SecretParams func(int64, NewImportedAddressParams) SecretParams

	// RowID extracts the ID from an address row.
	RowID func(AddrRow) int64

	// RowCreatedAt extracts the creation time from an address row.
	RowCreatedAt func(AddrRow) time.Time
}

// GetAddressFunc defines a function signature for retrieving a single address.
type GetAddressFunc func(context.Context, GetAddressQuery) (*AddressInfo, error)

// GetAddressByQuery validates the query and executes the script-based lookup.
func GetAddressByQuery(ctx context.Context, query GetAddressQuery,
	getter GetAddressFunc) (*AddressInfo, error) {

	if len(query.ScriptPubKey) == 0 {
		return nil, ErrInvalidAddressQuery
	}

	return getter(ctx, query)
}

// createDerivedAddress is a generic helper that encapsulates the shared
// derived address creation logic. It calls derivedAddressInput to prepare
// inputs and then createFn to create the address.
func createDerivedAddress[T any](ctx context.Context,
	params NewDerivedAddressParams, accountID int64,
	getExtIndex func(context.Context, int64) (int64, error),
	getIntIndex func(context.Context, int64) (int64, error),
	createFn func(context.Context, int64, AddressType, uint32, uint32,
		[]byte) (T, error),
	rowID func(T) int64, rowCreatedAt func(T) time.Time,
	deriveFn AddressDerivationFunc) (*AddressInfo, error) {

	addrType, branch, index, scriptPubKey, err :=
		derivedAddressInput(
			ctx, params, accountID, getExtIndex, getIntIndex, deriveFn,
		)
	if err != nil {
		return nil, err
	}

	row, err := createFn(ctx, accountID, addrType, branch, index, scriptPubKey)
	if err != nil {
		return nil, fmt.Errorf("create address: %w", err)
	}

	rowIDVal := rowID(row)

	id, convertedAcctID, err := convertAddressIDs(rowIDVal, accountID)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		ID:           id,
		AccountID:    convertedAcctID,
		AddrType:     addrType,
		CreatedAt:    rowCreatedAt(row),
		Origin:       DerivedAccount,
		Branch:       branch,
		Index:        index,
		ScriptPubKey: scriptPubKey,
		IsWatchOnly:  false,
	}, nil
}

// derivedAddressInput encapsulates the logic to prepare inputs for address
// derivation, including schema lookup, branch/type selection, index
// allocation with overflow check, accountID conversion, and derivation.
func derivedAddressInput(ctx context.Context,
	params NewDerivedAddressParams, accountID int64,
	getExtIndex func(context.Context, int64) (int64, error),
	getIntIndex func(context.Context, int64) (int64, error),
	deriveFn AddressDerivationFunc) (AddressType, uint32, uint32,
	[]byte, error) {

	addrSchema, err := getAddrSchemaForScope(params.Scope)
	if err != nil {
		return 0, 0, 0, nil, err
	}

	var (
		branch   uint32
		addrType AddressType
		getIdx   func(context.Context, int64) (int64, error)
	)

	if params.Change {
		branch = 1
		addrType = addrSchema.InternalAddrType
		getIdx = getIntIndex
	} else {
		addrType = addrSchema.ExternalAddrType
		getIdx = getExtIndex
	}

	indexValue, err := getIdx(ctx, accountID)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf(
			"get next address index: %w", err)
	}

	if indexValue > math.MaxUint32 {
		return 0, 0, 0, nil, ErrMaxAddressIndexReached
	}

	index, err := Int64ToUint32(indexValue)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf(
			"address index: %w", err)
	}

	acctID, err := Int64ToUint32(accountID)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf(
			"account ID: %w", err)
	}

	derivedData, err := deriveFn(ctx, acctID, branch, index)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf(
			"derive address: %w", err)
	}

	return addrType, branch, index, derivedData.ScriptPubKey, nil
}

// NewDerivedAddressWithTx combines transaction execution, account lookup,
// and derived address creation in one helper.
func NewDerivedAddressWithTx[QTX any, AccountRow any,
	AccountParams any, AddrRow any](ctx context.Context,
	params NewDerivedAddressParams,
	executeTx func(context.Context, func(QTX) error) error,
	adapters DerivedAddressAdapters[QTX, AccountRow, AccountParams, AddrRow],
	deriveFn AddressDerivationFunc) (*AddressInfo, error) {

	var result *AddressInfo

	err := executeTx(ctx, func(qtx QTX) error {
		row, err := adapters.GetAccount(ctx, adapters.AccountParams(params))
		if err == nil {
			info, errAddr := createDerivedAddress(
				ctx, params, adapters.GetAccountID(row),
				adapters.GetExtIndex(qtx),
				adapters.GetIntIndex(qtx),
				adapters.CreateAddr(qtx),
				adapters.RowID,
				adapters.RowCreatedAt, deriveFn)
			if errAddr != nil {
				return errAddr
			}

			result = info

			return nil
		}

		if errors.Is(err, sql.ErrNoRows) {
			key := AccountKeyFromParams(params)

			return fmt.Errorf("account %q in scope %d/%d: %w",
				key.AccountName, key.Purpose, key.CoinType,
				ErrAccountNotFound)
		}

		return fmt.Errorf("get account: %w", err)
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// NewImportedAddressWithTx combines transaction execution, account lookup,
// and imported address creation in one helper.
func NewImportedAddressWithTx[QTX any, AccountRow any, AccountParams any,
	CreateArgs any, AddrRow any, SecretParams any](
	ctx context.Context, params NewImportedAddressParams,
	executeTx func(context.Context, func(QTX) error) error,
	adapters ImportedAddressAdapters[QTX, AccountRow, AccountParams, CreateArgs,
		AddrRow, SecretParams]) (*AddressInfo, error) {

	validationErr := params.validate()
	if validationErr != nil {
		return nil, validationErr
	}

	var result *AddressInfo

	err := executeTx(ctx, func(qtx QTX) error {
		row, err := adapters.GetAccount(ctx, adapters.AccountParams(params))
		if err == nil {
			acctID := adapters.GetAccountID(row)

			info, errAddr := newImportedAddressTx(
				ctx, adapters.CreateAddr(qtx),
				adapters.CreateParams(acctID, params),
				adapters.InsertSecret, qtx,
				adapters.SecretParams, params, acctID,
				adapters.RowID,
				adapters.RowCreatedAt)
			if errAddr != nil {
				return errAddr
			}

			result = info

			return nil
		}

		if errors.Is(err, sql.ErrNoRows) {
			key := AccountKeyFromImportedParams(params)

			return fmt.Errorf("account %q in scope %d/%d: %w",
				key.AccountName, key.Purpose, key.CoinType,
				ErrAccountNotFound)
		}

		return fmt.Errorf("get account: %w", err)
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}
