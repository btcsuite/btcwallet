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

// requireUnreservedAccountName rejects caller-initiated account operations
// that target the reserved imported alias. Raw imported addresses use this
// alias for compatibility, but SQL must not materialize it as an account row.
// Centralized here so all account paths share one definition of "reserved".
func requireUnreservedAccountName(name string) error {
	if name == DefaultImportedAccountName {
		return fmt.Errorf("%q: %w", name, ErrReservedAccountName)
	}

	return nil
}

var (
	// errNilAddressDerivationFunc is returned when derived address creation is
	// called without a derivation callback.
	errNilAddressDerivationFunc = errors.New(
		"address derivation callback is nil",
	)

	// errNilDerivedAddressData is returned when the derivation callback reports
	// success but does not return any derived address data.
	errNilDerivedAddressData = errors.New("derived address data is nil")

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

// GetAddressSecret is a generic helper that retrieves address secret
// information using the provided getter function and converts it to an
// AddressSecret with error handling.
func GetAddressSecret[Row any](ctx context.Context,
	getter func(context.Context, int64, int64) (Row, error),
	query GetAddressSecretQuery,
	toSecret func(Row) (*AddressSecret, error)) (*AddressSecret, error) {

	row, err := getter(ctx, int64(query.WalletID), int64(query.AddressID))
	if err == nil {
		return toSecret(row)
	}

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("address secret for wallet %d address %d: %w",
			query.WalletID, query.AddressID, ErrAddressNotFound)
	}

	return nil, fmt.Errorf("get address secret: %w", err)
}

// ValidateBasic checks imported address creation parameters that do not depend
// on external state.
func (p NewImportedAddressParams) ValidateBasic() error {
	if len(p.ScriptPubKey) == 0 {
		return ErrMissingScriptPubKey
	}

	return nil
}

// ValidateWatchOnly checks imported address creation parameters against the
// parent wallet's watch-only state. A watch-only wallet must not receive
// private-key-bearing imports. The symmetric direction (a spendable wallet
// must not receive an imported address without private-key material) is
// enforced at the SQL-backend entry through requireAddressPrivKeyOnSpendable;
// kvdb's data model carries different invariants around legacy imported
// address rows (a grandfathered legacy shape), so the symmetric check is not
// applied there.
func (p NewImportedAddressParams) ValidateWatchOnly(
	walletIsWatchOnly bool) error {

	if walletIsWatchOnly && p.HasPrivateKey() {
		return fmt.Errorf("watch-only wallet %d cannot import private-key-"+
			"bearing address into account %q: %w",
			p.WalletID, DefaultImportedAccountName, ErrWatchOnlyViolation)
	}

	return nil
}

// RequireAddressPrivKeyOnSpendable enforces the ADR 0012 symmetric
// invariant for SQL backends: a spendable wallet must not receive an
// imported address without encrypted private-key material. Public-only
// and script-only imports are both rejected (HasPrivateKey covers both
// — script-only imports have material in EncryptedScript but no priv
// key).
func RequireAddressPrivKeyOnSpendable(walletID uint32,
	walletIsWatchOnly bool, hasPrivKey bool) error {

	if walletIsWatchOnly || hasPrivKey {
		return nil
	}

	return fmt.Errorf("spendable wallet %d cannot import address "+
		"without private-key material into account %q: %w",
		walletID, DefaultImportedAccountName,
		ErrSpendableWalletNeedsAddressPrivKey)
}

// HasPrivateKey returns true if the params include private key material.
// Script material is tracked separately and does not make an imported address
// spend-capable by itself.
func (p NewImportedAddressParams) HasPrivateKey() bool {
	return len(p.EncryptedPrivateKey) > 0
}

// HasSecretMaterial returns true when the imported address carries any
// encrypted secret payload that should be persisted in address_secrets.
// Private keys and scripts are stored independently.
func (p NewImportedAddressParams) HasSecretMaterial() bool {
	return len(p.EncryptedPrivateKey) > 0 || len(p.EncryptedScript) > 0
}

// HasScript returns true if the params include script spend data.
func (p NewImportedAddressParams) HasScript() bool {
	return len(p.EncryptedScript) > 0
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
	AccountName string

	// MasterFingerprint is the root fingerprint stored on the owning account.
	MasterFingerprint sql.NullInt64

	// AccountProps contains account metadata fetched separately when the
	// address query does not join all account fields.
	AccountProps *AccountInfo

	// Purpose is the BIP43 purpose component of the owning scope.
	Purpose int64

	// CoinType is the BIP44 coin type component of the owning scope.
	CoinType int64

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
		return row.AccountProps.AccountNumber, row.AccountProps.AccountName,
			row.AccountProps.MasterKeyFingerprint,
			row.AccountProps.KeyScope, nil
	}

	accountNumber, masterFingerprint, keyScope, err :=
		convertAccountMetadata(
			row.AccountNumber, row.MasterFingerprint, row.Purpose,
			row.CoinType,
		)
	if err != nil {
		return nil, "", 0, KeyScope{}, err
	}

	return accountNumber, row.AccountName, masterFingerprint, keyScope, nil
}

// validateAddressAccountShape checks that derived address rows expose account
// metadata consistent with the owning account's importedness.
func validateAddressAccountShape[TypeID any](
	row AddressInfoRow[TypeID]) error {

	if !row.IsDerived {
		if row.AccountID.Valid || row.AccountIsDerived.Valid ||
			row.AccountNumber.Valid {

			return fmt.Errorf("%w: raw imported address has account metadata",
				errAddressShapeCorruption)
		}

		return nil
	}

	if !row.AccountID.Valid || !row.AccountIsDerived.Valid {
		return fmt.Errorf("%w: derived address missing account metadata",
			errAddressShapeCorruption)
	}

	if !row.AccountIsDerived.Bool {
		if row.AccountNumber.Valid {
			return fmt.Errorf("%w: non-derived account has derived "+
				"account number",
				errAccountShapeCorruption)
		}

		return nil
	}

	if !row.AccountNumber.Valid {
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

	q.Page.After = &cursor

	return q
}

// DerivedAddressAdapters groups the functions needed to create a
// derived address across different database backends.
type DerivedAddressAdapters[QTX any, AccountRow any, AccountParams any,
	AddrRow any] struct {

	// GetAccount returns a transaction-scoped account lookup helper.
	GetAccount func(QTX) func(context.Context, AccountParams) (AccountRow,
		error)

	// AccountParams converts params to account lookup parameters.
	AccountParams func(NewDerivedAddressParams) AccountParams

	// GetAccountID extracts the account ID from an account row.
	GetAccountID func(AccountRow) int64

	// GetAccountNumber extracts the BIP44 account number from an account row.
	GetAccountNumber func(AccountRow) (uint32, error)

	// GetAccountIsDerived reports whether the account row is wallet-derived.
	GetAccountIsDerived func(AccountRow) bool

	// GetWalletWatchOnly extracts the wallet watch-only state from an account
	// row.
	GetWalletWatchOnly func(AccountRow) bool

	// GetAccountAddrSchema extracts the effective address schema for the
	// account from the looked-up row. SQL backends read the persisted
	// internal/external address type IDs so per-account overrides set at
	// account-creation time are honored.
	GetAccountAddrSchema func(AccountRow) (ScopeAddrSchema, error)

	// GetAccountPubKey extracts the account-level extended public key from an
	// account row.
	GetAccountPubKey func(AccountRow) []byte

	// GetExtIndex returns a function to get the external index.
	GetExtIndex func(QTX) func(context.Context, int64) (int64, error)

	// GetIntIndex returns a function to get the internal index.
	GetIntIndex func(QTX) func(context.Context, int64) (int64, error)

	// CreateAddr returns a function to create an address row.
	CreateAddr func(QTX) func(context.Context, int64, int64, AddressType,
		uint32, uint32, []byte, []byte) (AddrRow, error)

	// RowID extracts the ID from an address row.
	RowID func(AddrRow) int64

	// RowCreatedAt extracts the creation time from an address row.
	RowCreatedAt func(AddrRow) time.Time

	// ApplyAccountMetadata copies account metadata from the account row
	// onto the address result inside the create transaction.
	ApplyAccountMetadata func(*AddressInfo, AccountRow) error
}

// DerivedAddressCreateAddr returns a derived-address insert adapter from a
// backend-specific sqlc create method and parameter builder.
func DerivedAddressCreateAddr[CreateParams any, AddrRow any](
	create func(context.Context, CreateParams) (AddrRow, error),
	buildParams func(int64, int64, AddressType, uint32, uint32, []byte,
		[]byte) (CreateParams, error)) func(context.Context, int64, int64,
	AddressType, uint32, uint32, []byte, []byte) (AddrRow, error) {

	return func(ctx context.Context, walletID int64, accountID int64,
		addrType AddressType, branch uint32, index uint32,
		scriptPubKey []byte, pubKey []byte) (AddrRow, error) {

		params, err := buildParams(
			walletID, accountID, addrType, branch, index, scriptPubKey,
			pubKey,
		)
		if err != nil {
			var zero AddrRow

			return zero, err
		}

		return create(ctx, params)
	}
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
// inputs and then createFn to create the address. addrSchema is the
// account's effective schema (per-account override when set, otherwise
// the scope default).
func createDerivedAddress[T any](ctx context.Context,
	params NewDerivedAddressParams, walletID int64, accountID int64,
	accountNumber *uint32, walletIsWatchOnly bool, addrSchema ScopeAddrSchema,
	accountPubKey []byte,
	getExtIndex func(context.Context, int64) (int64, error),
	getIntIndex func(context.Context, int64) (int64, error),
	createFn func(context.Context, int64, int64, AddressType, uint32, uint32,
		[]byte, []byte) (T, error),
	rowID func(T) int64, rowCreatedAt func(T) time.Time,
	deriveFn AddressDerivationFunc) (*AddressInfo, error) {

	addrType, branch, index, scriptPubKey, pubKey, err :=
		derivedAddressInput(
			ctx, params, accountID, accountNumber, addrSchema,
			accountPubKey, getExtIndex, getIntIndex, deriveFn,
		)
	if err != nil {
		return nil, err
	}

	row, err := createFn(
		ctx, walletID, accountID, addrType, branch, index, scriptPubKey,
		pubKey,
	)
	if err != nil {
		return nil, fmt.Errorf("create address: %w", err)
	}

	rowIDVal := rowID(row)

	id, err := convertAddressID(rowIDVal)
	if err != nil {
		return nil, err
	}

	convertedAcctID, err := optionalAccountID(accountID)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		ID:                id,
		AccountID:         convertedAcctID,
		AccountNumber:     accountNumber,
		AddrType:          addrType,
		CreatedAt:         rowCreatedAt(row),
		HasDerivationPath: true,
		Branch:            branch,
		Index:             index,
		ScriptPubKey:      scriptPubKey,
		PubKey:            pubKey,
		IsWatchOnly:       walletIsWatchOnly,
	}, nil
}

// derivedAddressInput encapsulates the logic to prepare inputs for address
// derivation, including branch/type selection from the supplied effective
// schema, index allocation with overflow check, and derivation. addrSchema is
// the account's effective schema and must already account for any per-account
// override; this function does not consult the scope default itself.
func derivedAddressInput(ctx context.Context,
	params NewDerivedAddressParams, accountID int64, accountNumber *uint32,
	addrSchema ScopeAddrSchema, accountPubKey []byte,
	getExtIndex func(context.Context, int64) (int64, error),
	getIntIndex func(context.Context, int64) (int64, error),
	deriveFn AddressDerivationFunc) (AddressType, uint32, uint32,
	[]byte, []byte, error) {

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
		return 0, 0, 0, nil, nil,
			fmt.Errorf("get next address index: %w", err)
	}

	if indexValue > math.MaxUint32 {
		return 0, 0, 0, nil, nil, ErrMaxAddressIndexReached
	}

	index, err := Int64ToUint32(indexValue)
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("address index: %w", err)
	}

	deriveParams := AddressDerivationParams{
		Scope:                params.Scope,
		DerivedAccountNumber: accountNumber,
		Branch:               branch,
		Index:                index,
		AddrType:             addrType,
		AccountPubKey:        accountPubKey,
	}

	deriveParams.AccountID, err = optionalAccountID(accountID)
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}

	derivedData, err := deriveFn(ctx, deriveParams)
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("derive address: %w", err)
	}

	if derivedData == nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("derive address: %w",
			errNilDerivedAddressData)
	}

	return addrType, branch, index, derivedData.ScriptPubKey,
		derivedData.PubKey, nil
}

// resolveAccountNumber maps the account-number lookup result to the optional
// BIP44 account number, enforcing the wallet-derived/imported shape invariant.
func resolveAccountNumber(accountIsDerived bool, accountNumValue uint32,
	errAccount error) (*uint32, error) {

	var accountNumber *uint32

	switch {
	case errAccount == nil:
		if !accountIsDerived {
			return nil, fmt.Errorf("%w: non-derived account has "+
				"derived account number", errAccountShapeCorruption)
		}

		accountNumber = &accountNumValue

	case errors.Is(errAccount, ErrNilDBAccountNumber):
		if accountIsDerived {
			return nil, fmt.Errorf("%w: derived account missing "+
				"account number", errAccountShapeCorruption)
		}

	default:
		return nil, fmt.Errorf("account number: %w", errAccount)
	}

	return accountNumber, nil
}

// NewDerivedAddressWithTx combines transaction execution, account lookup,
// and derived address creation in one helper.
func NewDerivedAddressWithTx[QTX any, AccountRow any,
	AccountParams any, AddrRow any](ctx context.Context,
	params NewDerivedAddressParams,
	executeTx func(context.Context, func(QTX) error) error,
	adapters DerivedAddressAdapters[QTX, AccountRow, AccountParams, AddrRow],
	deriveFn AddressDerivationFunc) (*AddressInfo, error) {

	if deriveFn == nil {
		return nil, fmt.Errorf("derive address: %w",
			errNilAddressDerivationFunc)
	}

	var result *AddressInfo

	err := executeTx(ctx, func(qtx QTX) error {
		row, err := adapters.GetAccount(qtx)(
			ctx, adapters.AccountParams(params),
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				key := AccountKeyFromParams(params)

				return fmt.Errorf("account %q in scope %d/%d: %w",
					key.AccountName, key.Purpose, key.CoinType,
					ErrAccountNotFound)
			}

			return fmt.Errorf("get account: %w", err)
		}

		accountID := adapters.GetAccountID(row)
		accountIsDerived := adapters.GetAccountIsDerived(row)

		// Non-derived accounts have NULL account_number; their derivation
		// uses AccountPubKey directly so a BIP44 number is not available.
		accountNumValue, errAccount := adapters.GetAccountNumber(row)

		accountNumber, errNumber := resolveAccountNumber(
			accountIsDerived, accountNumValue, errAccount,
		)
		if errNumber != nil {
			return errNumber
		}

		addrSchema, errSchema := adapters.GetAccountAddrSchema(row)
		if errSchema != nil {
			return fmt.Errorf("account addr schema: %w", errSchema)
		}

		accountPubKey := adapters.GetAccountPubKey(row)

		info, errAddr := createDerivedAddress(
			ctx, params, int64(params.WalletID), accountID,
			accountNumber, adapters.GetWalletWatchOnly(row), addrSchema,
			accountPubKey,
			adapters.GetExtIndex(qtx),
			adapters.GetIntIndex(qtx),
			adapters.CreateAddr(qtx),
			adapters.RowID,
			adapters.RowCreatedAt, deriveFn)
		if errAddr != nil {
			return errAddr
		}

		errMeta := adapters.ApplyAccountMetadata(info, row)
		if errMeta != nil {
			return fmt.Errorf("apply address account metadata: %w",
				errMeta)
		}

		result = info

		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}
