package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
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

	// errNilAccountDerivationFunc is returned when derived account creation
	// is called without a derivation callback.
	errNilAccountDerivationFunc = errors.New(
		"account derivation callback is nil",
	)

	// ErrNilDerivedAccountData is returned when the derivation callback
	// reports success but does not return any derived account material.
	ErrNilDerivedAccountData = errors.New("derived account data is nil")

	// errMissingDerivedPublicKey is returned when the derivation callback
	// returns data with an empty public key. Every derived account must
	// have a public key.
	errMissingDerivedPublicKey = errors.New(
		"derived account public key is empty",
	)

	// errWatchOnlyDerivedPrivateKey is returned when the derivation
	// callback returns an encrypted private key for a watch-only wallet,
	// which must hold no spending material.
	errWatchOnlyDerivedPrivateKey = errors.New(
		"watch-only wallet must not return encrypted account private key",
	)

	// errMissingDerivedPrivateKey is returned when the derivation callback
	// omits the encrypted private key for a spendable wallet.
	errMissingDerivedPrivateKey = errors.New(
		"spendable wallet must return encrypted account private key",
	)
)

// Validate validates required fields for creating a derived account.
func (params *CreateDerivedAccountParams) Validate() error {
	if params.Name == "" {
		return ErrMissingAccountName
	}

	return nil
}

// CreateDerivedAccountRow contains the backend-independent fields the shared
// CreateDerivedAccount workflow needs from the final insert row.
type CreateDerivedAccountRow struct {
	AccountNumber sql.NullInt64
	CreatedAt     time.Time
}

// CreateDerivedAccountOps is the backend adapter the shared
// CreateDerivedAccount workflow uses.
//
// The shared account-creation algorithm is intentionally ordered:
//   - validate the public request before any backend step runs
//   - load the wallet watch-only mode so the returned AccountInfo matches the
//     stored wallet state
//   - ensure the requested key scope exists before allocating from its counter
//   - allocate the next derived account number for that scope
//   - insert the derived account row with the allocated number
//   - normalize the inserted row into the public AccountInfo result
//
// The adapter methods map directly to those stages so the shared helper keeps
// the sequencing and invariants while each backend keeps its sqlc query types,
// binding shapes, and row conversions local.
type CreateDerivedAccountOps interface {
	// WalletWatchOnly returns whether the target wallet currently runs in
	// watch-only mode.
	WalletWatchOnly(ctx context.Context, walletID uint32) (bool, error)

	// EnsureScope returns the existing or newly created key-scope row ID for
	// the wallet/scope pair.
	EnsureScope(ctx context.Context, walletID uint32,
		scope KeyScope) (int64, error)

	// AllocateAccountNumber advances and returns the next derived account
	// number for the provided scope row.
	AllocateAccountNumber(ctx context.Context, scopeID int64) (int64, error)

	// CreateDerivedAccount inserts the derived account row using the provided
	// scope ID, allocated account number, public account name, and the
	// wallet-derived account material returned by the workflow's
	// AccountDerivationFunc.
	CreateDerivedAccount(ctx context.Context, scopeID int64,
		accountNumber int64, name string,
		derived *DerivedAccountData) (CreateDerivedAccountRow, error)
}

// validateDerivedAccountData enforces the field rules documented on
// DerivedAccountData. Called by CreateDerivedAccountWithOps after the
// derivation callback returns.
func validateDerivedAccountData(data *DerivedAccountData,
	walletIsWatchOnly bool) error {

	if data == nil {
		return ErrNilDerivedAccountData
	}

	if len(data.PublicKey) == 0 {
		return errMissingDerivedPublicKey
	}

	// The private-key invariant is wallet-mode dependent: a watch-only
	// wallet must never store spending material, and a spendable wallet
	// must always carry an encrypted account-level private key so future
	// child derivations can sign.
	hasPrivKey := len(data.EncryptedPrivateKey) > 0
	switch {
	case walletIsWatchOnly && hasPrivKey:
		return errWatchOnlyDerivedPrivateKey

	case !walletIsWatchOnly && !hasPrivKey:
		return errMissingDerivedPrivateKey
	}

	return nil
}

// deriveAndValidate invokes the wallet-supplied derivation callback with
// the freshly allocated account number and validates the returned
// material against the wallet's watch-only mode. It returns the same
// "derive account: ..." wrap on both the callback and validation errors
// so callers see a single error shape regardless of which step failed.
func deriveAndValidate(ctx context.Context, scope KeyScope, accNum uint32,
	walletIsWatchOnly bool,
	deriveFn AccountDerivationFunc) (*DerivedAccountData, error) {

	derived, err := deriveFn(ctx, scope, accNum, walletIsWatchOnly)
	if err != nil {
		return nil, fmt.Errorf("derive account: %w", err)
	}

	err = validateDerivedAccountData(derived, walletIsWatchOnly)
	if err != nil {
		return nil, fmt.Errorf("derive account: %w", err)
	}

	return derived, nil
}

// allocateAndPreviewAccountNumber bridges the per-scope allocator and the
// uint32 preview that the derivation callback expects. It is split out
// of CreateDerivedAccountWithOps so the main workflow body stays under
// the cyclop budget and the "allocate then preview" pair is described
// in one place.
func allocateAndPreviewAccountNumber(ctx context.Context,
	ops CreateDerivedAccountOps, scopeID int64) (int64, uint32, error) {

	allocated, err := ops.AllocateAccountNumber(ctx, scopeID)
	if err != nil {
		return 0, 0, fmt.Errorf("allocate account number: %w", err)
	}

	accNumPreview, err := validateAccountNumber(allocated)
	if err != nil {
		return 0, 0, fmt.Errorf(
			"%w: %w", ErrMaxAccountNumberReached, err,
		)
	}

	return allocated, accNumPreview, nil
}

// CreateDerivedAccountWithOps runs the backend-independent
// CreateDerivedAccount workflow once the caller has opened a backend-specific
// SQL transaction.
//
// The helper owns the end-to-end sequencing so postgres and sqlite both:
// validate the public request first, allocate from the same scope counter only
// after that scope exists, invoke the wallet-supplied derivation callback to
// build the per-account material, preserve the same account-number overflow
// mapping, and build the same normalized AccountInfo result from the inserted
// row.
func CreateDerivedAccountWithOps(ctx context.Context,
	params CreateDerivedAccountParams,
	ops CreateDerivedAccountOps,
	deriveFn AccountDerivationFunc) (*AccountInfo, error) {

	if deriveFn == nil {
		return nil, errNilAccountDerivationFunc
	}

	paramsErr := params.Validate()
	if paramsErr != nil {
		return nil, paramsErr
	}

	walletIsWatchOnly, err := ops.WalletWatchOnly(ctx, params.WalletID)
	if err != nil {
		return nil, fmt.Errorf("wallet watch only: %w", err)
	}

	scopeID, err := ops.EnsureScope(ctx, params.WalletID, params.Scope)
	if err != nil {
		return nil, fmt.Errorf("ensure scope: %w", err)
	}

	allocated, accNumPreview, err := allocateAndPreviewAccountNumber(
		ctx, ops, scopeID,
	)
	if err != nil {
		return nil, err
	}

	derived, err := deriveAndValidate(
		ctx, params.Scope, accNumPreview, walletIsWatchOnly, deriveFn,
	)
	if err != nil {
		return nil, err
	}

	row, err := ops.CreateDerivedAccount(
		ctx, scopeID, allocated, params.Name, derived,
	)
	if err != nil {
		return nil, fmt.Errorf("create account: %w", err)
	}

	if !row.AccountNumber.Valid {
		// This should never happen unless the query is modified incorrectly.
		return nil, ErrNilDBAccountNumber
	}

	accNumber, err := Int64ToUint32(row.AccountNumber.Int64)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMaxAccountNumberReached, err)
	}

	return BuildAccountInfo(
		accNumber, params.Name, DerivedAccount, 0, 0, 0,
		walletIsWatchOnly, row.CreatedAt, params.Scope,
		derived.PublicKey, derived.MasterKeyFingerprint,
	), nil
}

// ValidateBasic validates required fields for creating an imported account.
func (params *CreateImportedAccountParams) ValidateBasic() error {
	if params.Name == "" {
		return ErrMissingAccountName
	}

	if len(params.PublicKey) == 0 {
		return ErrMissingAccountPublicKey
	}

	return nil
}

// ValidateWatchOnly validates watch-only invariants for creating an imported
// account.
func (params *CreateImportedAccountParams) ValidateWatchOnly(
	walletIsWatchOnly bool) error {

	hasPrivateKey := len(params.EncryptedPrivateKey) > 0
	if walletIsWatchOnly && hasPrivateKey {
		return fmt.Errorf("wallet %d cannot create account %q: %w",
			params.WalletID, params.Name, ErrWatchOnlyViolation)
	}

	return nil
}

// Validate checks that exactly one account selector was set.
func (query GetAccountQuery) Validate() error {
	if query.Name == nil && query.AccountNumber == nil {
		return ErrInvalidAccountQuery
	}

	if query.Name != nil && query.AccountNumber != nil {
		return ErrInvalidAccountQuery
	}

	return nil
}

// Validate checks that the rename parameters identify exactly one account.
func (params RenameAccountParams) Validate() error {
	if params.NewName == "" {
		return ErrMissingAccountName
	}

	if params.OldName == "" && params.AccountNumber == nil {
		return ErrInvalidAccountQuery
	}

	if params.OldName != "" && params.AccountNumber != nil {
		return ErrInvalidAccountQuery
	}

	return nil
}

// AccountPropsRow represents the raw database fields needed to construct
// AccountInfo.
type AccountPropsRow[AddrTypeId, AccOriginId any] struct {
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
	IDToAddrType      func(AddrTypeId) (AddressType, error)
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

// AccountPropsRowToInfo converts a database row containing full account
// properties into an AccountInfo struct. The idToAddrType function is
// used to convert the internal and external address type IDs to AddressType
// values.
func AccountPropsRowToInfo[AddrTypeId, AccOriginId any](
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
		IsWatchOnly: row.IsWatchOnly,
		CreatedAt:   row.CreatedAt,
	}, nil
}

// accountInfosFromRows converts a slice of database rows into AccountInfo
// structs using the provided conversion function.
func accountInfosFromRows[T any](rows []T,
	toInfo func(T) (*AccountInfo, error)) ([]AccountInfo, error) {

	accounts := make([]AccountInfo, len(rows))
	for i, row := range rows {
		info, err := toInfo(row)
		if err != nil {
			return nil, err
		}

		accounts[i] = *info
	}

	return accounts, nil
}

// ListAccounts is a generic helper that retrieves accounts using the provided
// list function and converts the results to AccountInfo structs.
func ListAccounts[T any, Args any](ctx context.Context,
	lister func(context.Context, Args) ([]T, error), args Args,
	toInfo func(T) (*AccountInfo, error)) ([]AccountInfo, error) {

	rows, err := lister(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	return accountInfosFromRows(rows, toInfo)
}

// getAddrSchemaForScope returns the address schema for a given key scope or
// returns an error if the scope is not in ScopeAddrMap.
func getAddrSchemaForScope(scope KeyScope) (ScopeAddrSchema, error) {
	addrSchema, exists := ScopeAddrMap[scope]
	if !exists {
		return ScopeAddrSchema{}, fmt.Errorf("%w: scope %d/%d",
			ErrUnknownKeyScope, scope.Purpose, scope.Coin)
	}

	return addrSchema, nil
}

// BuildAccountInfo creates an AccountInfo with the provided values and zeroed
// balances while we do not yet support balance tracking.
//
// TODO(stingelin): Add balance tracking support after transaction management is
// implemented.
func BuildAccountInfo(accountNum uint32, accountName string,
	origin AccountOrigin, externalKeyCount, internalKeyCount,
	importedKeyCount uint32, isWatchOnly bool, createdAt time.Time,
	scope KeyScope, publicKey []byte,
	masterKeyFingerprint uint32) *AccountInfo {

	return &AccountInfo{
		AccountNumber:        accountNum,
		AccountName:          accountName,
		Origin:               origin,
		ExternalKeyCount:     externalKeyCount,
		InternalKeyCount:     internalKeyCount,
		ImportedKeyCount:     importedKeyCount,
		ConfirmedBalance:     0,
		UnconfirmedBalance:   0,
		IsWatchOnly:          isWatchOnly,
		CreatedAt:            createdAt,
		KeyScope:             scope,
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
type AccountInfoRow[AccOriginId any] struct {
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
	IDToOriginType    func(AccOriginId) (AccountOrigin, error)
}

// AccountRowToInfo converts raw database field values into an AccountInfo
// struct. It handles type conversion and validation for each field.
func AccountRowToInfo[AccOriginId any](
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

	return BuildAccountInfo(
		accountNum, row.AccountName, origin, externalKeyCount, internalKeyCount,
		importedKeyCount, row.IsWatchOnly, row.CreatedAt,
		KeyScope{Purpose: purposeNum, Coin: coinTypeNum},
		row.PublicKey, fingerprint,
	), nil
}

// EnsureKeyScope retrieves an existing key scope or creates it if missing. It
// returns the scope ID once available.
func EnsureKeyScope[Row any, GetArgs any, CreateArgs any](
	ctx context.Context, getter func(context.Context, GetArgs) (Row, error),
	getArgs GetArgs, creator func(context.Context, CreateArgs) (int64, error),
	createArgs func(ScopeAddrSchema) CreateArgs, rowToID func(Row) int64,
	scope KeyScope) (int64, error) {

	scopeInfo, err := getter(ctx, getArgs)
	if err == nil {
		// Fast path: when the scope already exists.
		return rowToID(scopeInfo), nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("check key scope: %w", err)
	}

	defaultAddrSchema, err := getAddrSchemaForScope(scope)
	if err != nil {
		return 0, err
	}

	// Slow path: needs to create the scope. The SQL uses
	// "ON CONFLICT ... DO NOTHING RETURNING id", which means:
	// - If INSERT succeeds (no conflict): returns the new row's id.
	// - If INSERT conflicts (scope exists): returns NO rows, causing sqlc to
	// return sql.ErrNoRows.
	id, err := creator(ctx, createArgs(defaultAddrSchema))
	if err == nil {
		return id, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		// A real database error occurred (not a conflict).
		return 0, fmt.Errorf("create key scope: %w", err)
	}

	// ErrNoRows means the scope was created concurrently by another process
	// (the INSERT hit DO NOTHING due to conflict). Re-fetch the scope that
	// now exists.
	scopeInfo, err = getter(ctx, getArgs)
	if err != nil {
		return 0, fmt.Errorf("get scope after create: %w", err)
	}

	return rowToID(scopeInfo), nil
}

// GetAccountFunc defines a function signature for retrieving a single account.
type GetAccountFunc func(context.Context, GetAccountQuery) (*AccountInfo, error)

// GetAccountByQuery dispatches to the appropriate query based on the provided
// account identifier.
func GetAccountByQuery(ctx context.Context, query GetAccountQuery,
	getByNumber GetAccountFunc, getByName GetAccountFunc) (*AccountInfo,
	error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	if query.AccountNumber != nil {
		return getByNumber(ctx, query)
	}

	return getByName(ctx, query)
}

// ListAccountsFunc defines a function signature for listing accounts.
type ListAccountsFunc func(context.Context, ListAccountsQuery) ([]AccountInfo,
	error)

// ListAccountsByQuery dispatches to the appropriate list query based on the
// provided filters. It returns an error if both scope and name filters are
// provided, as they are mutually exclusive.
func ListAccountsByQuery(ctx context.Context, query ListAccountsQuery,
	listByScope ListAccountsFunc, listByName ListAccountsFunc,
	listAll ListAccountsFunc) ([]AccountInfo, error) {

	switch {
	case query.Scope != nil && query.Name != nil:
		return nil, ErrInvalidAccountQuery

	case query.Scope != nil:
		return listByScope(ctx, query)

	case query.Name != nil:
		return listByName(ctx, query)

	default:
		return listAll(ctx, query)
	}
}

// RenameAccountFunc defines a function signature for renaming an account.
type RenameAccountFunc func(context.Context, RenameAccountParams) error

// RenameAccountByQuery dispatches to the appropriate rename query based on the
// provided account identifier (either account number or old name).
func RenameAccountByQuery(ctx context.Context, params RenameAccountParams,
	renameByNumber RenameAccountFunc, renameByName RenameAccountFunc) error {

	err := params.Validate()
	if err != nil {
		return err
	}

	if params.AccountNumber != nil {
		return renameByNumber(ctx, params)
	}

	return renameByName(ctx, params)
}

// GetAccount is a generic helper that retrieves an account using the provided
// query function. It handles error mapping and delegates conversion to the
// toInfo function.
func GetAccount[T any, Args any](ctx context.Context,
	getter func(context.Context, Args) (T, error), args Args,
	query GetAccountQuery, toInfo func(T) (*AccountInfo, error)) (*AccountInfo,
	error) {

	row, err := getter(ctx, args)
	if err == nil {
		return toInfo(row)
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("get account: %w", err)
	}

	if query.Name != nil {
		return nil, fmt.Errorf("account %q in scope %d/%d: %w", *query.Name,
			query.Scope.Purpose, query.Scope.Coin, ErrAccountNotFound)
	}

	return nil, fmt.Errorf("account %d in scope %d/%d: %w",
		*query.AccountNumber, query.Scope.Purpose, query.Scope.Coin,
		ErrAccountNotFound)
}

// RenameAccount is a generic helper that updates an account name using the
// provided update function. It checks rows affected and returns an error if
// the account was not found.
func RenameAccount[Args any](ctx context.Context,
	update func(context.Context, Args) (int64, error), args Args,
	params RenameAccountParams) error {

	rowsAffected, err := update(ctx, args)
	if err != nil {
		return fmt.Errorf("rename account: %w", err)
	}

	if rowsAffected != 0 {
		return nil
	}

	if params.OldName != "" {
		return fmt.Errorf("account %q in scope %d/%d: %w", params.OldName,
			params.Scope.Purpose, params.Scope.Coin, ErrAccountNotFound)
	}

	return fmt.Errorf("account %d in scope %d/%d: %w", *params.AccountNumber,
		params.Scope.Purpose, params.Scope.Coin, ErrAccountNotFound)
}

// CreateImportedAccount is a generic helper that creates an imported account.
// It handles ensuring the key scope exists, creating the account record,
// optionally creating the account secret when account private key material is
// present, and fetching the full account properties from the database.
func CreateImportedAccount[CreateArgs any, CreateRow any, SecretArgs any](
	ctx context.Context, params CreateImportedAccountParams,
	ensureScope func() (int64, error),
	walletWatchOnly func() (bool, error),
	createAccount func(context.Context, CreateArgs) (CreateRow, error),
	buildCreateArgs func(scopeID int64) CreateArgs,
	rowToID func(CreateRow) int64,
	createSecret func(context.Context, SecretArgs) error,
	buildSecretArgs func(accountID int64) SecretArgs,
	getProps func(accountID int64) (*AccountInfo, error),
) (*AccountInfo, error) {

	err := params.ValidateBasic()
	if err != nil {
		return nil, err
	}

	walletIsWatchOnly, err := walletWatchOnly()
	if err != nil {
		return nil, err
	}

	err = params.ValidateWatchOnly(walletIsWatchOnly)
	if err != nil {
		return nil, err
	}

	hasAccountSecret := len(params.EncryptedPrivateKey) > 0

	scopeID, err := ensureScope()
	if err != nil {
		return nil, err
	}

	createArgs := buildCreateArgs(scopeID)

	row, err := createAccount(ctx, createArgs)
	if err != nil {
		return nil, fmt.Errorf("create account: %w", err)
	}

	accountID := rowToID(row)

	if !hasAccountSecret {
		return getProps(accountID)
	}

	err = createSecret(ctx, buildSecretArgs(accountID))
	if err != nil {
		return nil, fmt.Errorf("insert account secrets: %w", err)
	}

	return getProps(accountID)
}
