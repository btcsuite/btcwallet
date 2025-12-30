package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	// errNilDBAccountNumber is returned when the database returns a nil account
	// number. In practice, this should never happen, but it's possible if the
	// database is modified incorrectly or the query is incorrect.
	errNilDBAccountNumber = errors.New("database returned nil account number")

	// errInvalidAccountOrigin is returned when an account origin ID from the
	// database does not correspond to a known AccountOrigin value. In practice,
	// this should never happen, but it's possible if the database is modified
	// incorrectly or the query is incorrect.
	errInvalidAccountOrigin = errors.New("invalid account origin")
)

// validate validates required fields for creating a derived account.
func (params *CreateDerivedAccountParams) validate() error {
	if params.Name == "" {
		return ErrMissingAccountName
	}

	return nil
}

// validate validates required fields for creating an imported account.
func (params *CreateImportedAccountParams) validate() error {
	if params.Name == "" {
		return ErrMissingAccountName
	}

	if len(params.EncryptedPublicKey) == 0 {
		return ErrMissingAccountPublicKey
	}

	return nil
}

// isWatchOnly returns true if the account is watch-only.
func (params *CreateImportedAccountParams) isWatchOnly() bool {
	return len(params.EncryptedPrivateKey) == 0
}

// accountPropsRow represents the raw database fields needed to construct
// AccountProperties.
type accountPropsRow[AddrTypeId, AccOriginId any] struct {
	AccountNumber      sql.NullInt64
	AccountName        string
	OriginID           AccOriginId
	EncryptedPublicKey []byte
	MasterFingerprint  sql.NullInt64
	IsWatchOnly        bool
	CreatedAt          time.Time
	Purpose            int64
	CoinType           int64
	InternalTypeID     AddrTypeId
	ExternalTypeID     AddrTypeId
	IDToAddrType       func(AddrTypeId) (AddressType, error)
	IDToOriginType     func(AccOriginId) (AccountOrigin, error)
}

// accountPropsRowToProps converts a database row containing full account
// properties into an AccountProperties struct. The idToAddrType function is
// used to convert the internal and external address type IDs to AddressType
// values.
//
// TODO(stingelin): Add address counting support after address management is
// implemented.
func accountPropsRowToProps[AddrTypeId, AccOriginId any](
	row accountPropsRow[AddrTypeId, AccOriginId]) (*AccountProperties, error) {

	var accountNum uint32
	if row.AccountNumber.Valid {
		var err error

		accountNum, err = int64ToUint32(row.AccountNumber.Int64)
		if err != nil {
			return nil, fmt.Errorf("account number: %w", err)
		}
	}

	origin, err := row.IDToOriginType(row.OriginID)
	if err != nil {
		return nil, fmt.Errorf("origin: %w", err)
	}

	purposeNum, err := int64ToUint32(row.Purpose)
	if err != nil {
		return nil, fmt.Errorf("purpose: %w", err)
	}

	coinTypeNum, err := int64ToUint32(row.CoinType)
	if err != nil {
		return nil, fmt.Errorf("coin type: %w", err)
	}

	internalType, err := row.IDToAddrType(row.InternalTypeID)
	if err != nil {
		return nil, fmt.Errorf("internal type: %w", err)
	}

	externalType, err := row.IDToAddrType(row.ExternalTypeID)
	if err != nil {
		return nil, fmt.Errorf("external type: %w", err)
	}

	var fingerprint uint32
	if row.MasterFingerprint.Valid {
		fingerprint, err = int64ToUint32(row.MasterFingerprint.Int64)
		if err != nil {
			return nil, fmt.Errorf("master fingerprint: %w", err)
		}
	}

	return &AccountProperties{
		AccountNumber:        accountNum,
		AccountName:          row.AccountName,
		Origin:               origin,
		ExternalKeyCount:     0,
		InternalKeyCount:     0,
		ImportedKeyCount:     0,
		EncryptedPublicKey:   row.EncryptedPublicKey,
		MasterKeyFingerprint: fingerprint,
		KeyScope: KeyScope{
			Purpose: purposeNum,
			Coin:    coinTypeNum,
		},
		IsWatchOnly: row.IsWatchOnly,
		CreatedAt:   row.CreatedAt,
		AddrSchema: &ScopeAddrSchema{
			InternalAddrType: internalType,
			ExternalAddrType: externalType,
		},
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

// listAccounts is a generic helper that retrieves accounts using the provided
// list function and converts the results to AccountInfo structs.
func listAccounts[T any, Args any](ctx context.Context,
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

// buildAccountInfo creates an AccountInfo with the provided values and zeroed
// balances and key counts while we do not yet support address counting.
//
// TODO(stingelin): Add address counting support after address management is
// implemented.
// TODO(stingelin): Add balance tracking support after transaction management is
// implemented.
func buildAccountInfo(accountNum uint32, accountName string,
	origin AccountOrigin, isWatchOnly bool, createdAt time.Time,
	scope KeyScope) *AccountInfo {

	return &AccountInfo{
		AccountNumber:      accountNum,
		AccountName:        accountName,
		Origin:             origin,
		ExternalKeyCount:   0,
		InternalKeyCount:   0,
		ImportedKeyCount:   0,
		ConfirmedBalance:   0,
		UnconfirmedBalance: 0,
		IsWatchOnly:        isWatchOnly,
		CreatedAt:          createdAt,
		KeyScope:           scope,
	}
}

// idToAccountOrigin safely converts an integer to AccountOrigin. It returns an
// error if the value does not correspond to a known AccountOrigin value.
func idToAccountOrigin[T ~int16 | ~int64](v T) (AccountOrigin, error) {
	if v < 0 || v > T(ImportedAccount) {
		return 0, fmt.Errorf("%w: %d", errInvalidAccountOrigin, v)
	}

	return AccountOrigin(v), nil
}

// accountInfoRow represents the raw database fields needed to construct
// AccountInfo.
type accountInfoRow[AccOriginId any] struct {
	AccountNumber  sql.NullInt64
	AccountName    string
	OriginID       AccOriginId
	IsWatchOnly    bool
	CreatedAt      time.Time
	Purpose        int64
	CoinType       int64
	IDToOriginType func(AccOriginId) (AccountOrigin, error)
}

// accountRowToInfo converts raw database field values into an AccountInfo
// struct. It handles type conversion and validation for each field.
func accountRowToInfo[AccOriginId any](
	row accountInfoRow[AccOriginId]) (*AccountInfo, error) {

	var accountNum uint32
	if row.AccountNumber.Valid {
		var err error

		accountNum, err = int64ToUint32(row.AccountNumber.Int64)
		if err != nil {
			return nil, fmt.Errorf("account number: %w", err)
		}
	}

	origin, err := row.IDToOriginType(row.OriginID)
	if err != nil {
		return nil, fmt.Errorf("origin: %w", err)
	}

	purposeNum, err := int64ToUint32(row.Purpose)
	if err != nil {
		return nil, fmt.Errorf("purpose: %w", err)
	}

	coinTypeNum, err := int64ToUint32(row.CoinType)
	if err != nil {
		return nil, fmt.Errorf("coin type: %w", err)
	}

	return buildAccountInfo(
		accountNum, row.AccountName, origin, row.IsWatchOnly,
		row.CreatedAt, KeyScope{
			Purpose: purposeNum,
			Coin:    coinTypeNum,
		},
	), nil
}

// ensureKeyScope retrieves an existing key scope or creates it if missing. It
// returns the scope ID once available.
func ensureKeyScope[Row any, GetArgs any, CreateArgs any](
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

// getAccountFunc defines a function signature for retrieving a single account.
type getAccountFunc func(context.Context, GetAccountQuery) (*AccountInfo, error)

// getAccountByQuery dispatches to the appropriate query based on the provided
// account identifier.
func getAccountByQuery(ctx context.Context, query GetAccountQuery,
	getByNumber getAccountFunc, getByName getAccountFunc) (*AccountInfo,
	error) {

	switch {
	case query.AccountNumber != nil && query.Name == nil:
		return getByNumber(ctx, query)

	case query.Name != nil && query.AccountNumber == nil:
		return getByName(ctx, query)

	default:
		return nil, ErrInvalidAccountQuery
	}
}

// listAccountsFunc defines a function signature for listing accounts.
type listAccountsFunc func(context.Context, ListAccountsQuery) ([]AccountInfo,
	error)

// listAccountsByQuery dispatches to the appropriate list query based on the
// provided filters. It returns an error if both scope and name filters are
// provided, as they are mutually exclusive.
func listAccountsByQuery(ctx context.Context, query ListAccountsQuery,
	listByScope listAccountsFunc, listByName listAccountsFunc,
	listAll listAccountsFunc) ([]AccountInfo, error) {

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

// renameAccountFunc defines a function signature for renaming an account.
type renameAccountFunc func(context.Context, RenameAccountParams) error

// renameAccountByQuery dispatches to the appropriate rename query based on the
// provided account identifier (either account number or old name).
func renameAccountByQuery(ctx context.Context, params RenameAccountParams,
	renameByNumber renameAccountFunc, renameByName renameAccountFunc) error {

	if params.NewName == "" {
		return ErrMissingAccountName
	}

	switch {
	case params.AccountNumber != nil && params.OldName == "":
		return renameByNumber(ctx, params)

	case params.OldName != "" && params.AccountNumber == nil:
		return renameByName(ctx, params)

	default:
		return ErrInvalidAccountQuery
	}
}

// getAccount is a generic helper that retrieves an account using the provided
// query function. It handles error mapping and delegates conversion to the
// toInfo function.
func getAccount[T any, Args any](ctx context.Context,
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

// renameAccount is a generic helper that updates an account name using the
// provided update function. It checks rows affected and returns an error if
// the account was not found.
func renameAccount[Args any](ctx context.Context,
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

// createImportedAccount is a generic helper that creates an imported account.
// It handles ensuring the key scope exists, creating the account record,
// optionally creating the account secret for non-watch-only accounts, and
// fetching the full account properties from the database.
func createImportedAccount[CreateArgs any, CreateRow any, SecretArgs any](
	ctx context.Context, params CreateImportedAccountParams,
	ensureScope func() (int64, error),
	createAccount func(context.Context, CreateArgs) (CreateRow, error),
	buildCreateArgs func(scopeID int64, isWatchOnly bool) CreateArgs,
	rowToID func(CreateRow) int64,
	createSecret func(context.Context, SecretArgs) error,
	buildSecretArgs func(accountID int64) SecretArgs,
	getProps func(accountID int64) (*AccountProperties, error),
) (*AccountProperties, error) {

	err := params.validate()
	if err != nil {
		return nil, err
	}

	isWatchOnly := params.isWatchOnly()

	scopeID, err := ensureScope()
	if err != nil {
		return nil, err
	}

	createArgs := buildCreateArgs(scopeID, isWatchOnly)

	row, err := createAccount(ctx, createArgs)
	if err != nil {
		return nil, fmt.Errorf("create account: %w", err)
	}

	accountID := rowToID(row)

	if isWatchOnly {
		return getProps(accountID)
	}

	err = createSecret(ctx, buildSecretArgs(accountID))
	if err != nil {
		return nil, fmt.Errorf("insert account secrets: %w", err)
	}

	return getProps(accountID)
}
