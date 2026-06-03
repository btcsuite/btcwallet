package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
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

// EnsureKeyScope retrieves an existing key scope or creates it if missing. It
// returns the scope ID once available.
func EnsureKeyScope[Row any, GetArgs any, CreateArgs any](
	ctx context.Context, getter func(context.Context, GetArgs) (Row, error),
	getArgs GetArgs, creator func(context.Context, CreateArgs) (int64, error),
	createArgs func(ScopeAddrSchema) CreateArgs, rowToID func(Row) int64,
	rowToSchema func(Row) (ScopeAddrSchema, error),
	scope KeyScope, schemaOverride *ScopeAddrSchema,
) (int64, ScopeAddrSchema, error) {

	scopeInfo, err := getter(ctx, getArgs)
	if err == nil {
		// Fast path: when the scope already exists. Use the persisted
		// schema so callers see whatever was originally stored, not the
		// caller's override or the ScopeAddrMap default.
		persisted, err := rowToSchema(scopeInfo)
		if err != nil {
			return 0, ScopeAddrSchema{}, fmt.Errorf("scope "+
				"schema: %w", err)
		}

		return rowToID(scopeInfo), persisted, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return 0, ScopeAddrSchema{}, fmt.Errorf("check key scope: %w", err)
	}

	var addrSchema ScopeAddrSchema
	if schemaOverride != nil {
		addrSchema = *schemaOverride
	} else {
		defaultAddrSchema, err := getAddrSchemaForScope(scope)
		if err != nil {
			return 0, ScopeAddrSchema{}, err
		}

		addrSchema = defaultAddrSchema
	}

	// Slow path: needs to create the scope. The SQL uses
	// "ON CONFLICT ... DO NOTHING RETURNING id", which means:
	// - If INSERT succeeds (no conflict): returns the new row's id.
	// - If INSERT conflicts (scope exists): returns NO rows, causing sqlc to
	// return sql.ErrNoRows.
	id, err := creator(ctx, createArgs(addrSchema))
	if err == nil {
		return id, addrSchema, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		// A real database error occurred (not a conflict).
		return 0, ScopeAddrSchema{}, fmt.Errorf("create key scope: %w", err)
	}

	// ErrNoRows means the scope was created concurrently by another process
	// (the INSERT hit DO NOTHING due to conflict). Re-fetch the scope that
	// now exists so we return the schema that actually landed in the DB,
	// not the one we tried to insert.
	scopeInfo, err = getter(ctx, getArgs)
	if err != nil {
		return 0, ScopeAddrSchema{}, fmt.Errorf("get scope after "+
			"create: %w", err)
	}

	persisted, err := rowToSchema(scopeInfo)
	if err != nil {
		return 0, ScopeAddrSchema{}, fmt.Errorf("scope schema after "+
			"create: %w", err)
	}

	return rowToID(scopeInfo), persisted, nil
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
