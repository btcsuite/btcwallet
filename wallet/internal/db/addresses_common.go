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

	// ErrInvalidListAddressesQuery is returned when a list-addresses request
	// mixes derived-account and raw-import selector fields.
	ErrInvalidListAddressesQuery = errors.New(
		"list addresses requires both Scope and AccountName, or neither",
	)
)

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
