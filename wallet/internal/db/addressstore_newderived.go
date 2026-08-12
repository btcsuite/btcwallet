package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"
)

var (
	// errNilAddressDerivationFunc is returned when derived address creation is
	// called without a derivation callback.
	errNilAddressDerivationFunc = errors.New(
		"address derivation callback is nil",
	)

	// errNilDerivedAddressData is returned when the derivation callback reports
	// success but does not return any derived address data.
	errNilDerivedAddressData = errors.New("derived address data is nil")
)

// DerivedAddressAccount is the normalized view of the owning account that the
// shared NewDerivedAddress workflow needs. Each backend loads its account row
// and maps it onto this struct, so the workflow stays free of backend row
// types and generics.
type DerivedAddressAccount struct {
	// AccountID is the backend account row ID.
	AccountID int64

	// AccountNumber is the BIP44 account number; NULL for non-derived
	// (imported) accounts.
	AccountNumber sql.NullInt64

	// AccountName is the human-readable account name.
	AccountName string

	// MasterFingerprint is the root fingerprint stored on the account.
	MasterFingerprint sql.NullInt64

	// Purpose is the BIP43 purpose component of the owning scope.
	Purpose int64

	// CoinType is the BIP44 coin type component of the owning scope.
	CoinType int64

	// IsDerived reports whether the owning account is wallet-derived.
	IsDerived bool

	// WalletWatchOnly reports whether the parent wallet is watch-only.
	WalletWatchOnly bool

	// AddrSchema is the account's effective address schema, honoring any
	// per-account override persisted at account creation.
	AddrSchema ScopeAddrSchema

	// PubKey is the account-level extended public key.
	PubKey []byte
}

// CreateDerivedAddressRequest carries the backend-independent inputs for
// inserting a derived address row and its derivation path.
type CreateDerivedAddressRequest struct {
	WalletID     int64
	AccountID    int64
	AddrType     AddressType
	Branch       uint32
	Index        uint32
	ScriptPubKey []byte
	PubKey       []byte
}

// CreateDerivedAddressRow contains the backend-independent fields the shared
// NewDerivedAddress workflow needs from the inserted address row.
type CreateDerivedAddressRow struct {
	ID        int64
	CreatedAt time.Time
}

// NewDerivedAddressOps is the backend adapter the shared NewDerivedAddress
// workflow uses.
//
// The shared derived-address algorithm is intentionally ordered:
//   - reject a nil derivation callback before any backend step runs
//   - load the owning account, mapping a miss to ErrAccountNotFound
//   - resolve the optional BIP44 account number, enforcing the
//     derived/imported account shape invariant
//   - select the branch and address type from the account schema, allocate
//     the next index (with an overflow check), and derive the address
//   - insert the address row and its derivation path
//   - assemble the AddressInfo and attach the owning account metadata
//
// The adapter methods map directly to those stages so the shared helper keeps
// the sequencing and invariants while each backend keeps its sqlc query types,
// index counters, and row conversions local.
type NewDerivedAddressOps interface {
	// GetAccount loads the owning account, normalized to a
	// DerivedAddressAccount. It returns ErrAccountNotFound when no matching
	// account exists.
	GetAccount(ctx context.Context,
		key AccountLookupKey) (DerivedAddressAccount, error)

	// NextIndex allocates and returns the next address index for the account.
	// change selects the internal (change) branch counter; otherwise the
	// external counter is used.
	NextIndex(ctx context.Context, accountID int64, change bool) (int64, error)

	// CreateDerivedAddress inserts the derived address row and its derivation
	// path, returning the backend-independent identity fields.
	CreateDerivedAddress(ctx context.Context,
		req CreateDerivedAddressRequest) (CreateDerivedAddressRow, error)
}

// NewDerivedAddressWithOps runs the backend-independent derived-address
// workflow once the caller has opened a backend-specific write transaction.
//
// The helper owns the end-to-end sequencing so postgres and sqlite both:
// reject a nil callback first, load and shape-check the owning account,
// resolve the account number, select the branch/type and allocate the next
// index before invoking the derivation callback, insert the address and its
// path, and finally assemble the AddressInfo with its account metadata.
func NewDerivedAddressWithOps(ctx context.Context,
	params NewDerivedAddressParams, ops NewDerivedAddressOps,
	deriveFn AddressDerivationFunc) (*AddressInfo, error) {

	if deriveFn == nil {
		return nil, fmt.Errorf("derive address: %w",
			errNilAddressDerivationFunc)
	}

	key := AccountKeyFromParams(params)

	account, err := ops.GetAccount(ctx, key)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return nil, fmt.Errorf("account %q in scope %d/%d: %w",
				key.AccountName, key.Purpose, key.CoinType, ErrAccountNotFound)
		}

		return nil, fmt.Errorf("get account: %w", err)
	}

	accountNumber, err := resolveAccountNumber(
		account.IsDerived, account.AccountNumber,
	)
	if err != nil {
		return nil, err
	}

	info, err := createDerivedAddress(
		ctx, params, account, accountNumber, ops, deriveFn,
	)
	if err != nil {
		return nil, err
	}

	err = ApplyAddressAccountMetadata(
		info, account.AccountNumber, account.AccountName,
		account.MasterFingerprint, account.Purpose, account.CoinType,
		!account.IsDerived,
	)
	if err != nil {
		return nil, fmt.Errorf("apply address account metadata: %w", err)
	}

	return info, nil
}

// createDerivedAddress prepares the derivation inputs, inserts the address
// through the backend adapter, and assembles the AddressInfo result.
func createDerivedAddress(ctx context.Context,
	params NewDerivedAddressParams, account DerivedAddressAccount,
	accountNumber *uint32, ops NewDerivedAddressOps,
	deriveFn AddressDerivationFunc) (*AddressInfo, error) {

	addrType, branch, index, scriptPubKey, pubKey, err := derivedAddressInput(
		ctx, params, account, accountNumber, ops, deriveFn,
	)
	if err != nil {
		return nil, err
	}

	row, err := ops.CreateDerivedAddress(ctx, CreateDerivedAddressRequest{
		WalletID:     int64(params.WalletID),
		AccountID:    account.AccountID,
		AddrType:     addrType,
		Branch:       branch,
		Index:        index,
		ScriptPubKey: scriptPubKey,
		PubKey:       pubKey,
	})
	if err != nil {
		return nil, fmt.Errorf("create address: %w", err)
	}

	id, err := convertAddressID(row.ID)
	if err != nil {
		return nil, err
	}

	convertedAcctID, err := optionalAccountID(account.AccountID)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		ID:                id,
		AccountID:         convertedAcctID,
		AccountNumber:     accountNumber,
		AddrType:          addrType,
		CreatedAt:         row.CreatedAt,
		HasDerivationPath: true,
		Branch:            branch,
		Index:             index,
		ScriptPubKey:      scriptPubKey,
		PubKey:            pubKey,
		IsWatchOnly:       account.WalletWatchOnly,
	}, nil
}

// derivedAddressInput selects the branch/address type from the account's
// effective schema, allocates the next index with an overflow check, and
// invokes the derivation callback. The account's schema must already account
// for any per-account override; this function does not consult the scope
// default itself.
func derivedAddressInput(ctx context.Context,
	params NewDerivedAddressParams, account DerivedAddressAccount,
	accountNumber *uint32, ops NewDerivedAddressOps,
	deriveFn AddressDerivationFunc) (AddressType, uint32, uint32,
	[]byte, []byte, error) {

	var (
		branch   uint32
		addrType AddressType
	)

	if params.Change {
		branch = 1
		addrType = account.AddrSchema.InternalAddrType
	} else {
		addrType = account.AddrSchema.ExternalAddrType
	}

	indexValue, err := ops.NextIndex(ctx, account.AccountID, params.Change)
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
		AccountPubKey:        account.PubKey,
	}

	deriveParams.AccountID, err = optionalAccountID(account.AccountID)
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
func resolveAccountNumber(accountIsDerived bool,
	accountNumber sql.NullInt64) (*uint32, error) {

	var resolved *uint32

	if !accountNumber.Valid {
		if accountIsDerived {
			return nil, fmt.Errorf("%w: derived account missing "+
				"account number", errAccountShapeCorruption)
		}

		return resolved, nil
	}

	if !accountIsDerived {
		return nil, fmt.Errorf("%w: non-derived account has derived "+
			"account number", errAccountShapeCorruption)
	}

	accountNumValue, err := validateAccountNumber(accountNumber.Int64)
	if err != nil {
		return nil, fmt.Errorf("account number: %w", err)
	}

	resolved = &accountNumValue

	return resolved, nil
}
