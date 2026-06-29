package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
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

	return requireUnreservedAccountName(params.Name)
}

// CreateDerivedAccountRow contains the backend-independent fields the shared
// CreateDerivedAccount workflow needs from the final insert row.
type CreateDerivedAccountRow struct {
	AccountID     int64
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

	// EnsureScope returns the existing or newly created key-scope row ID
	// for the wallet/scope pair together with the schema persisted for that
	// scope. The persisted schema may differ from ScopeAddrMap when the
	// scope was originally created with a non-default override (e.g. an
	// imported account that overrode the BIP44 / BIP49 / BIP84 / BIP86
	// defaults).
	EnsureScope(ctx context.Context, walletID uint32,
		scope KeyScope) (int64, ScopeAddrSchema, error)

	// AllocateAccountNumber advances and returns the next derived account
	// number for the provided scope row.
	AllocateAccountNumber(ctx context.Context, scopeID int64) (int64, error)

	// CreateDerivedAccount inserts the derived account row using the provided
	// scope ID, allocated account number, public account name, and the
	// wallet-derived account material returned by the workflow's
	// AccountDerivationFunc.
	CreateDerivedAccount(ctx context.Context, scopeID int64,
		accountNumber int64, name string,
		d *DerivedAccountData) (CreateDerivedAccountRow, error)
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

// derivedAccountNumber converts a wallet-derived account's persisted account
// number, which must always be present, into its uint32 form.
func derivedAccountNumber(accountNumber sql.NullInt64) (uint32, error) {
	if !accountNumber.Valid {
		// This should never happen unless the query is modified incorrectly.
		return 0, ErrNilDBAccountNumber
	}

	number, err := Int64ToUint32(accountNumber.Int64)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrMaxAccountNumberReached, err)
	}

	return number, nil
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

	err := params.Validate()
	if err != nil {
		return nil, err
	}

	walletIsWatchOnly, err := ops.WalletWatchOnly(ctx, params.WalletID)
	if err != nil {
		return nil, fmt.Errorf("wallet watch only: %w", err)
	}

	scopeID, addrSchema, err := ops.EnsureScope(
		ctx, params.WalletID, params.Scope,
	)
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

	accNumber, err := derivedAccountNumber(row.AccountNumber)
	if err != nil {
		return nil, err
	}

	accountID, err := optionalAccountID(row.AccountID)
	if err != nil {
		return nil, err
	}

	return BuildAccountInfo(
		accountID, &accNumber, params.Name, false, 0, 0, 0,
		walletIsWatchOnly, row.CreatedAt, params.Scope, addrSchema,
		derived.PublicKey, derived.MasterKeyFingerprint,
		0, 0,
	), nil
}
