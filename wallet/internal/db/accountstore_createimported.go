package db

import (
	"context"
	"fmt"
)

// CreateImportedAccountInsertRequest carries the normalized account insert
// parameters for the shared imported-account creation workflow.
type CreateImportedAccountInsertRequest struct {
	// ScopeID is the resolved key-scope row ID for the account's scope pair.
	ScopeID int64

	// Name is the imported account's display name.
	Name string

	// PublicKey is the extended public key for the imported account.
	PublicKey []byte

	// MasterFingerprint is the master key fingerprint for the imported account.
	MasterFingerprint uint32
}

// Validate validates required fields for creating an imported account.
func (params *CreateImportedAccountParams) Validate() error {
	if params.Name == "" {
		return ErrMissingAccountName
	}

	if len(params.PublicKey) == 0 {
		return ErrMissingAccountPublicKey
	}

	return requireUnreservedAccountName(params.Name)
}

// ValidateWatchOnly validates watch-only invariants for creating an imported
// account. A watch-only wallet must not receive private-key material. The
// symmetric direction (a spendable wallet must not receive an imported
// account without private-key material) is enforced at the SQL-backend
// entry through requireAccountPrivKeyOnSpendable; kvdb's data model cannot
// persist account-level private keys at all, so the symmetric check would
// conflict with the legitimate watch-only-account-in-spendable-wallet flow
// that kvdb supports today (a grandfathered legacy shape).
func (params *CreateImportedAccountParams) ValidateWatchOnly(
	walletIsWatchOnly bool) error {

	hasPrivateKey := len(params.EncryptedPrivateKey) > 0
	if walletIsWatchOnly && hasPrivateKey {
		return fmt.Errorf("wallet %d cannot create account %q: %w",
			params.WalletID, params.Name, ErrWatchOnlyViolation)
	}

	return nil
}

// requireAccountPrivKeyOnSpendable enforces the ADR 0012 symmetric
// invariant for SQL backends: a spendable wallet must not contain an
// imported account without encrypted private-key material. Called from
// the SQL-only CreateImportedAccount workflow below.
func requireAccountPrivKeyOnSpendable(walletID uint32, name string,
	walletIsWatchOnly bool, encryptedPrivKey []byte) error {

	if walletIsWatchOnly || len(encryptedPrivKey) > 0 {
		return nil
	}

	return fmt.Errorf("wallet %d cannot create imported account %q: %w",
		walletID, name, ErrSpendableWalletNeedsAccountPrivKey)
}

// CreateImportedAccountOps is the backend adapter the shared
// CreateImportedAccount workflow uses.
//
// The shared imported-account algorithm is intentionally ordered:
//   - validate the public request before any backend step runs
//   - load the wallet watch-only mode before enforcing wallet-mode invariants
//   - ensure the requested key scope exists before inserting the account
//   - insert the imported account row and return only its created row ID
//   - optionally persist encrypted private material for spendable wallets
//   - reload the final AccountInfo from backend-specific account-property rows
//
// The adapter methods map directly to those stages so the shared helper keeps
// sequencing and invariants while each backend keeps sqlc query types, binding
// shapes, and row-to-AccountInfo conversions local.
type CreateImportedAccountOps interface {
	// IsWalletWatchOnly returns whether the target wallet currently runs in
	// watch-only mode.
	IsWalletWatchOnly(ctx context.Context, walletID uint32) (bool, error)

	// EnsureKeyScope returns the existing or newly created key-scope row ID for
	// the wallet/scope pair, using addrSchema when the caller overrides the
	// scope's default address schema.
	EnsureKeyScope(ctx context.Context, walletID uint32, scope KeyScope,
		addrSchema *ScopeAddrSchema) (int64, error)

	// CreateImportedAccount inserts the imported account row for the provided
	// insert request and returns the created account row ID.
	CreateImportedAccount(ctx context.Context,
		req CreateImportedAccountInsertRequest) (int64, error)

	// CreateAccountSecret persists encrypted private key material for
	// the imported account when the request includes it.
	CreateAccountSecret(ctx context.Context, accountID int64,
		encryptedPrivateKey []byte) error

	// GetAccountInfoByID reloads the final normalized public account
	// view for the created account row ID.
	GetAccountInfoByID(ctx context.Context, accountID int64) (*AccountInfo,
		error)
}

// validateCreateImportedParams runs the backend-independent validation
// sequence for the imported-account workflow before any backend write: basic
// field checks, the reserved-name guard, and the watch-only/private-key
// invariants resolved against the persisted wallet mode.
func validateCreateImportedParams(ctx context.Context,
	ops CreateImportedAccountOps, params CreateImportedAccountParams) error {

	err := params.Validate()
	if err != nil {
		return err
	}

	walletIsWatchOnly, err := ops.IsWalletWatchOnly(ctx, params.WalletID)
	if err != nil {
		return fmt.Errorf("wallet watch only: %w", err)
	}

	err = params.ValidateWatchOnly(walletIsWatchOnly)
	if err != nil {
		return err
	}

	// ADR 0012 invariant: a spendable wallet must not hold an imported
	// account without encrypted private-key material. Applies to the SQL
	// backends only — kvdb's data model cannot persist account-level
	// private keys, and its legacy watch-only-account-in-spendable-wallet
	// flow is grandfathered.
	err = requireAccountPrivKeyOnSpendable(
		params.WalletID, params.Name, walletIsWatchOnly,
		params.EncryptedPrivateKey,
	)
	if err != nil {
		return err
	}

	return nil
}

// CreateImportedAccountWithOps runs the backend-independent imported-account
// workflow once the caller has opened a backend-specific SQL transaction.
//
// The helper owns the ordered sequencing so postgres and sqlite both validate
// before any backend step, enforce the same watch-only rules against the
// persisted wallet mode, create or reuse the same scope before the insert,
// optionally persist secret material only after the account exists, and return
// the same final AccountInfo shape loaded through backend-local conversions.
func CreateImportedAccountWithOps(ctx context.Context,
	params CreateImportedAccountParams,
	ops CreateImportedAccountOps) (*AccountInfo, error) {

	err := validateCreateImportedParams(ctx, ops, params)
	if err != nil {
		return nil, err
	}

	scopeID, err := ops.EnsureKeyScope(
		ctx, params.WalletID, params.Scope, params.AddrSchema,
	)
	if err != nil {
		return nil, fmt.Errorf("ensure scope: %w", err)
	}

	insertReq := CreateImportedAccountInsertRequest{
		ScopeID:           scopeID,
		Name:              params.Name,
		PublicKey:         params.PublicKey,
		MasterFingerprint: params.MasterFingerprint,
	}

	accountID, err := ops.CreateImportedAccount(ctx, insertReq)
	if err != nil {
		return nil, fmt.Errorf("create account: %w", err)
	}

	if len(params.EncryptedPrivateKey) > 0 {
		err = ops.CreateAccountSecret(
			ctx, accountID, params.EncryptedPrivateKey,
		)
		if err != nil {
			return nil, fmt.Errorf("insert account secrets: %w", err)
		}
	}

	accountInfo, err := ops.GetAccountInfoByID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account info: %w", err)
	}

	return accountInfo, nil
}
