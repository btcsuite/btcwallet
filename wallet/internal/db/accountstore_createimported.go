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

// CreateImportedAccount preserves the pre-ops generic helper used by the
// existing backend adapters while the shared workflow is being introduced.
//
// The follow-up adapter commit switches postgres and sqlite to
// CreateImportedAccountWithOps directly.
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

	row, err := createAccount(ctx, buildCreateArgs(scopeID))
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

	err := params.ValidateBasic()
	if err != nil {
		return nil, err
	}

	walletIsWatchOnly, err := ops.IsWalletWatchOnly(ctx, params.WalletID)
	if err != nil {
		return nil, fmt.Errorf("wallet watch only: %w", err)
	}

	err = params.ValidateWatchOnly(walletIsWatchOnly)
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
