package db

import (
	"context"
	"fmt"
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
