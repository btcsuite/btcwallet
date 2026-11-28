package db

import (
	"context"
	"fmt"
)

// Validate checks wallet secret update parameters for store-level invariants.
// Every wallet must store the key-derivation parameters and script crypto key;
// spendable wallets must include private wallet secret material, while
// watch-only wallets must not include it.
func (p *UpdateWalletSecretsParams) Validate(walletIsWatchOnly bool) error {
	if len(p.MasterPrivParams) == 0 {
		return fmt.Errorf("wallet %d master private parameters: %w", p.WalletID,
			ErrMissingField)
	}

	if len(p.EncryptedCryptoScriptKey) == 0 {
		return fmt.Errorf("wallet %d encrypted script crypto key: %w",
			p.WalletID, ErrMissingField)
	}

	if !walletIsWatchOnly {
		if len(p.EncryptedCryptoPrivKey) == 0 {
			return fmt.Errorf("wallet %d private crypto key: %w", p.WalletID,
				ErrMissingField)
		}

		if len(p.EncryptedMasterHdPrivKey) == 0 {
			return fmt.Errorf("wallet %d master HD private key: %w", p.WalletID,
				ErrMissingField)
		}

		return nil
	}

	if len(p.EncryptedCryptoPrivKey) == 0 &&
		len(p.EncryptedMasterHdPrivKey) == 0 {

		return nil
	}

	return fmt.Errorf("watch-only wallet %d private secrets: %w", p.WalletID,
		ErrWatchOnlyViolation)
}

// UpdateWalletSecretsOps is the backend adapter the shared
// UpdateWalletSecrets workflow uses.
//
// The shared secrets-update algorithm is intentionally ordered:
//   - load the wallet watch-only state first
//   - validate the request against that mode second
//   - run the backend-local secrets update third
//
// The adapter methods map directly to those stages so the shared helper owns
// the sequencing while each backend keeps sqlc query shapes and row-count
// handling local.
type UpdateWalletSecretsOps interface {
	// WalletWatchOnly returns whether the target wallet is watch-only.
	WalletWatchOnly(ctx context.Context, walletID uint32) (bool, error)

	// UpdateWalletSecrets writes the prepared backend-local secrets update.
	UpdateWalletSecrets(ctx context.Context,
		params UpdateWalletSecretsParams) error
}

// UpdateWalletSecretsWithOps runs the backend-independent
// UpdateWalletSecrets workflow once the caller has opened a backend-specific
// SQL transaction.
func UpdateWalletSecretsWithOps(ctx context.Context,
	params UpdateWalletSecretsParams, ops UpdateWalletSecretsOps) error {

	watchOnly, err := ops.WalletWatchOnly(ctx, params.WalletID)
	if err != nil {
		return fmt.Errorf("get wallet: %w", err)
	}

	err = params.Validate(watchOnly)
	if err != nil {
		return err
	}

	err = ops.UpdateWalletSecrets(ctx, params)
	if err != nil {
		return fmt.Errorf("update wallet secrets: %w", err)
	}

	return nil
}
