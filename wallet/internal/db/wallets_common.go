package db

import "fmt"

// Validate checks wallet creation parameters for store-level invariants.
// Watch-only wallets may keep the script crypto key so they can still encrypt
// imported scripts, but they must not include private wallet secret material.
func (p *CreateWalletParams) Validate() error {
	if !p.IsWatchOnly {
		return nil
	}

	if len(p.MasterKeyPrivParams) == 0 &&
		len(p.EncryptedCryptoPrivKey) == 0 &&
		len(p.EncryptedMasterPrivKey) == 0 {

		return nil
	}

	return fmt.Errorf("watch-only wallet %q private secrets: %w", p.Name,
		ErrWatchOnlyViolation)
}

// Validate checks wallet secret update parameters for store-level invariants.
// Watch-only wallets may keep the script crypto key so they can still encrypt
// imported scripts, but they must not include private wallet secret material.
func (p *UpdateWalletSecretsParams) Validate(walletIsWatchOnly bool) error {
	if !walletIsWatchOnly {
		return nil
	}

	if len(p.MasterPrivParams) == 0 &&
		len(p.EncryptedCryptoPrivKey) == 0 &&
		len(p.EncryptedMasterHdPrivKey) == 0 {

		return nil
	}

	return fmt.Errorf("watch-only wallet %d private secrets: %w", p.WalletID,
		ErrWatchOnlyViolation)
}

// NextListWalletsQuery returns a query with its pagination cursor advanced to
// the provided value.
func NextListWalletsQuery(q ListWalletsQuery, cursor uint32) ListWalletsQuery {
	q.Page.After = &cursor

	return q
}
