package wallet

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	vault "github.com/btcsuite/btcwallet/wallet/internal/keyvault"
)

// sqlManagerBackend owns the SQL Store shared by a Manager's wallets.
type sqlManagerBackend struct {
	store   db.Store
	closeFn func() error
}

var _ managerBackend = (*sqlManagerBackend)(nil)

// create atomically creates a SQL wallet and returns its committed data.
func (b *sqlManagerBackend) create(ctx context.Context, cfg Config,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) (
	*walletData, error) {

	createParams, err := sqliteCreateWalletParams(
		cfg, params, rootKey,
		birthdayWithSafetyMargin(params.Birthday),
	)
	if err != nil {
		return nil, err
	}

	info, err := b.store.CreateWallet(ctx, createParams)
	if err != nil {
		return nil, fmt.Errorf("create runtime wallet: %w", err)
	}

	return b.walletData(info)
}

// load reads an existing SQL wallet and resolves its runtime dependencies.
func (b *sqlManagerBackend) load(ctx context.Context,
	cfg Config) (*walletData, error) {

	info, err := b.store.GetWallet(ctx, cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("get runtime wallet: %w", err)
	}

	return b.walletData(info)
}

// walletData resolves the runtime dependencies for one committed wallet row.
func (b *sqlManagerBackend) walletData(
	w *db.WalletInfo) (*walletData, error) {

	fingerprint, err := masterFingerprint(w)
	if err != nil {
		return nil, fmt.Errorf("cache master fingerprint: %w", err)
	}

	return &walletData{
		id:                w.ID,
		store:             b.store,
		vault:             vault.NewWalletVault(b.store, w.ID, w.IsWatchOnly),
		masterFingerprint: fingerprint,
		isWatchOnly:       w.IsWatchOnly,
	}, nil
}

// close releases the SQL Store when this backend owns it.
func (b *sqlManagerBackend) close() error {
	if b.closeFn == nil {
		return nil
	}

	return b.closeFn()
}
