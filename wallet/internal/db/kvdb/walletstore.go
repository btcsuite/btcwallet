package kvdb

import (
	"context"
	"iter"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
)

// A compile-time assertion to ensure Store implements the wallet store.
var _ db.WalletStore = (*Store)(nil)

// CreateWallet is not yet implemented for kvdb.
func (s *Store) CreateWallet(ctx context.Context,
	_ db.CreateWalletParams) (*db.WalletInfo, error) {

	return nil, notImplemented(ctx, "CreateWallet")
}

// GetWallet is not yet implemented for kvdb.
func (s *Store) GetWallet(ctx context.Context,
	_ string) (*db.WalletInfo, error) {

	return nil, notImplemented(ctx, "GetWallet")
}

// ListWallets is not yet implemented for kvdb.
func (s *Store) ListWallets(ctx context.Context,
	_ db.ListWalletsQuery) (page.Result[db.WalletInfo, uint32], error) {

	return page.Result[db.WalletInfo, uint32]{}, notImplemented(
		ctx, "ListWallets",
	)
}

// IterWallets is not yet implemented for kvdb.
func (s *Store) IterWallets(ctx context.Context,
	_ db.ListWalletsQuery) iter.Seq2[db.WalletInfo, error] {

	return func(yield func(db.WalletInfo, error) bool) {
		yield(db.WalletInfo{}, notImplemented(ctx, "IterWallets"))
	}
}

// UpdateWallet is not yet implemented for kvdb.
func (s *Store) UpdateWallet(ctx context.Context,
	_ db.UpdateWalletParams) error {

	return notImplemented(ctx, "UpdateWallet")
}

// GetEncryptedHDSeed is not yet implemented for kvdb.
func (s *Store) GetEncryptedHDSeed(ctx context.Context,
	_ uint32) ([]byte, error) {

	return nil, notImplemented(ctx, "GetEncryptedHDSeed")
}

// UpdateWalletSecrets is not yet implemented for kvdb.
func (s *Store) UpdateWalletSecrets(ctx context.Context,
	_ db.UpdateWalletSecretsParams) error {

	return notImplemented(ctx, "UpdateWalletSecrets")
}
