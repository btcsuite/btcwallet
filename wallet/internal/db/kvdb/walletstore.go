package kvdb

import (
	"context"
	"errors"
	"iter"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/walletdb"
)

// errKvdbAddrStoreTypeMismatch is returned when the caller wires kvdb.NewStore
// with an addrStore value that does not satisfy the kvdbAddrStore narrow
// interface.
var errKvdbAddrStoreTypeMismatch = errors.New(
	"kvdb: addrStore does not satisfy kvdbAddrStore",
)

// A compile-time assertion to ensure Store implements the wallet store.
var _ db.WalletStore = (*Store)(nil)

// kvdbAddrStore is the narrow waddrmgr.Manager surface kvdb depends on for
// pure-DB reads against the legacy bucket layout. A separate interface keeps
// kvdb decoupled from waddrmgr.AddrStore's full breadth.
type kvdbAddrStore interface {
	// EncryptedMasterHDPriv reads the encrypted master HD private key
	// from the manager's main bucket.
	EncryptedMasterHDPriv(ns walletdb.ReadBucket) ([]byte, error)

	// FetchScopedKeyManager returns the scoped key manager for the
	// given scope, or an error if it does not exist.
	FetchScopedKeyManager(scope waddrmgr.KeyScope) (
		waddrmgr.AccountStore, error)

	// ActiveScopedKeyManagers returns every active scoped key manager.
	ActiveScopedKeyManagers() []waddrmgr.AccountStore

	// WatchOnly returns whether the wallet itself is watch-only.
	WatchOnly() bool
}

// addrManager type-asserts s.addrStore into kvdbAddrStore. A nil store or a
// wrong type indicates a caller-side wiring bug.
func (s *Store) addrManager() (kvdbAddrStore, error) {
	mgr, ok := s.addrStore.(kvdbAddrStore)
	if !ok {
		return nil, errKvdbAddrStoreTypeMismatch
	}

	return mgr, nil
}

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

// GetEncryptedHDSeed reads the encrypted master HD private key from the
// legacy waddrmgr main bucket. Watch-only wallets are surfaced as
// db.ErrSecretNotFound.
func (s *Store) GetEncryptedHDSeed(_ context.Context,
	_ uint32) ([]byte, error) {

	var encrypted []byte

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return db.ErrSecretNotFound
		}

		raw, readErr := s.addrStore.EncryptedMasterHDPriv(ns)
		if readErr != nil {
			if waddrmgr.IsError(readErr, waddrmgr.ErrWatchingOnly) {
				return db.ErrSecretNotFound
			}

			return readErr
		}

		encrypted = raw

		return nil
	})
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// UpdateWalletSecrets is not yet implemented for kvdb.
func (s *Store) UpdateWalletSecrets(ctx context.Context,
	_ db.UpdateWalletSecretsParams) error {

	return notImplemented(ctx, "UpdateWalletSecrets")
}
