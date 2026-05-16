package kvdb

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/walletdb"
)

// A compile-time assertion to ensure Store implements the wallet store.
var _ db.WalletStore = (*Store)(nil)

// legacyWalletMetadataStore is the legacy address-manager subset needed for
// wallet metadata operations.
type legacyWalletMetadataStore interface {
	Birthday() time.Time
	BirthdayBlock(ns walletdb.ReadBucket) (waddrmgr.BlockStamp, bool, error)
	SyncedTo() waddrmgr.BlockStamp
}

// CreateWallet is not yet implemented for kvdb.
func (s *Store) CreateWallet(ctx context.Context,
	_ db.CreateWalletParams) (*db.WalletInfo, error) {

	return nil, notImplemented(ctx, "CreateWallet")
}

// GetWallet reads wallet runtime metadata from the legacy address manager.
func (s *Store) GetWallet(_ context.Context,
	name string) (*db.WalletInfo, error) {

	addrStore, err := s.walletMetadataStore("GetWallet")
	if err != nil {
		return nil, err
	}

	var birthdayBlock *db.Block

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		block, verified, err := addrStore.BirthdayBlock(ns)
		if err != nil {
			if waddrmgr.IsError(err, waddrmgr.ErrBirthdayBlockNotSet) {
				return nil
			}

			return fmt.Errorf("get birthday block: %w", err)
		}

		if !verified {
			return nil
		}

		birthdayBlock, err = kvdbBlockFromBlockStamp(block)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetWallet: %w", err)
	}

	syncedTo, err := kvdbOptionalBlockFromBlockStamp(addrStore.SyncedTo())
	if errors.Is(err, db.ErrBlockNotFound) {
		syncedTo = nil
	} else if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetWallet: %w", err)
	}

	return &db.WalletInfo{
		ID:            0,
		Name:          name,
		Birthday:      addrStore.Birthday().UTC(),
		BirthdayBlock: birthdayBlock,
		SyncedTo:      syncedTo,
	}, nil
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
		_ = yield(db.WalletInfo{}, notImplemented(ctx, "IterWallets"))
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

// walletMetadataStore returns the legacy address manager used for wallet
// metadata operations.
func (s *Store) walletMetadataStore(method string) (legacyWalletMetadataStore,
	error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.%s: %w", method, errMissingLegacyAddrStore,
		)
	}

	addrStore, ok := s.addrStore.(legacyWalletMetadataStore)
	if !ok {
		return nil, fmt.Errorf(
			"kvdb.Store.%s: %w", method, errMissingLegacyAddrStore,
		)
	}

	return addrStore, nil
}

// kvdbBlockFromBlockStamp converts a non-negative legacy block stamp into the
// store block shape.
func kvdbBlockFromBlockStamp(block waddrmgr.BlockStamp) (*db.Block, error) {
	height, err := db.Int64ToUint32(int64(block.Height))
	if err != nil {
		return nil, fmt.Errorf("block height %d: %w", block.Height, err)
	}

	return &db.Block{
		Hash:      block.Hash,
		Height:    height,
		Timestamp: block.Timestamp.UTC(),
	}, nil
}

// kvdbOptionalBlockFromBlockStamp converts a legacy block stamp into the store
// block shape, treating negative heights as missing metadata.
func kvdbOptionalBlockFromBlockStamp(
	block waddrmgr.BlockStamp) (*db.Block, error) {

	if block.Height < 0 {
		return nil, db.ErrBlockNotFound
	}

	return kvdbBlockFromBlockStamp(block)
}
