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

// errMissingAddrStore is returned when a legacy address-manager backed store
// operation has no address manager wired.
var errMissingAddrStore = errors.New("missing legacy addr store")

// CreateWallet is not yet implemented for kvdb.
func (s *Store) CreateWallet(ctx context.Context,
	_ db.CreateWalletParams) (*db.WalletInfo, error) {

	return nil, notImplemented(ctx, "CreateWallet")
}

// readMasterPubKey returns the plaintext master HD public key persisted for
// the wallet, or nil for shell, watch-only, and pre-master-key wallets, which
// persist none and surface ErrNoExist.
func readMasterPubKey(addrStore waddrmgr.AddrStore,
	ns walletdb.ReadBucket) ([]byte, error) {

	pubKey, err := addrStore.MasterHDPubKey(ns)
	switch {
	case err == nil:
		return pubKey, nil

	case waddrmgr.IsError(err, waddrmgr.ErrNoExist):
		return nil, nil

	default:
		return nil, fmt.Errorf("get master HD pubkey: %w", err)
	}
}

// GetWallet reads wallet runtime metadata from the legacy address manager.
//
// NOTE: kvdb is a single-wallet legacy backend. The supplied name is not
// validated against the underlying wallet; the returned WalletInfo echoes the
// requested name. SQL backends honor the Store contract and return
// db.ErrWalletNotFound for unknown names; kvdb does not.
func (s *Store) GetWallet(_ context.Context,
	name string) (*db.WalletInfo, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf("kvdb.Store.GetWallet: %w",
			errMissingAddrStore)
	}

	addrStore := s.addrStore

	var (
		birthdayBlock *db.Block
		masterPubKey  []byte
	)

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		var err error

		masterPubKey, err = readMasterPubKey(addrStore, ns)
		if err != nil {
			return err
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

		birthdayBlock, err = db.BlockFromBlockStamp(block)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetWallet: %w", err)
	}

	syncedTo := db.OptionalBlockFromBlockStamp(addrStore.SyncedTo())

	return &db.WalletInfo{
		ID:            0,
		Name:          name,
		Birthday:      addrStore.Birthday().UTC(),
		BirthdayBlock: birthdayBlock,
		SyncedTo:      syncedTo,
		MasterPubKey:  masterPubKey,
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

// ListSyncedBlocks reads block hashes from the legacy address manager.
func (s *Store) ListSyncedBlocks(_ context.Context,
	query db.ListSyncedBlocksQuery) ([]db.Block, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf("kvdb.Store.ListSyncedBlocks: %w",
			errMissingAddrStore)
	}

	if query.EndHeight < query.StartHeight {
		return nil, fmt.Errorf("kvdb.Store.ListSyncedBlocks: %w: end "+
			"height before start height", db.ErrInvalidParam)
	}

	// Preallocate for the inclusive [StartHeight, EndHeight] range. The
	// span is range-checked here so a height delta that overflows int32
	// fails with a clear error instead of producing a bogus make capacity.
	length, err := db.Uint32ToInt32(
		query.EndHeight - query.StartHeight + 1,
	)
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.ListSyncedBlocks: %w", err)
	}

	blocks := make([]db.Block, 0, int(length))

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		for height := query.StartHeight; ; height++ {
			height32, err := db.Uint32ToInt32(height)
			if err != nil {
				return fmt.Errorf("convert block height %d: %w",
					height, err)
			}

			hash, err := s.addrStore.BlockHash(ns, height32)
			if err != nil {
				return fmt.Errorf("get block hash %d: %w", height, err)
			}

			blocks = append(blocks, db.Block{
				Hash:   *hash,
				Height: height,
			})
			if height == query.EndHeight {
				break
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.ListSyncedBlocks: %w", err)
	}

	return blocks, nil
}

// UpdateWallet writes wallet runtime metadata through the legacy address
// manager.
//
// NOTE: kvdb is a single-wallet legacy backend. params.WalletID is ignored;
// the call always targets the single underlying wallet. SQL backends honor the
// Store contract and return db.ErrWalletNotFound for unknown WalletIDs; kvdb
// does not.
func (s *Store) UpdateWallet(_ context.Context,
	params db.UpdateWalletParams) error {

	if s.addrStore == nil {
		return fmt.Errorf("kvdb.Store.UpdateWallet: %w",
			errMissingAddrStore)
	}

	addrStore := s.addrStore

	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		if ns == nil {
			return errMissingAddrmgrNamespace
		}

		return updateWallet(ns, addrStore, params)
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.UpdateWallet: %w", err)
	}

	return nil
}

// walletStateSnapshot captures the wallet metadata that updateWallet may
// mutate inside a single walletdb transaction. It is consumed by the
// deferred restoreWalletStateOnError so a failed mutation does not leave
// the in-memory waddrmgr cache out of sync with the rolled-back walletdb
// transaction.
type walletStateSnapshot struct {
	birthday         time.Time
	syncedTo         waddrmgr.BlockStamp
	birthdayBlock    waddrmgr.BlockStamp
	birthdayBlockSet bool
}

// snapshotWalletState captures the current wallet metadata from the address
// manager so updateWallet can restore it on rollback. A missing birthday
// block is normal before initial sync finishes and is signalled via the
// birthdayBlockSet flag rather than returned as an error.
func snapshotWalletState(ns walletdb.ReadWriteBucket,
	addrStore waddrmgr.AddrStore) (walletStateSnapshot, error) {

	snap := walletStateSnapshot{
		birthday: addrStore.Birthday(),
		syncedTo: addrStore.SyncedTo(),
	}

	prior, _, err := addrStore.BirthdayBlock(ns)
	switch {
	case err == nil:
		snap.birthdayBlock = prior
		snap.birthdayBlockSet = true

	case waddrmgr.IsError(err, waddrmgr.ErrBirthdayBlockNotSet):
		// A missing birthday block is normal before initial sync finishes.

	default:
		return walletStateSnapshot{}, fmt.Errorf("snapshot birthday "+
			"block: %w", err)
	}

	return snap, nil
}

// restoreWalletStateOnError reverts the in-memory waddrmgr cache (Birthday,
// SyncedTo) and the birthday-block bucket back to the pre-update snapshot
// when the enclosing walletdb transaction returns an error. The birthday-
// block bucket is restored first so a follow-up SetSyncedTo cache rollback
// does not enforce predecessor-hash continuity against a block this
// transaction is rolling back.
func restoreWalletStateOnError(ns walletdb.ReadWriteBucket,
	addrStore waddrmgr.AddrStore, snap walletStateSnapshot,
	birthdayMayMutate, syncedToMutated bool, retErr error) {

	if retErr == nil {
		return
	}

	if !snap.birthdayBlockSet {
		rerr := waddrmgr.DeleteBirthdayBlock(ns)
		if rerr != nil {
			log.Errorf("UpdateWallet rollback: "+
				"DeleteBirthdayBlock: %v (orig: %v)",
				rerr, retErr)
		}
	} else {
		rerr := waddrmgr.PutBirthdayBlock(ns, snap.birthdayBlock)
		if rerr != nil {
			log.Errorf("UpdateWallet rollback: "+
				"PutBirthdayBlock prior: %v (orig: %v)",
				rerr, retErr)
		}
	}

	if birthdayMayMutate {
		rerr := addrStore.SetBirthday(ns, snap.birthday)
		if rerr != nil {
			log.Errorf("UpdateWallet rollback: restore "+
				"SetBirthday: %v (orig: %v)", rerr, retErr)
		}
	}

	if !syncedToMutated {
		return
	}

	rerr := addrStore.SetSyncedTo(ns, &snap.syncedTo)
	if rerr != nil {
		log.Errorf("UpdateWallet rollback: restore SetSyncedTo: "+
			"%v (orig: %v)", rerr, retErr)
	}
}

// updateWallet applies wallet metadata updates through the legacy address
// manager while preserving in-memory cache consistency on rollback.
func updateWallet(ns walletdb.ReadWriteBucket,
	addrStore waddrmgr.AddrStore,
	params db.UpdateWalletParams) error {

	if params.Birthday == nil && params.BirthdayBlock == nil &&
		params.SyncedTo == nil {

		return nil
	}

	snap, err := snapshotWalletState(ns, addrStore)
	if err != nil {
		return err
	}

	birthdayMayMutate := params.Birthday != nil
	syncedToMutated := false

	// applyWalletMutations mutates the in-memory waddrmgr cache
	// (Birthday, SyncedTo) and the birthday-block bucket inline. If
	// it returns an error after one of those mutations has been
	// applied, restoreWalletStateOnError reverts the cache back to
	// the snapshot so the next read does not see a half-applied
	// update.
	err = applyWalletMutations(ns, addrStore, params, &syncedToMutated)
	if err != nil {
		restoreWalletStateOnError(
			ns, addrStore, snap, birthdayMayMutate,
			syncedToMutated, err,
		)
	}

	return err
}

// applyWalletMutations applies the requested birthday, synced-to and
// birthday-block changes through the address manager in the order the
// legacy waddrmgr expects: birthday timestamp first, then synced-to
// (so SetSyncedTo's predecessor-hash check still runs against the prior
// birthday block bucket), and birthday-block bucket last.
func applyWalletMutations(ns walletdb.ReadWriteBucket,
	addrStore waddrmgr.AddrStore, params db.UpdateWalletParams,
	syncedToMutated *bool) error {

	if params.Birthday != nil {
		err := addrStore.SetBirthday(ns, params.Birthday.UTC())
		if err != nil {
			return fmt.Errorf("set birthday: %w", err)
		}
	}

	if params.SyncedTo != nil {
		syncedTo, err := db.BlockStampFromBlock(params.SyncedTo)
		if err != nil {
			return err
		}

		err = addrStore.SetSyncedTo(ns, &syncedTo)
		if err != nil {
			return fmt.Errorf("set synced to: %w", err)
		}

		*syncedToMutated = true
	}

	if params.BirthdayBlock != nil {
		birthdayBlock, err := db.BlockStampFromBlock(
			params.BirthdayBlock,
		)
		if err != nil {
			return err
		}

		err = addrStore.SetBirthdayBlock(ns, birthdayBlock, true)
		if err != nil {
			return fmt.Errorf("set birthday block: %w", err)
		}
	}

	return nil
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

// GetWalletSecrets is not yet implemented for kvdb.
func (s *Store) GetWalletSecrets(ctx context.Context,
	_ uint32) (*db.WalletSecrets, error) {

	return nil, notImplemented(ctx, "GetWalletSecrets")
}

// UpdateWalletSecrets is not yet implemented for kvdb.
func (s *Store) UpdateWalletSecrets(ctx context.Context,
	_ db.UpdateWalletSecretsParams) error {

	return notImplemented(ctx, "UpdateWalletSecrets")
}
