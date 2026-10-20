package wallet

//nolint:staticcheck // Required by the temporary kvdb compatibility path.
import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	kvdb "github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb" // Register bdb.
)

// kvdbManagerBackend owns the legacy walletdb database and the one legacy
// wallet opened over it.
//
// Deprecated: remove this backend after kvdb wallet migration and support are
// removed.
type kvdbManagerBackend struct {
	// chainSource is the same borrowed client as Manager's source. Resolve
	// canonical identities here while Manager keeps Wallet writers prepared.
	chainSource chain.Interface
	db          walletdb.DB
	chainParams *chaincfg.Params
	pubPass     []byte
	store       *kvdb.Store //nolint:staticcheck // Remove with kvdb support.
	addressMgr  *waddrmgr.Manager
	walletName  string
}

// Compile-time assertion that kvdbManagerBackend implements managerBackend.
var _ managerBackend = (*kvdbManagerBackend)(nil)

// newKVDBManagerBackend opens or creates the legacy walletdb database owned by
// a Manager.
//
// Deprecated: remove this constructor with kvdb support.
func newKVDBManagerBackend(cfg ManagerConfig) (*kvdbManagerBackend, error) {
	err := os.MkdirAll(filepath.Dir(cfg.DataSource), defaultWalletDBDirPerm)
	if err != nil {
		return nil, fmt.Errorf("create kvdb directory: %w", err)
	}

	dbConn, err := walletdb.Open(
		"bdb", cfg.DataSource, cfg.NoFreelistSync, cfg.timeout(), false,
	)
	switch {
	case err == nil:

	case errors.Is(err, walletdb.ErrDbDoesNotExist):
		dbConn, err = walletdb.Create(
			"bdb", cfg.DataSource, cfg.NoFreelistSync,
			cfg.timeout(), false,
		)
		if err != nil {
			return nil, fmt.Errorf("create kvdb: %w", err)
		}

	default:
		return nil, fmt.Errorf("open kvdb: %w", err)
	}

	return &kvdbManagerBackend{
		chainSource: cfg.ChainSource,
		db:          dbConn,
		chainParams: &cfg.ChainParams,
		pubPass:     cfg.KVDBPubPassphrase,
	}, nil
}

// create initializes and opens the one legacy wallet served by the backend.
func (b *kvdbManagerBackend) create(ctx context.Context,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) (
	*walletData, error) {

	if b.store != nil {
		return nil, fmt.Errorf("%w: kvdb serves one wallet per "+
			"database; %q is already loaded", db.ErrWalletExists,
			b.walletName)
	}

	adapterCfg := kvdb.Config{
		DB:            b.db,
		ChainParams:   b.chainParams,
		PubPassphrase: params.PubPassphrase,
	}

	err := kvdb.CreateWallet(adapterCfg, kvdb.CreateWalletRequest{
		RootKey:           rootKey,
		PrivatePassphrase: params.PrivatePassphrase,
		Birthday:          params.Birthday,
	})
	if err != nil {
		return nil, fmt.Errorf("create legacy wallet: %w", err)
	}

	return b.open(ctx, params.Name, adapterCfg)
}

// listWallets loads the sole legacy Wallet once. A pristine database is the
// only successful empty result because kvdb cannot contain a second identity.
func (b *kvdbManagerBackend) listWallets(
	ctx context.Context) ([]*walletData, error) {

	data, err := b.open(ctx, "", kvdb.Config{
		DB:            b.db,
		ChainParams:   b.chainParams,
		PubPassphrase: b.pubPass,
	})
	// Missing durable state is kvdb's only zero-Wallet representation. Every
	// partial namespace, credential, and storage failure remains visible.
	switch {
	case err == nil:

	case errors.Is(err, db.ErrWalletNotFound):
		return []*walletData{}, nil

	default:
		return nil, err
	}

	return []*walletData{data}, nil
}

// open binds the legacy managers and validates all wallet metadata before the
// backend retains their live state.
//
//nolint:staticcheck // Required by the temporary kvdb compatibility path.
func (b *kvdbManagerBackend) open(ctx context.Context, walletName string,
	cfg kvdb.Config) (*walletData, error) {

	store, addressMgr, err := kvdb.OpenStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("open legacy store: %w", err)
	}

	retain := false
	defer func() {
		if !retain {
			addressMgr.Close()
		}
	}()

	info, err := store.GetWallet(ctx, walletName)
	if err != nil {
		return nil, fmt.Errorf("get runtime wallet: %w", err)
	}

	fingerprint, err := masterFingerprint(info)
	if err != nil {
		return nil, fmt.Errorf("cache master fingerprint: %w", err)
	}

	data := &walletData{
		id:                info.ID,
		name:              walletName,
		store:             store,
		addressStore:      addressMgr,
		transactionStore:  store.TxStore(),
		vault:             kvdb.NewLegacyWalletVault(b.db, addressMgr),
		masterFingerprint: fingerprint,
		isWatchOnly:       addressMgr.WatchOnly(),
	}

	b.store = store
	b.addressMgr = addressMgr
	b.walletName = walletName
	retain = true

	return data, nil
}

// rollbackToBlock reconciles disconnected identities while Manager keeps the
// Wallet worker prepared. Resolve canonical membership before any Store write
// so stale events cannot detach replacements or valid pending descendants.
func (b *kvdbManagerBackend) rollbackToBlock(ctx context.Context,
	block db.Block) error {

	// The Store is opened lazily with its Wallet. An empty Manager has no
	// Wallet history to rewind even though its source reader is running.
	if b.store == nil {
		return nil
	}

	height, err := db.Uint32ToInt32(block.Height)
	if err != nil {
		return fmt.Errorf("disconnect height: %w", err)
	}

	synced := b.addressMgr.SyncedTo()

	_, sourceHeight, err := b.chainSource.GetBestBlock()
	if err != nil {
		return fmt.Errorf("disconnect source tip: %w", err)
	}

	fork, err := b.canonicalDisconnectFork(
		ctx, min(synced.Height, height-1, sourceHeight), synced,
	)
	if err != nil {
		return err
	}

	// Classify every mined record after the retained fork. With no known
	// common ancestor, the affected range begins at genesis.
	start := max(0, fork.Height+1)

	canonical, err := b.canonicalDisconnectHistory(ctx, start, sourceHeight)
	if err != nil {
		return err
	}

	return b.store.DisconnectBlock(
		ctx, block, db.OptionalBlockFromBlockStamp(fork), canonical,
	)
}

// canonicalDisconnectFork skips pruned manager hashes and fetches headers only
// after proving canonical membership; Neutrino may already delete old headers.
func (b *kvdbManagerBackend) canonicalDisconnectFork(ctx context.Context,
	height int32, synced waddrmgr.BlockStamp) (waddrmgr.BlockStamp, error) {

	for ; height >= 0; height-- {
		// The loop bounds prove this manager height is non-negative.
		h := uint32(height)

		blocks, err := b.store.ListSyncedBlocks(
			ctx, db.ListSyncedBlocksQuery{
				StartHeight: h, EndHeight: h,
			},
		)
		if err != nil {
			if errors.Is(err, db.ErrBlockNotFound) {
				continue
			}

			var managerErr waddrmgr.ManagerError
			if errors.As(err, &managerErr) &&
				managerErr.ErrorCode == waddrmgr.ErrBlockNotFound {

				continue
			}

			return waddrmgr.BlockStamp{}, err
		}

		hash, err := b.chainSource.GetBlockHash(int64(height))
		if err != nil {
			return waddrmgr.BlockStamp{}, fmt.Errorf(
				"disconnect fork hash: %w", err,
			)
		}

		if *hash != blocks[0].Hash {
			continue
		}

		if height == synced.Height {
			return synced, nil
		}

		header, err := b.chainSource.GetBlockHeader(hash)
		if err != nil {
			return waddrmgr.BlockStamp{}, fmt.Errorf(
				"disconnect fork header: %w", err,
			)
		}

		return waddrmgr.BlockStamp{
			Height: height, Hash: *hash, Timestamp: header.Timestamp,
		}, nil
	}

	return waddrmgr.BlockStamp{Height: -1}, nil
}

// canonicalDisconnectHistory snapshots each affected mined height once before
// the Store write. Explicit nil entries classify heights beyond the source tip.
func (b *kvdbManagerBackend) canonicalDisconnectHistory(ctx context.Context,
	height, sourceHeight int32) (map[uint32]*chainhash.Hash, error) {

	start, err := db.Int64ToUint32(int64(height))
	if err != nil {
		return nil, fmt.Errorf("disconnect history start: %w", err)
	}

	tip, err := db.Int64ToUint32(int64(sourceHeight))
	if err != nil {
		return nil, fmt.Errorf("disconnect history tip: %w", err)
	}

	history, err := b.store.ListTxns(ctx, db.ListTxnsQuery{
		WalletID: 0, StartHeight: start, EndHeight: math.MaxInt32,
	})
	if err != nil {
		return nil, fmt.Errorf("disconnect history: %w", err)
	}

	canonical := make(map[uint32]*chainhash.Hash)
	for _, info := range history {
		h := info.Block.Height
		if _, known := canonical[h]; known {
			continue
		}

		if h > tip {
			canonical[h] = nil
			continue
		}

		hash, err := b.chainSource.GetBlockHash(int64(h))
		if err != nil {
			return nil, fmt.Errorf("disconnect history hash: %w", err)
		}

		canonical[h] = hash
	}

	return canonical, nil
}

// close releases the legacy address manager before its physical database.
func (b *kvdbManagerBackend) close() error {
	if b.addressMgr != nil {
		b.addressMgr.Close()
	}

	if b.db == nil {
		return nil
	}

	err := b.db.Close()
	if err != nil {
		return fmt.Errorf("close kvdb: %w", err)
	}

	return nil
}
