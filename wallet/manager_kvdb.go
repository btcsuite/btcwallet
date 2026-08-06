package wallet

//nolint:staticcheck // Required by the temporary kvdb compatibility path.
import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
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
	db          walletdb.DB
	chainParams *chaincfg.Params
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
		db:          dbConn,
		chainParams: cfg.ChainParams,
	}, nil
}

// create initializes and opens the one legacy wallet served by the backend.
func (b *kvdbManagerBackend) create(ctx context.Context, cfg Config,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) (
	*walletData, error) {

	if b.store != nil {
		return nil, fmt.Errorf("%w: kvdb serves one wallet per "+
			"database; %q is already loaded", ErrInvalidParam,
			b.walletName)
	}

	adapterCfg := kvdb.Config{
		DB:            b.db,
		ChainParams:   b.chainParams,
		PubPassphrase: params.PubPassphrase,
	}

	// waddrmgr recognizes exactly one watch-only shape: a manager created
	// without a root key. It has nowhere to persist a neutered root and treats
	// every key it is handed as spendable, so it would fail deriving the
	// hardened cointype key from an xpub anyway.
	//
	// Reject a supplied root key rather than dropping it. Discarding it would
	// lose caller key material without a word, and make one request mean two
	// different things: a SQL wallet records that key on the wallet row. This
	// leaves the same watch-only shape the legacy constructor offered -- "No
	// root key can be provided as this wallet will be watching only" -- whose
	// keyspace is built from account-level xpub imports, one account at a time.
	if params.WatchOnly && rootKey != nil {
		return nil, fmt.Errorf("%w: kvdb cannot persist a watch-only "+
			"root key; create a rootless wallet (ModeShell) and "+
			"import account xpubs instead", ErrInvalidParam)
	}

	err := kvdb.CreateWallet(adapterCfg, kvdb.CreateWalletRequest{
		RootKey:           rootKey,
		PrivatePassphrase: params.PrivatePassphrase,
		Birthday:          params.Birthday,
	})
	if err != nil {
		return nil, fmt.Errorf("create legacy wallet: %w", err)
	}

	return b.open(ctx, cfg.Name, adapterCfg)
}

// load opens the one existing legacy wallet served by the backend.
func (b *kvdbManagerBackend) load(ctx context.Context,
	cfg Config) (*walletData, error) {

	if b.store != nil {
		return nil, fmt.Errorf("%w: kvdb serves one wallet per "+
			"database; %q is already loaded", ErrInvalidParam,
			b.walletName)
	}

	return b.open(ctx, cfg.Name, kvdb.Config{
		DB:            b.db,
		ChainParams:   b.chainParams,
		PubPassphrase: cfg.PubPassphrase,
	})
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
