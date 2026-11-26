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
	db          walletdb.DB
	chainParams *chaincfg.Params
	pubPass     []byte
	store       *kvdb.Store //nolint:staticcheck // Remove with kvdb support.
	addressMgr  *waddrmgr.Manager
	walletName  string
}

// Compile-time assertion that kvdbManagerBackend implements managerBackend.
var _ managerBackend = (*kvdbManagerBackend)(nil)

// openKVDB acquires the handle the backend will close after its wallets stop.
func (cfg ManagerConfig) openKVDB(ctx context.Context) (walletdb.DB, error) {
	// The caller selects the namespace and driver. A nil success would
	// leave startup without a database for its first wallet lookup.
	if cfg.OpenKVDB != nil {
		dbConn, err := cfg.OpenKVDB(ctx)
		if err != nil {
			return nil, fmt.Errorf("open kvdb: %w", err)
		}

		if dbConn == nil {
			return nil, fmt.Errorf("%w: OpenKVDB returned nil",
				ErrInvalidParam)
		}

		return dbConn, nil
	}

	// A fallback to bbolt after an opener error could create another wallet.
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

	return dbConn, nil
}

// newKVDBManagerBackend acquires the legacy database for a Manager.
//
// Deprecated: remove this constructor with kvdb support.
func newKVDBManagerBackend(ctx context.Context, cfg ManagerConfig,
	open func(context.Context) (walletdb.DB, error)) (*kvdbManagerBackend,
	error) {

	// Both acquisition paths transfer one handle to backend.close.
	dbConn, err := open(ctx)
	if err != nil {
		return nil, err
	}

	return &kvdbManagerBackend{
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

	//nolint:staticcheck // Legacy kvdb uses a public passphrase.
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

	//nolint:staticcheck // Legacy kvdb uses a public passphrase.
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
