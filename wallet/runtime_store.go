package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
)

var runtimeStoreFactory = openRuntimeStore

// runtimeStoreHandle is the constructed runtime store plus metadata loaded
// from the same backend.
type runtimeStoreHandle struct {
	store      db.Store
	walletInfo *db.WalletInfo
	closeFn    func() error
}

// close closes the runtime store if this handle owns one.
func (h *runtimeStoreHandle) close() error {
	if h == nil || h.closeFn == nil {
		return nil
	}

	err := h.closeFn()
	h.closeFn = nil

	if err != nil {
		return fmt.Errorf("close runtime store: %w", err)
	}

	return nil
}

// closeAfterError closes an owned runtime store while preserving err as the
// primary failure.
func (h *runtimeStoreHandle) closeAfterError(err error) error {
	closeErr := h.close()
	if closeErr != nil {
		return errors.Join(err, closeErr)
	}

	return err
}

// masterFingerprint parses the runtime wallet's master HD public key and
// returns its BIP32 fingerprint. Shell, watch-only, and pre-master-key wallets
// have no pubkey persisted, so the fingerprint is zero.
func (h *runtimeStoreHandle) masterFingerprint() (uint32, error) {
	if h.walletInfo == nil || len(h.walletInfo.MasterPubKey) == 0 {
		return 0, nil
	}

	extKey, err := hdkeychain.NewKeyFromString(
		string(h.walletInfo.MasterPubKey),
	)
	if err != nil {
		return 0, fmt.Errorf("parse master HD pubkey: %w", err)
	}

	mfp, err := masterKeyFingerprint(extKey)
	if err != nil {
		return 0, fmt.Errorf("master fingerprint: %w", err)
	}

	return mfp, nil
}

// openRuntimeStore constructs the configured runtime store and loads the
// wallet row that will identify all store-backed wallet operations.
func openRuntimeStore(ctx context.Context, cfg Config,
	legacyStore *kvdb.StoreHandle) (*runtimeStoreHandle, error) {

	runtimeCfg := cfg.DB.withDefaults()

	err := runtimeCfg.Validate()
	if err != nil {
		return nil, err
	}

	switch runtimeCfg.Backend {
	case DBBackendKVDB:
		return loadRuntimeWallet(ctx, legacyStore.Store, nil, cfg.Name)

	case DBBackendSQLite:
		store, err := sqlite.NewStore(ctx, sqlite.Config{
			DBPath:         runtimeCfg.SQLite.DBPath,
			MaxConnections: runtimeCfg.SQLite.MaxConnections,
			DeriveAddress:  newRuntimeAddressDeriver(cfg),
		})
		if err != nil {
			return nil, fmt.Errorf("open sqlite runtime store: %w", err)
		}

		return loadRuntimeWallet(ctx, store, store.Close, cfg.Name)

	case DBBackendPostgres:
		store, err := pg.NewStore(ctx, pg.Config{
			Dsn:            runtimeCfg.Postgres.DSN,
			MaxConnections: runtimeCfg.Postgres.MaxConnections,
			DeriveAddress:  newRuntimeAddressDeriver(cfg),
		})
		if err != nil {
			return nil, fmt.Errorf("open postgres runtime store: %w", err)
		}

		return loadRuntimeWallet(ctx, store, store.Close, cfg.Name)

	default:
		return nil, fmt.Errorf("%w: DB.Backend %q",
			ErrInvalidParam, runtimeCfg.Backend)
	}
}

// legacyKVDBConfig converts the wallet-level kvdb settings to the internal
// kvdb package config.
func legacyKVDBConfig(cfg Config) kvdb.Config {
	return kvdb.Config{
		DBPath:         cfg.DB.KVDB.DBPath,
		NoFreelistSync: cfg.DB.KVDB.NoFreelistSync,
		Timeout:        cfg.DB.KVDB.Timeout,
	}
}

// createRuntimeWallet creates the wallet row in the selected runtime database
// when the selected backend is SQL. The legacy kvdb backend reads wallet
// metadata directly from walletdb and does not need a separate row.
func createRuntimeWallet(ctx context.Context, cfg Config,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) error {

	runtimeCfg := cfg.DB.withDefaults()

	err := runtimeCfg.Validate()
	if err != nil {
		return err
	}

	switch runtimeCfg.Backend {
	case DBBackendKVDB:
		return nil

	case DBBackendSQLite:
		store, err := sqlite.NewStore(ctx, sqlite.Config{
			DBPath:         runtimeCfg.SQLite.DBPath,
			MaxConnections: runtimeCfg.SQLite.MaxConnections,
			DeriveAddress:  newRuntimeAddressDeriver(cfg),
		})
		if err != nil {
			return fmt.Errorf("open sqlite runtime store: %w", err)
		}

		defer func() {
			_ = store.Close()
		}()

		return createRuntimeWalletWithStore(ctx, store, cfg, params, rootKey)

	case DBBackendPostgres:
		store, err := pg.NewStore(ctx, pg.Config{
			Dsn:            runtimeCfg.Postgres.DSN,
			MaxConnections: runtimeCfg.Postgres.MaxConnections,
			DeriveAddress:  newRuntimeAddressDeriver(cfg),
		})
		if err != nil {
			return fmt.Errorf("open postgres runtime store: %w", err)
		}

		defer func() {
			_ = store.Close()
		}()

		return createRuntimeWalletWithStore(ctx, store, cfg, params, rootKey)

	default:
		return fmt.Errorf("%w: DB.Backend %q", ErrInvalidParam,
			runtimeCfg.Backend)
	}
}

// createRuntimeWalletWithStore creates a runtime wallet row unless an existing
// row with the same name is already present.
func createRuntimeWalletWithStore(ctx context.Context, store db.Store,
	cfg Config, params CreateWalletParams,
	rootKey *hdkeychain.ExtendedKey) error {

	_, err := store.GetWallet(ctx, cfg.Name)
	if err == nil {
		return nil
	}

	if !errors.Is(err, db.ErrWalletNotFound) {
		return fmt.Errorf("get runtime wallet: %w", err)
	}

	createParams, err := runtimeCreateWalletParams(cfg, params, rootKey)
	if err != nil {
		return err
	}

	_, err = store.CreateWallet(ctx, createParams)
	if err != nil {
		return fmt.Errorf("create runtime wallet: %w", err)
	}

	return nil
}

// runtimeCreateWalletParams converts wallet creation inputs into the SQL
// runtime wallet metadata row.
func runtimeCreateWalletParams(cfg Config, params CreateWalletParams,
	rootKey *hdkeychain.ExtendedKey) (db.CreateWalletParams, error) {

	createParams := db.CreateWalletParams{
		Name: cfg.Name,
		IsImported: params.Mode == ModeImportSeed ||
			params.Mode == ModeImportExtKey,
		//nolint:gosec // LatestMgrVersion is a small constant that fits int32.
		ManagerVersion: int32(waddrmgr.LatestMgrVersion),
		IsWatchOnly:    params.WatchOnly,
		Birthday:       params.Birthday,
	}

	if rootKey == nil {
		return createParams, nil
	}

	masterPubKey := rootKey
	if rootKey.IsPrivate() {
		var err error

		masterPubKey, err = rootKey.Neuter()
		if err != nil {
			return db.CreateWalletParams{}, fmt.Errorf(
				"derive master HD pubkey: %w", err,
			)
		}
	}

	createParams.MasterPubKey = []byte(masterPubKey.String())

	return createParams, nil
}

// loadRuntimeWallet loads the named wallet from store and closes owned stores
// when the wallet row is missing or unreadable.
func loadRuntimeWallet(ctx context.Context, store db.Store,
	closeFn func() error, walletName string) (*runtimeStoreHandle, error) {

	handle := &runtimeStoreHandle{
		store:   store,
		closeFn: closeFn,
	}

	info, err := store.GetWallet(ctx, walletName)
	if err != nil {
		return nil, handle.closeAfterError(
			fmt.Errorf("get runtime wallet: %w", err),
		)
	}

	handle.walletInfo = info

	return handle, nil
}

// newRuntimeAddressDeriver returns the SQL address derivation callback for a
// runtime store. The callback only needs static chain parameters, so it uses a
// minimal Wallet value rather than a fully assembled runtime wallet.
func newRuntimeAddressDeriver(cfg Config) db.AddressDerivationFunc {
	deriver := &Wallet{cfg: cfg}

	return deriver.deriveAddressData
}
