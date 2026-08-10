package wallet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
)

// newSQLiteManagerBackend opens the SQLite Store owned by a Manager.
func newSQLiteManagerBackend(ctx context.Context,
	cfg ManagerConfig) (*sqlManagerBackend, error) {

	err := os.MkdirAll(filepath.Dir(cfg.DataSource), defaultWalletDBDirPerm)
	if err != nil {
		return nil, fmt.Errorf("create sqlite dir: %w", err)
	}

	store, err := sqlite.NewStore(ctx, sqlite.Config{
		DBPath:         cfg.DataSource,
		MaxConnections: cfg.MaxConnections,
		DeriveAddress:  newSQLiteAddressDeriver(cfg.ChainParams),
	})
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}

	return &sqlManagerBackend{
		store:   store,
		closeFn: store.Close,
	}, nil
}

// sqliteCreateWalletParams converts wallet creation inputs into the SQL
// wallet metadata and secret rows.
func sqliteCreateWalletParams(cfg Config, params CreateWalletParams,
	rootKey *hdkeychain.ExtendedKey, birthday time.Time) (
	db.CreateWalletParams, error) {

	createParams := db.CreateWalletParams{
		Name: cfg.Name,
		IsImported: params.Mode == ModeImportSeed ||
			params.Mode == ModeImportExtKey,
		// LatestMgrVersion is a small constant that fits int32.
		//nolint:gosec
		ManagerVersion: int32(waddrmgr.LatestMgrVersion),
		IsWatchOnly:    params.WatchOnly,
		Birthday:       birthday,
	}

	switch {
	case rootKey == nil:
		createParams.IsWatchOnly = true

	case rootKey.IsPrivate():
		masterPubKey, err := rootKey.Neuter()
		if err != nil {
			return db.CreateWalletParams{}, fmt.Errorf(
				"derive master HD pubkey: %w", err,
			)
		}

		createParams.MasterPubKey = []byte(masterPubKey.String())

	default:
		createParams.IsWatchOnly = true
		createParams.MasterPubKey = []byte(rootKey.String())
	}

	secrets, err := keyvault.CreateWalletSecrets(
		params.PrivatePassphrase, rootKey, createParams.IsWatchOnly,
	)
	if err != nil {
		return db.CreateWalletParams{}, fmt.Errorf(
			"create wallet secrets: %w", err,
		)
	}

	createParams.MasterKeyPrivParams = secrets.MasterPrivParams
	createParams.EncryptedCryptoPrivKey = secrets.EncryptedCryptoPrivKey
	createParams.EncryptedCryptoScriptKey = secrets.EncryptedCryptoScriptKey
	createParams.EncryptedMasterPrivKey = secrets.EncryptedMasterHdPrivKey

	return createParams, nil
}

// birthdayWithSafetyMargin applies the legacy birthday safety margin to a
// non-zero birthday.
func birthdayWithSafetyMargin(birthday time.Time) time.Time {
	if birthday.IsZero() {
		return birthday
	}

	return birthday.Add(-waddrmgr.BirthdaySafetyMargin)
}

// newSQLiteAddressDeriver returns the SQLite address derivation callback for
// the configured network.
func newSQLiteAddressDeriver(
	chainParams *chaincfg.Params) db.AddressDerivationFunc {

	return func(_ context.Context, params db.AddressDerivationParams) (
		*db.DerivedAddressData, error) {

		return deriveAddressData(chainParams, params)
	}
}
