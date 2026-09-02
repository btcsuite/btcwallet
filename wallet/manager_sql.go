package wallet

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
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
func (b *sqlManagerBackend) create(ctx context.Context,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) (
	*walletData, error) {

	createParams, err := sqlCreateWalletParams(params, rootKey,
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
	params LoadWalletParams) (*walletData, error) {

	info, err := b.store.GetWallet(ctx, params.Name)
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

// sqlCreateWalletParams converts wallet creation inputs into SQL rows.
func sqlCreateWalletParams(params CreateWalletParams,
	rootKey *hdkeychain.ExtendedKey, birthday time.Time) (
	db.CreateWalletParams, error) {

	createParams := db.CreateWalletParams{
		Name: params.Name,
		IsImported: params.Mode == ModeImportSeed ||
			params.Mode == ModeImportExtKey,
		// LatestMgrVersion is a small constant that fits int32.
		//nolint:gosec
		ManagerVersion: int32(waddrmgr.LatestMgrVersion),
		IsWatchOnly:    params.WatchOnly,
		Birthday:       birthday,
	}

	// A validated rootless shell persists no master public key. Every other
	// validated mode supplies a private root, which SQL persists neutered.
	if rootKey != nil {
		masterPubKey, err := rootKey.Neuter()
		if err != nil {
			return db.CreateWalletParams{}, fmt.Errorf("derive pubkey: %w", err)
		}

		createParams.MasterPubKey = []byte(masterPubKey.String())
	}

	secrets, err := vault.CreateWalletSecrets(
		params.PrivatePassphrase, rootKey, createParams.IsWatchOnly)
	if err != nil {
		return db.CreateWalletParams{}, fmt.Errorf(
			"create wallet secrets: %w", err)
	}

	createParams.MasterKeyPrivParams = secrets.MasterPrivParams
	createParams.EncryptedCryptoPrivKey = secrets.EncryptedCryptoPrivKey
	createParams.EncryptedCryptoScriptKey = secrets.EncryptedCryptoScriptKey
	createParams.EncryptedMasterPrivKey = secrets.EncryptedMasterHdPrivKey

	return createParams, nil
}

// birthdayWithSafetyMargin applies the legacy margin to a non-zero birthday.
func birthdayWithSafetyMargin(birthday time.Time) time.Time {
	if birthday.IsZero() {
		return birthday
	}

	return birthday.Add(-waddrmgr.BirthdaySafetyMargin)
}

// newSQLAddressDeriver returns an address derivation callback for a network.
func newSQLAddressDeriver(
	chainParams *chaincfg.Params) db.AddressDerivationFunc {

	return func(_ context.Context, params db.AddressDerivationParams) (
		*db.DerivedAddressData, error) {

		return deriveAddressData(chainParams, params)
	}
}
