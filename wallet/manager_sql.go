package wallet

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	vault "github.com/btcsuite/btcwallet/wallet/internal/keyvault"
)

// managerWalletBatchSize supplies the mandatory positive Store iterator batch
// size; IterWallets remains responsible for exhausting the durable Wallet set.
const managerWalletBatchSize = 100

// sqlManagerStore keeps constructor batching local to SQL backends instead of
// expanding the Store contract used by running Wallets and the legacy adapter.
type sqlManagerStore interface {
	db.Store

	// CreateInitialDerivedAccounts keeps the unpublished account set in a
	// single backend write while retaining ordinary identity admission.
	CreateInitialDerivedAccounts(ctx context.Context, walletID uint32,
		accounts []db.CreateDerivedAccountParams,
		deriveFn db.AccountDerivationFunc) error
}

// sqlManagerBackend owns the SQL Store shared by a Manager's wallets.
type sqlManagerBackend struct {
	store   sqlManagerStore
	closeFn func() error
}

var _ managerBackend = (*sqlManagerBackend)(nil)

// listWallets resolves every SQL Wallet in the Store's durable-ID order.
func (b *sqlManagerBackend) listWallets(
	ctx context.Context) ([]*walletData, error) {

	pageReq, err := page.NewRequest[uint32](managerWalletBatchSize)
	if err != nil {
		return nil, fmt.Errorf("create wallet page request: %w", err)
	}

	wallets := make([]*walletData, 0)
	query := db.ListWalletsQuery{Page: pageReq}

	for info, iterErr := range b.store.IterWallets(ctx, query) {
		if iterErr != nil {
			return nil, fmt.Errorf("list runtime wallets: %w", iterErr)
		}

		data, err := b.walletData(&info)
		if err != nil {
			return nil, fmt.Errorf("resolve runtime wallet: %w", err)
		}

		wallets = append(wallets, data)
	}

	return wallets, nil
}

// create persists a SQL wallet and its initial account batch before runtime
// publication. The borrowed root is used only during this synchronous call.
func (b *sqlManagerBackend) create(ctx context.Context,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey,
	accounts []db.CreateDerivedAccountParams) (
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

	data, err := b.walletData(info)
	if err != nil {
		return nil, err
	}

	if len(accounts) == 0 {
		return data, nil
	}

	// Use the creation root while it is already available, avoiding a root
	// read/decryption per account. Authentication and the locked return stay
	// at the existing vault boundary even though no worker has started yet.
	err = data.vault.Unlock(ctx, params.PrivatePassphrase)
	if err != nil {
		return nil, fmt.Errorf("unlock initial accounts: %w", err)
	}
	defer data.vault.Lock()

	err = b.store.CreateInitialDerivedAccounts(
		ctx, data.id, accounts,
		newAccountDeriveFn(rootKey, data.vault, data.masterFingerprint),
	)
	if err != nil {
		return nil, fmt.Errorf("create initial accounts: %w",
			newAccountErr(err))
	}

	return data, nil
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
		name:              w.Name,
		store:             b.store,
		vault:             vault.NewWalletVault(b.store, w.ID, w.IsWatchOnly),
		masterFingerprint: fingerprint,
		isWatchOnly:       w.IsWatchOnly,
	}, nil
}

// rollbackToBlock rewinds shared SQL history once all Wallet workers are ready.
// The existing Store operation uses the first removed height.
func (b *sqlManagerBackend) rollbackToBlock(ctx context.Context,
	block db.Block) error {

	return b.store.RollbackToBlock(ctx, block.Height)
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
