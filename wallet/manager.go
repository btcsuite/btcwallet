package wallet

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	kvdb "github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
)

var (
	// ErrWalletParams is returned when the creation parameters are invalid.
	ErrWalletParams = errors.New("invalid wallet params")
)

// CreateMode determines how a new wallet is initialized.
type CreateMode uint8

const (
	// ModeUnknown indicates no specific creation mode.
	ModeUnknown CreateMode = iota

	// ModeGenSeed indicates creating a new wallet by generating a fresh random
	// seed.
	ModeGenSeed

	// ModeImportSeed indicates restoring a wallet from a provided seed
	// (CreateWalletParams.Seed).
	ModeImportSeed

	// ModeImportExtKey indicates creating a wallet from an extended key
	// (CreateWalletParams.RootKey).
	ModeImportExtKey

	// ModeShell indicates creating an empty wallet shell (no root key).
	// Intended for importing specific Account XPubs.
	ModeShell
)

// WatchOnlyAccount contains the information needed to import a watch-only
// account.
type WatchOnlyAccount struct {
	// Scope is the key scope of the account.
	Scope waddrmgr.KeyScope

	// XPub is the extended public key for the account.
	XPub *hdkeychain.ExtendedKey

	// MasterKeyFingerprint is the fingerprint of the master key.
	MasterKeyFingerprint uint32

	// Name is the name of the account.
	Name string

	// AddrType is the address type of the account.
	AddrType waddrmgr.AddressType
}

// CreateWalletParams holds the parameters required to initialize a new wallet.
// These are one-time inputs used during the creation process.
type CreateWalletParams struct {
	// Mode determines which fields below are required.
	Mode CreateMode

	// Seed is required for ModeImportSeed. Ignored for others.
	Seed []byte

	// RootKey is required for ModeImportExtKey. Ignored for others. Can be XPrv
	// or XPub.
	RootKey *hdkeychain.ExtendedKey

	// InitialAccounts is optional for ModeShell. Reserved for future use and
	// currently has no effect during wallet creation.
	InitialAccounts []WatchOnlyAccount

	// WatchOnly controls whether the resulting wallet is watch-only.
	// - If true with Seed/XPrv input: Derives Master XPub, then discards
	//   the private material.
	// - If true with XPub/Shell input: No-op (already watch-only).
	WatchOnly bool

	// Birthday is the wallet's birthday.
	Birthday time.Time

	// PubPassphrase is the public passphrase for the wallet.
	PubPassphrase []byte

	// PrivatePassphrase is the private passphrase for the wallet.
	PrivatePassphrase []byte
}

// validateInitialAccountsMode enforces the ADR 0012 wallet-level watch-only
// invariant against the params before any on-disk artifact is created. A
// non-watch-only wallet cannot ship with watch-only InitialAccounts; the
// import would later be rejected by requireAccountPrivKeyOnSpendable but
// only after the wallet row had already been written. The check fires
// once at create time so the failure is atomic.
func validateInitialAccountsMode(params CreateWalletParams) error {
	if params.WatchOnly || len(params.InitialAccounts) == 0 {
		return nil
	}

	return fmt.Errorf("%w: cannot create a non-watch-only wallet with "+
		"InitialAccounts; xpub-only imports require WatchOnly=true",
		ErrWalletParams)
}

// validate ensures that the parameters are consistent with the chosen
// creation mode.
//
// We skip cyclop because this method performs exhaustive validation of
// mutually exclusive fields across all creation modes.
//
//nolint:cyclop
func (p *CreateWalletParams) validate() error {
	if p.Mode == ModeUnknown {
		return fmt.Errorf("%w: unknown mode", ErrWalletParams)
	}

	// InitialAccounts should only be set for ModeShell.
	if p.Mode != ModeShell && len(p.InitialAccounts) > 0 {
		return fmt.Errorf("%w: initial accounts should only be set "+
			"for ModeShell", ErrWalletParams)
	}

	if p.Mode == ModeGenSeed {
		if len(p.Seed) != 0 {
			return fmt.Errorf("%w: seed should not be set for "+
				"ModeGenSeed", ErrWalletParams)
		}

		if p.RootKey != nil {
			return fmt.Errorf("%w: root key should not be set for "+
				"ModeGenSeed", ErrWalletParams)
		}
	}

	if p.Mode == ModeImportSeed {
		if len(p.Seed) == 0 {
			return fmt.Errorf("%w: seed is required for "+
				"ModeImportSeed", ErrWalletParams)
		}

		if p.RootKey != nil {
			return fmt.Errorf("%w: root key should not be set for "+
				"ModeImportSeed", ErrWalletParams)
		}
	}

	if p.Mode == ModeImportExtKey {
		if p.RootKey == nil {
			return fmt.Errorf("%w: root key is required for "+
				"ModeImportExtKey", ErrWalletParams)
		}

		if len(p.Seed) != 0 {
			return fmt.Errorf("%w: seed should not be set for "+
				"ModeImportExtKey", ErrWalletParams)
		}
	}

	if p.Mode == ModeShell {
		if len(p.Seed) != 0 {
			return fmt.Errorf("%w: seed should not be set for "+
				"ModeShell", ErrWalletParams)
		}

		if p.RootKey != nil {
			return fmt.Errorf("%w: root key should not be set for "+
				"ModeShell", ErrWalletParams)
		}
	}

	return nil
}

// Manager is a high-level manager that handles the lifecycle of multiple
// wallets. It acts as a factory for creating and loading wallets, and can
// optionally track the active wallets.
//
// The Manager enables a one-to-many relationship, allowing a single application
// to manage multiple distinct wallets (e.g., for different coins or different
// accounts) simultaneously.
type Manager struct {
	sync.RWMutex

	// wallets holds the active wallets keyed by their unique name.
	wallets map[string]*Wallet
}

// NewManager creates a new Wallet Manager.
func NewManager() *Manager {
	return &Manager{
		wallets: make(map[string]*Wallet),
	}
}

// createLegacyStore creates the legacy kvdb compatibility store for a new
// wallet.
func createLegacyStore(cfg Config, params CreateWalletParams,
	rootKey *hdkeychain.ExtendedKey) error {

	createParams := kvdb.CreateLegacyWalletParams{
		RootKey:           rootKey,
		PubPassphrase:     params.PubPassphrase,
		PrivatePassphrase: params.PrivatePassphrase,
		ChainParams:       cfg.ChainParams,
		Birthday:          params.Birthday,
	}

	legacyStore, err := kvdb.CreateStore(
		legacyKVDBConfig(cfg), createParams,
	)
	if err != nil {
		return fmt.Errorf("create legacy store: %w", err)
	}

	err = legacyStore.Close()
	if err != nil {
		return fmt.Errorf("close legacy store: %w", err)
	}

	return nil
}

// openLegacyStore opens the legacy kvdb compatibility store for an existing
// wallet.
func openLegacyStore(cfg Config) (*kvdb.StoreHandle, error) {
	openParams := kvdb.OpenStoreParams{
		PubPassphrase: cfg.PubPassphrase,
		ChainParams:   cfg.ChainParams,
	}

	store, err := kvdb.OpenStore(legacyKVDBConfig(cfg), openParams)
	if err != nil {
		return nil, fmt.Errorf("open legacy store: %w", err)
	}

	return store, nil
}

// closeRuntimeStores returns a closer for all stores owned by a loaded wallet.
func closeRuntimeStores(runtimeStore *runtimeStoreHandle,
	legacyStore *kvdb.StoreHandle) func() error {

	return func() error {
		return errors.Join(runtimeStore.close(), legacyStore.Close())
	}
}

// closeStoresAfterError closes stores opened during wallet load while
// preserving err as the primary failure.
func closeStoresAfterError(err error, runtimeStore *runtimeStoreHandle,
	legacyStore *kvdb.StoreHandle) error {

	var closeErr error
	if runtimeStore != nil {
		closeErr = errors.Join(closeErr, runtimeStore.close())
	}

	if legacyStore != nil {
		closeErr = errors.Join(closeErr, legacyStore.Close())
	}

	return errors.Join(err, closeErr)
}

// String returns a summary of the active wallets managed by the Manager.
func (m *Manager) String() string {
	m.RLock()
	defer m.RUnlock()

	names := make([]string, 0, len(m.wallets))
	for name := range m.wallets {
		names = append(names, name)
	}

	sort.Strings(names)

	return fmt.Sprintf("active_wallets=%v", names)
}

// Create creates a new wallet based on the provided configuration and
// initialization parameters. It initializes the database structure and then
// loads the wallet.
func (m *Manager) Create(cfg Config,
	params CreateWalletParams) (*Wallet, error) {

	rootKey, err := m.prepareWalletCreation(cfg, params)
	if err != nil {
		return nil, err
	}

	// Per ADR 0012 a wallet is uniformly watch-only or uniformly
	// spendable. Validate the params.InitialAccounts list upfront so a
	// mismatched-mode create fails before the kvdb wallet create runs
	// (otherwise the wallet row exists on disk while importInitialAccounts
	// later rejects an entry, leaving a half-created wallet).
	err = validateInitialAccountsMode(params)
	if err != nil {
		return nil, err
	}

	// Create the underlying legacy compatibility store structure.
	err = createLegacyStore(cfg, params, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create legacy wallet: %w", err)
	}

	err = createRuntimeWallet(
		context.Background(), cfg, params, rootKey,
	)
	if err != nil {
		return nil, err
	}

	// Load the newly created wallet.
	w, err := m.Load(cfg)
	if err != nil {
		return nil, err
	}

	// If we are in shell mode and have initial accounts, we import them now.
	if params.Mode == ModeShell && len(params.InitialAccounts) > 0 {
		err = w.importInitialAccounts(
			context.Background(), params.InitialAccounts,
		)
		if err != nil {
			return nil, err
		}
	}

	return w, nil
}

// importInitialAccounts imports a list of watch-only accounts into the wallet.
// This is typically used during wallet initialization in shell mode.
func (w *Wallet) importInitialAccounts(ctx context.Context,
	accounts []WatchOnlyAccount) error {

	for _, account := range accounts {
		_, err := w.importAccountInternal(
			ctx, account.Name, account.XPub, account.MasterKeyFingerprint,
			account.AddrType, false,
		)
		if err != nil {
			return fmt.Errorf("failed to import account %s: %w", account.Name,
				err)
		}
	}

	return nil
}

// Load loads an existing wallet from the provided configuration. It opens the
// database, initializes the wallet structure, and registers it with the manager
// for tracking.
func (m *Manager) Load(cfg Config) (*Wallet, error) {
	err := cfg.validate()
	if err != nil {
		return nil, err
	}

	// Check if the wallet is already loaded.
	m.RLock()
	existingW, ok := m.wallets[cfg.Name]
	m.RUnlock()

	if ok {
		return existingW, nil
	}

	legacyStore, err := openLegacyStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("load legacy wallet: %w", err)
	}

	// Apply the safe default for auto-lock duration if not specified.
	if cfg.AutoLockDuration == 0 {
		cfg.AutoLockDuration = defaultLockDuration
	}

	// Initialize the auto-lock timer in a stopped state. We perform a
	// non-blocking drain on the channel to ensure it's empty and won't fire
	// immediately.
	lockTimer := time.NewTimer(0)
	if !lockTimer.Stop() {
		<-lockTimer.C
	}

	runtimeStore, err := runtimeStoreFactory(
		context.Background(), cfg, legacyStore,
	)
	if err != nil {
		return nil, closeStoresAfterError(err, nil, legacyStore)
	}

	store := runtimeStore.store
	vault := kvdb.NewLegacyManagerVault(
		legacyStore.DB, legacyStore.AddrStore,
	)

	// Cache the wallet's master HD fingerprint up-front, before any
	// context/cancel is set up so an error here doesn't leak a cancellable
	// context. The master public key is public wallet metadata from the
	// selected runtime store.
	masterFingerprint, err := runtimeStore.masterFingerprint()
	if err != nil {
		err = fmt.Errorf("cache master fingerprint: %w", err)
		return nil, closeStoresAfterError(err, runtimeStore, legacyStore)
	}

	walletID := runtimeStore.walletInfo.ID
	isWatchOnly := legacyStore.AddrStore.WatchOnly()

	if cfg.DB.withDefaults().Backend != DBBackendKVDB {
		isWatchOnly = runtimeStore.walletInfo.IsWatchOnly
	}

	runtimeStoreClose := closeRuntimeStores(runtimeStore, legacyStore)

	lifetimeCtx, cancel := context.WithCancel(context.Background())

	w := &Wallet{
		cfg:               cfg,
		id:                walletID,
		addrStore:         legacyStore.AddrStore,
		legacyStore:       legacyStore.Store,
		store:             store,
		runtimeStoreClose: runtimeStoreClose,
		cache:             newStoreRuntimeCache(store),
		keyVault:          vault,
		txStore:           legacyStore.TxStore,
		requestChan:       make(chan any),
		lifetimeCtx:       lifetimeCtx,
		cancel:            cancel,
		lockTimer:         lockTimer,
		masterFingerprint: masterFingerprint,
		isWatchOnly:       isWatchOnly,
	}

	syncer := newSyncer(cfg, w.addrStore, w.txStore, w, w.store, w.id)
	syncer.legacyStore = legacyStore.Store
	w.sync = syncer
	w.state = newWalletState(w.sync)

	// Register the wallet.
	m.Lock()
	m.wallets[cfg.Name] = w
	m.Unlock()

	return w, nil
}

// prepareWalletCreation validates the configuration and parameters, and derives
// the root key for wallet creation.
func (m *Manager) prepareWalletCreation(cfg Config,
	params CreateWalletParams) (*hdkeychain.ExtendedKey, error) {

	err := cfg.validate()
	if err != nil {
		return nil, err
	}

	err = params.validate()
	if err != nil {
		return nil, err
	}

	rootKey, err := m.deriveRootKey(cfg, params)
	if err != nil {
		return nil, err
	}

	// If the wallet is NOT watch-only, we require a private root key to be able
	// to sign transactions and derive child private keys.
	if !params.WatchOnly && rootKey != nil && !rootKey.IsPrivate() {
		return nil, fmt.Errorf("%w: private key required for "+
			"non-watch-only wallet", ErrWalletParams)
	}

	return rootKey, nil
}

// deriveRootKey resolves the master extended key based on the creation mode.
func (m *Manager) deriveRootKey(cfg Config,
	params CreateWalletParams) (*hdkeychain.ExtendedKey, error) {

	switch params.Mode {
	case ModeGenSeed:
		return m.genRootKey(cfg)

	case ModeImportSeed:
		return m.deriveFromSeed(cfg, params.Seed)

	case ModeImportExtKey:
		// Ensure an extended key was provided.
		if params.RootKey == nil {
			return nil, fmt.Errorf("%w: root key is required",
				ErrWalletParams)
		}

		// Use the provided extended key (can be XPrv or XPub).
		return params.RootKey, nil

	case ModeShell:
		// In shell mode, no root key is persisted. Accounts will be
		// imported individually.
		return nil, nil //nolint:nilnil

	case ModeUnknown:
		fallthrough

	default:
		return nil, fmt.Errorf("%w: unknown mode %v", ErrWalletParams,
			params.Mode)
	}
}

// genRootKey generates a fresh random seed and derives the master extended
// private key from it.
func (m *Manager) genRootKey(cfg Config) (*hdkeychain.ExtendedKey, error) {
	// Generate a fresh random seed using the recommended length.
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	return m.deriveFromSeed(cfg, seed)
}

// deriveFromSeed derives the master extended private key from the provided
// seed.
func (m *Manager) deriveFromSeed(cfg Config, seed []byte) (
	*hdkeychain.ExtendedKey, error) {

	// Ensure a seed was provided for restoration.
	if len(seed) == 0 {
		return nil, fmt.Errorf("%w: seed is required", ErrWalletParams)
	}

	// Derive the master extended private key from the provided seed.
	key, err := hdkeychain.NewMaster(seed, cfg.ChainParams)
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key: %w", err)
	}

	return key, nil
}
