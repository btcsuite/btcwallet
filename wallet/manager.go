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
	"github.com/btcsuite/btcwallet/wallet/internal/db"
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

	// WatchOnly controls whether the resulting wallet is watch-only. A
	// watch-only wallet must be created from public-only key material, so
	// WatchOnly=true is only valid with an XPub root (ModeImportExtKey) or a
	// rootless shell (ModeShell).
	// - If true with XPub/Shell input: the wallet is watch-only (the XPub case
	//   simply records the wallet watch-only; the shell case holds no root).
	// - If true with Seed/GenSeed or an XPrv root (ModeImportSeed,
	//   ModeGenSeed, or ModeImportExtKey with a private key): rejected with
	//   ErrWalletParams. These modes always yield a private master key, and
	//   silently discarding it would build a spendable legacy manager while
	//   recording the wallet watch-only. Neuter the key to an XPub and pass it
	//   via ModeImportExtKey to create a watch-only wallet from such material.
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

// validateInitialAccounts checks every initial account's extended public key
// against the same rules importInitialAccounts later enforces, and rejects
// duplicate (effective scope, name) entries, so both failure classes fail the
// create before any store is written rather than after, where they would leave
// a half-created wallet that a corrected retry could not get past.
//
// Duplicates must be caught up front because importInitialAccounts inserts the
// accounts one by one: the unique (wallet, scope, name) constraint would only
// reject the second copy after the wallet row, legacy wallet, and earlier
// accounts had already been committed durably. The dedup uses the xpub-derived
// effective scope rather than the caller-declared one because that is the
// scope the import persists under.
func validateInitialAccounts(cfg Config, params CreateWalletParams) error {
	type scopeName struct {
		scope waddrmgr.KeyScope
		name  string
	}

	seen := make(map[scopeName]struct{}, len(params.InitialAccounts))
	for _, account := range params.InitialAccounts {
		err := validateExtendedPubKey(account.XPub, true, cfg.ChainParams)
		if err != nil {
			return fmt.Errorf("invalid initial account %q: %w",
				account.Name, err)
		}

		// Dedup on the effective scope the import actually persists under,
		// not the caller-declared account.Scope. importInitialAccounts looks
		// the account up by the scope derived from the xpub (see
		// initialAccountAlreadyImported / importAccountInternal), so two
		// entries with the same name and the same xpub-derived scope but
		// different declared scopes would pass this prevalidation yet collide
		// on the unique (wallet, scope, name) constraint mid-import, after the
		// wallet row and earlier accounts were already committed.
		addrType := account.AddrType

		scope, _, err := keyScopeFromPubKey(account.XPub, &addrType)
		if err != nil {
			return fmt.Errorf("invalid initial account %q: %w",
				account.Name, err)
		}

		key := scopeName{scope: scope, name: account.Name}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: duplicate initial account %q in "+
				"scope %d'/%d'", ErrWalletParams, account.Name,
				scope.Purpose, scope.Coin)
		}

		seen[key] = struct{}{}
	}

	return nil
}

// seedDefaultAccounts seeds account 0 for each default key scope of a freshly
// created spendable SQL wallet. The legacy kvdb backend seeds these during
// waddrmgr.Create, but the SQL create path inserts only wallet and secret
// rows, so without this a SQL wallet cannot derive a normal receiving address.
func seedDefaultAccounts(ctx context.Context, w *Wallet,
	rootKey *hdkeychain.ExtendedKey, privatePassphrase []byte) error {

	// Deriving and encrypting account keys requires the key vault's private
	// crypto key, which is locked after load. We pass a negative timeout to
	// disable the vault's auto-lock: this transient unlock is re-locked by
	// the deferred Lock below.
	err := w.keyVault.Unlock(ctx, privatePassphrase, -1)
	if err != nil {
		return fmt.Errorf("unlock key vault: %w", err)
	}

	// Lock is void and idempotent: the vault swallows an already-locked
	// condition and logs any other failure internally.
	defer w.keyVault.Lock()

	deriveFn := newAccountDeriveFn(rootKey, w.keyVault, w.masterFingerprint)

	for _, scope := range waddrmgr.DefaultKeyScopes {
		err := seedDefaultAccountForScope(ctx, w, scope, deriveFn)
		if err != nil {
			return fmt.Errorf("create default account for scope "+
				"%v: %w", scope, err)
		}
	}

	return nil
}

// seedDefaultAccountForScope creates the default account for a single scope,
// skipping the insert when it already exists. Seeding must be idempotent
// because a Create that failed partway through (after seeding only some of the
// default scopes) is retried against the same wallet; replaying the insert for
// an already-seeded scope would otherwise hit the unique (wallet, scope, name)
// constraint and wedge the retry.
func seedDefaultAccountForScope(ctx context.Context, w *Wallet,
	scope waddrmgr.KeyScope, deriveFn db.AccountDerivationFunc) error {

	defaultName := waddrmgr.DefaultAccountName

	_, err := w.store.GetAccount(ctx, db.GetAccountQuery{
		WalletID:    w.id,
		Scope:       db.KeyScope(scope),
		Name:        &defaultName,
		SkipBalance: true,
	})
	switch {
	// Already seeded by an earlier attempt; nothing to do.
	case err == nil:
		return nil

	// Not seeded yet (the scope or the account is absent); fall through to
	// create it below.
	case errors.Is(err, db.ErrAccountNotFound):

	default:
		return fmt.Errorf("check default account: %w", err)
	}

	_, err = w.store.CreateDerivedAccount(
		ctx, db.CreateDerivedAccountParams{
			WalletID: w.id,
			Scope:    db.KeyScope(scope),
			Name:     defaultName,
		}, deriveFn,
	)
	if err != nil {
		return err
	}

	return nil
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
func createLegacyStore(ctx context.Context, cfg Config,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) ([]byte,
	error) {

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
	switch {
	// A legacy wallet already exists at this path. A previous Create that
	// failed after this step (runtime create or initial-account import)
	// leaves it behind; tolerate it so Create can be retried instead of
	// being wedged by ErrAlreadyExists, mirroring the idempotent runtime
	// create. waddrmgr.Create wraps the sentinel in a ManagerError several
	// layers down and waddrmgr.IsError does not unwrap %w, so match with
	// errors.As.
	//
	// Reopen the existing legacy store to recover its encrypted master HD
	// key rather than returning a nil seed: a nil seed would let the SQL
	// runtime row be created with no EncryptedMasterPrivKey for a spendable
	// wallet, so its later GetEncryptedHDSeed would fail and break SQL
	// account/key derivation.
	case isLegacyWalletAlreadyExists(err):
		return readExistingLegacyEncryptedSeed(ctx, cfg, params, rootKey)

	case err != nil:
		return nil, fmt.Errorf("create legacy store: %w", err)
	}

	// Capture the encrypted master HD private key the legacy create just
	// persisted, so the runtime store can persist the same blob (the runtime
	// key vault is backed by this legacy manager, so it decrypts unchanged).
	encryptedSeed, err := legacyEncryptedSeed(
		ctx, legacyStore, params, rootKey,
	)
	if err != nil {
		return nil, errors.Join(err, legacyStore.Close())
	}

	err = legacyStore.Close()
	if err != nil {
		return nil, fmt.Errorf("close legacy store: %w", err)
	}

	return encryptedSeed, nil
}

// readExistingLegacyEncryptedSeed reopens an already-created legacy store and
// reads its encrypted master HD key. It is used on the Create retry path,
// where the legacy wallet exists from an earlier attempt that failed before
// the runtime row was committed.
func readExistingLegacyEncryptedSeed(ctx context.Context, cfg Config,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) ([]byte,
	error) {

	legacyStore, err := openLegacyStore(cfg)
	if err != nil {
		return nil, err
	}

	encryptedSeed, err := legacyEncryptedSeed(
		ctx, legacyStore, params, rootKey,
	)
	if err != nil {
		return nil, errors.Join(err, legacyStore.Close())
	}

	err = legacyStore.Close()
	if err != nil {
		return nil, fmt.Errorf("close legacy store: %w", err)
	}

	return encryptedSeed, nil
}

// legacyEncryptedSeed reads the encrypted master HD private key from an open
// legacy store for spendable wallets. Watch-only, shell, and xpub-only wallets
// hold no master secret, so it returns a nil seed for them.
func legacyEncryptedSeed(ctx context.Context, legacyStore *kvdb.StoreHandle,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) ([]byte,
	error) {

	// Only a spendable wallet backed by a private root key holds an
	// encrypted master HD key; otherwise the legacy manager was created
	// watch-only and has no such secret to read.
	if params.WatchOnly || rootKey == nil || !rootKey.IsPrivate() {
		return nil, nil
	}

	encryptedSeed, err := legacyStore.Store.GetEncryptedHDSeed(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("read legacy master HD key: %w", err)
	}

	return encryptedSeed, nil
}

// isLegacyWalletAlreadyExists reports whether err indicates the legacy
// waddrmgr namespace was already initialized. The sentinel is wrapped in a
// ManagerError several fmt layers down, so it must be matched with errors.As
// rather than waddrmgr.IsError (which does not unwrap).
func isLegacyWalletAlreadyExists(err error) bool {
	var mErr waddrmgr.ManagerError

	return errors.As(err, &mErr) && mErr.ErrorCode == waddrmgr.ErrAlreadyExists
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

	// Prevalidate every initial account's extended key before any store is
	// written, so a malformed xpub fails the create up front instead of
	// leaving a half-created wallet that blocks a corrected retry.
	err = validateInitialAccounts(cfg, params)
	if err != nil {
		return nil, err
	}

	// Create the underlying legacy compatibility store structure, capturing
	// the encrypted master HD key it persisted so the runtime store can
	// persist the same blob (F2).
	encryptedSeed, err := createLegacyStore(
		context.Background(), cfg, params, rootKey,
	)
	if err != nil {
		return nil, fmt.Errorf("create legacy wallet: %w", err)
	}

	err = createRuntimeWallet(
		context.Background(), cfg, params, rootKey, encryptedSeed,
	)
	if err != nil {
		return nil, err
	}

	// Load the newly created wallet.
	w, err := m.Load(cfg)
	if err != nil {
		return nil, err
	}

	// Any failure past this point has already registered w in the manager
	// cache with open stores, so it must tear w down before returning;
	// otherwise the cache is left holding a partial wallet whose stores
	// stay open and whose name blocks a corrected retry.
	discardOnErr := func(err error) error {
		return errors.Join(err, w.discardUnstarted())
	}

	// Seed the default accounts for spendable SQL wallets (F1). The kvdb
	// backend already seeds account 0 per scope during legacy create; the
	// SQL create path does not, so a fresh SQL wallet would otherwise fail
	// to derive its first receiving address.
	isKVDB := cfg.DB.withDefaults().Backend == DBBackendKVDB
	spendable := !params.WatchOnly && rootKey != nil && rootKey.IsPrivate()
	if !isKVDB && spendable {
		err = seedDefaultAccounts(
			context.Background(), w, rootKey, params.PrivatePassphrase,
		)
		if err != nil {
			return nil, discardOnErr(
				fmt.Errorf("seed default accounts: %w", err),
			)
		}
	}

	// If we are in shell mode and have initial accounts, we import them now.
	if params.Mode == ModeShell && len(params.InitialAccounts) > 0 {
		err = w.importInitialAccounts(
			context.Background(), params.InitialAccounts,
		)
		if err != nil {
			return nil, discardOnErr(err)
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

	// Deregister the wallet from the cache once it stops, so a later Load
	// rebuilds it with fresh stores instead of handing back a stopped
	// wallet whose runtime stores are closed.
	name := cfg.Name
	w.onStopped = func() {
		m.Lock()
		// Only evict this exact instance; a concurrent Load may have
		// already replaced it with a fresh wallet of the same name.
		if m.wallets[name] == w {
			delete(m.wallets, name)
		}
		m.Unlock()
	}

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

	// Conversely, a watch-only wallet must not be backed by a private root
	// key: legacy creation infers watch-only from a nil root key, so a
	// private root would build a spendable legacy manager while the runtime
	// store records the wallet as watch-only. ModeImportSeed and ModeGenSeed
	// always derive a private master key, so WatchOnly=true is rejected for
	// them too; create a watch-only wallet from an XPub (ModeImportExtKey) or
	// a rootless shell (ModeShell) instead.
	if params.WatchOnly && rootKey != nil && rootKey.IsPrivate() {
		return nil, fmt.Errorf("%w: watch-only wallet requires an xpub "+
			"or shell input; a seed or private root key is not "+
			"allowed", ErrWalletParams)
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
