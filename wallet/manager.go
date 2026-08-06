package wallet

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
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

	// RootKey is required for ModeImportExtKey and must be nil for every
	// other mode, which reject a key they would not use. It must agree with
	// WatchOnly: an XPrv for a spendable wallet, an XPub for a watch-only
	// one.
	RootKey *hdkeychain.ExtendedKey

	// InitialAccounts is optional and names watch-only accounts to import
	// after the wallet is created. It requires WatchOnly and is only
	// honored for ModeShell.
	InitialAccounts []WatchOnlyAccount

	// WatchOnly requests a watch-only wallet, and is the sole authority on
	// whether the created wallet is watch-only. The root key must agree with
	// it: a watch-only wallet takes an XPub root (ModeImportExtKey) or no
	// root at all (ModeShell), while a spendable wallet requires a private
	// root key.
	WatchOnly bool

	// Birthday is the wallet's birthday.
	Birthday time.Time

	// PubPassphrase is the public passphrase for the wallet.
	//
	// Deprecated: only the kvdb backend has a public passphrase. A SQL
	// wallet seals its metadata under a single passphrase, so this field is
	// ignored there and goes away with kvdb support.
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

// Manager is a high-level manager that handles the lifecycle of multiple
// wallets. It acts as a factory for creating and loading wallets, and can
// optionally track the active wallets.
//
// The Manager enables a one-to-many relationship, allowing a single application
// to manage multiple distinct wallets (e.g., for different coins or different
// accounts) simultaneously.
type Manager struct {
	sync.RWMutex

	// wallets holds the active wallets keyed by their unique name, published
	// as soon as they are assembled. A ModeShell Create imports its initial
	// accounts after publishing, so a wallet can be observed here before
	// that import finishes.
	wallets map[string]*Wallet

	// backend owns the database and resolves the storage dependencies for
	// every wallet this Manager serves.
	backend managerBackend

	// chainParams is fixed at construction and shared by every wallet.
	chainParams *chaincfg.Params
}

// NewManager opens the one database described by cfg and returns a Manager that
// owns it.
//
// Every wallet the Manager serves shares that database. The legacy kvdb
// backend remains single-wallet until it is removed; SQL stores distinguish
// wallets by ID. The caller stops its wallets and then calls Close.
func NewManager(ctx context.Context, cfg ManagerConfig) (*Manager, error) {
	err := cfg.validate()
	if err != nil {
		return nil, err
	}

	var backend managerBackend

	switch cfg.Backend {
	case DBBackendKVDB:
		backend, err = newKVDBManagerBackend(cfg)

	case DBBackendSQLite:
		backend, err = newSQLiteManagerBackend(ctx, cfg)

	case DBBackendPostgres:
		backend, err = newPostgresManagerBackend(ctx, cfg)
	}

	if err != nil {
		return nil, err
	}

	return &Manager{
		wallets:     make(map[string]*Wallet),
		backend:     backend,
		chainParams: cfg.ChainParams,
	}, nil
}

// Close releases the database this Manager owns.
//
// The caller must have stopped every wallet first. There is no close fence and
// no use-after-close guarantee beyond that contract.
func (m *Manager) Close() error {
	return m.backend.close()
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

	// The Manager owns the network for every wallet it serves, so overwrite
	// the caller's copy before validating. A caller that leaves it unset, or
	// sets a conflicting one, gets the Manager's.
	cfg.ChainParams = m.chainParams

	// Validate the configuration and parameters before touching the cache
	// or any store, so a malformed request fails on its own merits rather
	// than on a name collision or store error.
	err := cfg.validate()
	if err != nil {
		return nil, err
	}

	err = params.validate()
	if err != nil {
		return nil, err
	}

	// Per ADR 0012 a wallet is uniformly watch-only or uniformly
	// spendable. Validate the params.InitialAccounts list upfront so a
	// mismatched-mode create fails before any backend create runs
	// (otherwise the wallet row exists on disk while importInitialAccounts
	// later rejects an entry, leaving a half-created wallet).
	err = validateInitialAccountsMode(params)
	if err != nil {
		return nil, err
	}

	rootKey, err := m.prepareWalletCreation(cfg, params)
	if err != nil {
		return nil, err
	}

	data, err := m.backend.create(
		context.Background(), cfg, params, rootKey,
	)
	if err != nil {
		return nil, err
	}

	w := newManagedWallet(cfg, data)

	m.Lock()
	m.wallets[cfg.Name] = w
	m.Unlock()

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
			ctx, account.Name, account.XPub,
			account.MasterKeyFingerprint, account.AddrType, false,
		)
		if err != nil {
			return fmt.Errorf("failed to import account %s: %w",
				account.Name, err)
		}
	}

	return nil
}

// validate ensures that the parameters are consistent with the chosen creation
// mode.
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

	// A seed is private material: both seed modes produce a private root
	// key that a watch-only wallet cannot hold. Reject the contradiction
	// here, before the key is generated or derived, so no signing material
	// is ever created only to be thrown away.
	if p.WatchOnly && (p.Mode == ModeGenSeed || p.Mode == ModeImportSeed) {
		return fmt.Errorf("%w: a seed derives a private root key, which "+
			"a watch-only wallet cannot hold; use ModeImportExtKey "+
			"with an XPub or ModeShell", ErrWalletParams)
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

// Load loads an existing wallet from the provided configuration. It opens the
// database, initializes the wallet structure, and registers it with the manager
// for tracking.
//
// TODO(yy): concurrent Load calls for the same name are not serialized, so two
// callers racing on one wallet can both open a store. Call it from one
// goroutine per wallet until that is fixed.
func (m *Manager) Load(cfg Config) (*Wallet, error) {
	// The Manager owns the network for every wallet it serves; see Create.
	cfg.ChainParams = m.chainParams

	err := cfg.validate()
	if err != nil {
		return nil, err
	}

	// A wallet already published under this name is returned as is; callers
	// serialize Create and Load, so a miss means this call builds it.
	m.RLock()
	existingW, ok := m.wallets[cfg.Name]
	m.RUnlock()

	if ok {
		return existingW, nil
	}

	data, err := m.backend.load(context.Background(), cfg)
	if err != nil {
		return nil, err
	}

	w := newManagedWallet(cfg, data)

	m.Lock()
	m.wallets[cfg.Name] = w
	m.Unlock()

	return w, nil
}

// prepareWalletCreation derives the root key for wallet creation and checks it
// against the requested watch-only state. The caller has already validated cfg
// and params.
func (m *Manager) prepareWalletCreation(cfg Config,
	params CreateWalletParams) (*hdkeychain.ExtendedKey, error) {

	rootKey, err := m.deriveRootKey(cfg, params)
	if err != nil {
		return nil, err
	}

	err = validateWatchOnlyRootKey(params, rootKey)
	if err != nil {
		return nil, err
	}

	return rootKey, nil
}

// validateWatchOnlyRootKey checks the derived root key against the requested
// watch-only state.
//
// params.WatchOnly is the single source of truth: every backend persists that
// flag verbatim, so a request whose key material contradicts it is rejected
// here rather than silently reinterpreted.
func validateWatchOnlyRootKey(params CreateWalletParams,
	rootKey *hdkeychain.ExtendedKey) error {

	hasPrivateKey := rootKey != nil && rootKey.IsPrivate()

	switch {
	// A watch-only wallet must not be handed signing material, because
	// nothing persists it: kvdb drops the root key outright and a SQL
	// wallet keeps only its neutered form. Accepting an extended private
	// key here would silently discard the caller's key material, leaving a
	// wallet that cannot sign and a seed it has no record of.
	case params.WatchOnly && hasPrivateKey:
		return fmt.Errorf("%w: watch-only wallet cannot be created "+
			"from a private root key; neuter it first", ErrWalletParams)

	// A spendable wallet needs a root key at all. A rootless wallet holds
	// its accounts as imported extended public keys, which is watch-only by
	// construction.
	case !params.WatchOnly && rootKey == nil:
		return fmt.Errorf("%w: a rootless wallet holds no signing "+
			"material; it requires WatchOnly", ErrWalletParams)

	// That root key must be private, so the wallet can sign transactions
	// and derive child private keys.
	case !params.WatchOnly && !hasPrivateKey:
		return fmt.Errorf("%w: private key required for "+
			"non-watch-only wallet", ErrWalletParams)
	}

	return nil
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

// genRootKey generates a fresh random seed and derives its master extended
// private key.
func (m *Manager) genRootKey(cfg Config) (*hdkeychain.ExtendedKey, error) {
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
