package wallet

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

var (
	// ErrWalletNotFound is returned when a wallet is not found by Manager.Load.
	ErrWalletNotFound = errors.New("wallet not found")

	// ErrWalletParams is returned when the creation parameters are invalid.
	ErrWalletParams = errors.New("invalid wallet params")

	// ErrInvalidDatabaseIdentity reports invalid Manager network identity
	// input before a SQL database is opened.
	ErrInvalidDatabaseIdentity = errors.New("invalid database identity")

	// ErrDatabaseIdentityMismatch reports that an existing SQL database is
	// owned by a different or malformed network identity.
	ErrDatabaseIdentityMismatch = errors.New("database identity mismatch")
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

	// ModeImportExtKey indicates creating a spendable wallet from an extended
	// private root key (CreateWalletParams.RootKey).
	ModeImportExtKey

	// ModeShell indicates creating a watch-only wallet shell without a root
	// key. Its optional initial accounts contain account XPubs.
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
	// Name is the durable identity used for Manager cache and Store operations.
	Name string

	// Mode determines which fields below are required.
	Mode CreateMode

	// Seed is required for ModeImportSeed. Ignored for others.
	Seed []byte

	// RootKey is the required ModeImportExtKey XPrv. XPub-root creation is
	// unsupported; use a ModeShell wallet and import account XPubs.
	RootKey *hdkeychain.ExtendedKey

	// InitialAccounts is optional and names watch-only accounts to import
	// after the wallet is created. It requires WatchOnly and is only
	// honored for ModeShell.
	InitialAccounts []WatchOnlyAccount

	// WatchOnly requests a watch-only wallet and is valid only for ModeShell.
	WatchOnly bool

	// Birthday is the wallet's birthday.
	Birthday time.Time

	// PubPassphrase creates the legacy kvdb wallet. SQL backends ignore it
	// because they have no public encryption passphrase.
	//
	// Remove this field with kvdb support.
	PubPassphrase []byte

	// PrivatePassphrase protects the wallet's secret material. SQL backends
	// require it for every wallet; legacy kvdb permits it to be empty when
	// creating a watch-only wallet.
	PrivatePassphrase []byte
}

// LoadWalletParams identifies an existing Wallet and carries inputs needed
// only while its backend opens durable state.
type LoadWalletParams struct {
	// Name is the required runtime identity used by the Manager cache and SQL
	// wallet lookup. The legacy kvdb backend also uses it for the one Wallet
	// instance it can serve, but does not persist it as an alias.
	Name string

	// PubPassphrase opens the legacy kvdb wallet. SQL backends ignore it
	// because they have no public encryption passphrase.
	//
	// Remove this field with kvdb support.
	PubPassphrase []byte
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

	// wallets holds the active wallets keyed by their unique name. The
	// Manager lock serializes runtime assembly, Store access, and cache
	// installation. A ModeShell Create imports its initial accounts after
	// installation, so a wallet can be observed here before that import
	// finishes.
	wallets map[string]*Wallet

	// backend owns the database and resolves the storage dependencies for
	// every wallet this Manager serves.
	backend managerBackend

	// config is the immutable shared policy retained at construction.
	config ManagerConfig
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

	// Clone mutable network state and resolve defaults before the backend is
	// opened, making the retained configuration the sole runtime authority for
	// every Wallet assembled by this Manager.
	chainParams, err := cloneChainParams(cfg.ChainParams)
	if err != nil {
		return nil, fmt.Errorf("copy chain parameters: %w", err)
	}

	cfg.ChainParams = chainParams

	// Startup has no load request from which to recover a legacy public
	// passphrase, so isolate the configured bytes before the backend retains
	// them for aggregate startup.
	cfg.KVDBPubPassphrase = slices.Clone(cfg.KVDBPubPassphrase)

	if cfg.WalletSyncRetryInterval == 0 {
		cfg.WalletSyncRetryInterval = initialBackoff
	}

	if cfg.AutoLockDuration <= 0 {
		cfg.AutoLockDuration = defaultLockDuration
	}

	identity, err := newManagerDatabaseIdentity(cfg)
	if err != nil {
		return nil, err
	}

	var backend managerBackend

	switch cfg.Backend {
	case DBBackendKVDB:
		backend, err = newKVDBManagerBackend(cfg)

	case DBBackendSQLite:
		backend, err = newSQLiteManagerBackend(ctx, cfg, identity)

	case DBBackendPostgres:
		backend, err = newPostgresManagerBackend(ctx, cfg, identity)
	}

	if err != nil {
		return nil, translateDatabaseIdentityError(err)
	}

	// The kvdb backend now owns the cloned startup credential. Do not retain
	// another reference in the Manager's otherwise immutable configuration.
	cfg.KVDBPubPassphrase = nil

	return &Manager{
		wallets: make(map[string]*Wallet),
		backend: backend,
		config:  cfg,
	}, nil
}

// newManagerDatabaseIdentity validates the owned network snapshot before a SQL
// connection is opened while leaving the legacy kvdb startup path unchanged.
func newManagerDatabaseIdentity(
	cfg ManagerConfig) (db.DatabaseIdentity, error) {

	if cfg.Backend == DBBackendKVDB {
		return db.DatabaseIdentity{}, nil
	}

	identity, err := db.NewDatabaseIdentity(
		&cfg.ChainParams, cfg.SignetChallengeDigest,
	)
	if err != nil {
		return db.DatabaseIdentity{}, translateDatabaseIdentityError(err)
	}

	return identity, nil
}

// translateDatabaseIdentityError exposes internal identity classifications at
// the public Manager boundary while preserving unrelated backend failures.
func translateDatabaseIdentityError(err error) error {
	switch {
	case errors.Is(err, db.ErrInvalidDatabaseIdentity):
		return fmt.Errorf("%w: %w", ErrInvalidDatabaseIdentity, err)

	case errors.Is(err, db.ErrDatabaseIdentityMismatch):
		return fmt.Errorf("%w: %w", ErrDatabaseIdentityMismatch, err)

	default:
		return err
	}
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

// validateManagedWalletName rejects an absent durable identity before cache,
// key-derivation, or Store work can obscure the caller error.
func validateManagedWalletName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: Name", ErrMissingParam)
	}

	return nil
}

// Create persists and assembles a Wallet with Manager-owned runtime policy.
func (m *Manager) Create(params CreateWalletParams) (*Wallet, error) {
	// Validate identity before key derivation or Store work can produce a less
	// useful error or side effect.
	err := validateManagedWalletName(params.Name)
	if err != nil {
		return nil, err
	}

	err = params.validate()
	if err != nil {
		return nil, err
	}

	rootKey, err := m.deriveRootKey(params)
	if err != nil {
		return nil, err
	}

	m.Lock()

	// The Manager mutex keeps runtime assembly, Store mutation, and cache
	// publication atomic so no partial Wallet becomes observable.
	walletCfg, err := m.config.walletConfig(params.Name)
	if err != nil {
		m.Unlock()

		return nil, err
	}

	data, err := m.backend.create(context.Background(), params, rootKey)
	if err != nil {
		m.Unlock()

		return nil, err
	}

	w := newManagedWallet(walletCfg, data)
	m.wallets[walletCfg.Name] = w
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
	if p.Mode != ModeShell && len(p.InitialAccounts) > 0 {
		return fmt.Errorf("%w: initial accounts should only be set "+
			"for ModeShell", ErrWalletParams)
	}

	switch p.Mode {
	case ModeGenSeed:
		if p.WatchOnly {
			return fmt.Errorf("%w: ModeGenSeed is spendable", ErrWalletParams)
		}

		if len(p.Seed) != 0 {
			return fmt.Errorf("%w: seed should not be set for "+
				"ModeGenSeed", ErrWalletParams)
		}

		if p.RootKey != nil {
			return fmt.Errorf("%w: root key should not be set for "+
				"ModeGenSeed", ErrWalletParams)
		}

	case ModeImportSeed:
		if p.WatchOnly {
			return fmt.Errorf("%w: ModeImportSeed must be spendable",
				ErrWalletParams)
		}

		if len(p.Seed) == 0 {
			return fmt.Errorf("%w: seed is required for "+
				"ModeImportSeed", ErrWalletParams)
		}

		if p.RootKey != nil {
			return fmt.Errorf("%w: root key should not be set for "+
				"ModeImportSeed", ErrWalletParams)
		}

	case ModeImportExtKey:
		if p.RootKey == nil {
			return fmt.Errorf("%w: root key is required for "+
				"ModeImportExtKey", ErrWalletParams)
		}

		if len(p.Seed) != 0 {
			return fmt.Errorf("%w: seed should not be set for "+
				"ModeImportExtKey", ErrWalletParams)
		}

		if !p.RootKey.IsPrivate() {
			return fmt.Errorf("%w: XPub-root wallet creation is "+
				"unsupported; use ModeShell", ErrWalletParams)
		}

		if p.WatchOnly {
			return fmt.Errorf("%w: ModeImportExtKey must be spendable",
				ErrWalletParams)
		}

	case ModeShell:
		if !p.WatchOnly {
			return fmt.Errorf("%w: ModeShell must be watch-only",
				ErrWalletParams)
		}

		if len(p.Seed) != 0 {
			return fmt.Errorf("%w: seed should not be set for "+
				"ModeShell", ErrWalletParams)
		}

		if p.RootKey != nil {
			return fmt.Errorf("%w: root key should not be set for "+
				"ModeShell", ErrWalletParams)
		}

		return validateInitialAccountKeys(p.InitialAccounts)

	case ModeUnknown:
		fallthrough

	default:
		return fmt.Errorf("%w: unknown mode %v", ErrWalletParams, p.Mode)
	}

	return nil
}

// validateInitialAccountKeys requires public keys for shell account imports.
func validateInitialAccountKeys(accounts []WatchOnlyAccount) error {
	for i, account := range accounts {
		switch {
		case account.XPub == nil:
			return fmt.Errorf("%w: account %d needs XPub", ErrWalletParams, i)
		case account.XPub.IsPrivate():
			return fmt.Errorf("%w: account %d needs XPub, not XPrv",
				ErrWalletParams, i)
		}
	}

	return nil
}

// Load opens the requested durable Wallet and assembles it from Manager-owned
// runtime policy. If it does not exist, Load returns ErrWalletNotFound.
func (m *Manager) Load(params LoadWalletParams) (*Wallet, error) {
	// Validate identity before cache or backend work so every backend reports
	// the same caller error for an empty name.
	err := validateManagedWalletName(params.Name)
	if err != nil {
		return nil, err
	}

	name := params.Name

	m.Lock()
	defer m.Unlock()

	// Serializing the cache check through installation ensures concurrent cold
	// Loads share the one Wallet assembled by the first caller.
	existingW, ok := m.wallets[name]
	if ok {
		return existingW, nil
	}

	// A cache miss receives a fresh Wallet-local policy assembled from the
	// Manager's immutable configuration snapshot.
	walletCfg, err := m.config.walletConfig(name)
	if err != nil {
		return nil, err
	}

	// Only the narrow request reaches the backend. The assembled Wallet never
	// retains a legacy public passphrase.
	data, err := m.backend.load(context.Background(), params)
	if err != nil {
		// Hide the database sentinel at the public Manager boundary while
		// retaining the requested wallet name for caller diagnostics.
		if errors.Is(err, db.ErrWalletNotFound) {
			return nil, fmt.Errorf(
				"wallet %q: %w", name, ErrWalletNotFound,
			)
		}

		return nil, err
	}

	w := newManagedWallet(walletCfg, data)
	m.wallets[walletCfg.Name] = w

	return w, nil
}

// deriveRootKey resolves the master extended key after creation parameters have
// passed validation.
func (m *Manager) deriveRootKey(
	params CreateWalletParams) (*hdkeychain.ExtendedKey, error) {

	if params.Mode == ModeGenSeed {
		return m.genRootKey()
	}

	if params.Mode == ModeImportSeed {
		return m.deriveFromSeed(params.Seed)
	}

	if params.Mode == ModeImportExtKey {
		return params.RootKey, nil
	}

	// The only remaining validated mode is ModeShell. It persists no root
	// key; accounts are imported individually.
	return nil, nil //nolint:nilnil
}

// genRootKey generates a fresh random seed and derives its master extended
// private key.
func (m *Manager) genRootKey() (*hdkeychain.ExtendedKey, error) {
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	return m.deriveFromSeed(seed)
}

// deriveFromSeed derives the master extended private key from the provided
// seed.
func (m *Manager) deriveFromSeed(seed []byte) (
	*hdkeychain.ExtendedKey, error) {

	// Ensure a seed was provided for restoration.
	if len(seed) == 0 {
		return nil, fmt.Errorf("%w: seed is required", ErrWalletParams)
	}

	// Derive the master extended private key from the provided seed.
	key, err := hdkeychain.NewMaster(seed, &m.config.ChainParams)
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key: %w", err)
	}

	return key, nil
}
