package wallet

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	kvdb "github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// ErrWalletParams is returned when the creation parameters are invalid.
	ErrWalletParams = errors.New("invalid wallet params")

	// ErrWalletExists is returned by Create when a wallet with the
	// requested name already exists end to end. A partial wallet left by an
	// earlier failed create is recoverable and does not trigger this error.
	ErrWalletExists = errors.New("wallet already exists")
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
//
// It returns the number of default accounts it actually created. A retry over
// a partial create skips the scopes an earlier attempt already seeded, so a
// zero count means every default account was already present.
func seedDefaultAccounts(ctx context.Context, w *Wallet,
	rootKey *hdkeychain.ExtendedKey, privatePassphrase []byte) (int, error) {

	// Deriving and encrypting account keys requires the key vault's private
	// crypto key, which is locked after load. We pass a negative timeout to
	// disable the vault's auto-lock: this transient unlock is re-locked by
	// the deferred Lock below.
	err := w.keyVault.Unlock(ctx, privatePassphrase, -1)
	if err != nil {
		return 0, fmt.Errorf("unlock key vault: %w", err)
	}

	// Lock is void and idempotent: the vault swallows an already-locked
	// condition and logs any other failure internally.
	defer w.keyVault.Lock()

	deriveFn := newAccountDeriveFn(rootKey, w.keyVault, w.masterFingerprint)

	created := 0
	for _, scope := range waddrmgr.DefaultKeyScopes {
		seeded, err := seedDefaultAccountForScope(
			ctx, w, scope, deriveFn,
		)
		if err != nil {
			return 0, fmt.Errorf("create default account for scope "+
				"%v: %w", scope, err)
		}

		if seeded {
			created++
		}
	}

	return created, nil
}

// seedDefaultAccountForScope creates the default account for a single scope,
// skipping the insert when it already exists. Seeding must be idempotent
// because a Create that failed partway through (after seeding only some of the
// default scopes) is retried against the same wallet; replaying the insert for
// an already-seeded scope would otherwise hit the unique (wallet, scope, name)
// constraint and wedge the retry.
//
// It reports whether it created the account (true) or found it already seeded
// (false), so the caller can tell a fresh create from a no-op retry.
func seedDefaultAccountForScope(ctx context.Context, w *Wallet,
	scope waddrmgr.KeyScope, deriveFn db.AccountDerivationFunc) (bool, error) {

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
		return false, nil

	// Not seeded yet (the scope or the account is absent); fall through to
	// create it below.
	case errors.Is(err, db.ErrAccountNotFound):

	default:
		return false, fmt.Errorf("check default account: %w", err)
	}

	_, err = w.store.CreateDerivedAccount(
		ctx, db.CreateDerivedAccountParams{
			WalletID: w.id,
			Scope:    db.KeyScope(scope),
			Name:     defaultName,
		}, deriveFn,
	)
	if err != nil {
		return false, fmt.Errorf("create default account: %w", err)
	}

	return true, nil
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

	// wallets holds the active wallets keyed by their unique name. A wallet
	// is published here only once it is ready for normal runtime use: for a
	// Create that means after its post-load initialization (default-account
	// seeding and initial-account import) has completed.
	wallets map[string]*Wallet

	// creating tracks the wallet names whose Create is in progress, keyed by
	// name to a channel that is closed when the create completes (whether it
	// published a wallet or failed and cleaned up). It guards the window
	// between a wallet's durable rows being written and its post-load
	// initialization finishing, during which the wallet is in a create-only
	// state and must not be exposed through the cache. A concurrent Load or
	// Create for the same name waits on the channel and then re-checks the
	// cache, so no caller can observe or open a wallet that Create is still
	// initializing.
	creating map[string]chan struct{}
}

// NewManager creates a new Wallet Manager.
func NewManager() *Manager {
	return &Manager{
		wallets:  make(map[string]*Wallet),
		creating: make(map[string]chan struct{}),
	}
}

// createLegacyStore creates the legacy kvdb compatibility store for a new
// wallet. It reports whether a legacy wallet already existed at this path so
// Create can distinguish a fresh create from a retry over a partial one.
func createLegacyStore(ctx context.Context, cfg Config,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) ([]byte,
	bool, time.Time, error) {

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
	// account/key derivation. Reports legacyExisted=true so Create can
	// decide whether this is a recoverable partial create or a fully
	// created wallet that must be rejected.
	case isLegacyWalletAlreadyExists(err):
		encryptedSeed, legacyBirthday, err :=
			readExistingLegacyEncryptedSeed(ctx, cfg, params, rootKey)

		return encryptedSeed, true, legacyBirthday, err

	case err != nil:
		return nil, false, time.Time{}, fmt.Errorf(
			"create legacy store: %w", err,
		)
	}

	// Capture the encrypted master HD private key the legacy create just
	// persisted, so the runtime store can persist the same blob (the runtime
	// key vault is backed by this legacy manager, so it decrypts unchanged).
	encryptedSeed, err := legacyEncryptedSeed(
		ctx, legacyStore, params, rootKey,
	)
	if err != nil {
		return nil, false, time.Time{}, errors.Join(
			err, legacyStore.Close(),
		)
	}

	err = legacyStore.Close()
	if err != nil {
		return nil, false, time.Time{}, fmt.Errorf(
			"close legacy store: %w", err,
		)
	}

	// A fresh create has no pre-existing legacy birthday to reuse; the
	// runtime row uses the requested birthday with the safety margin
	// applied. Report a zero time to signal that.
	return encryptedSeed, false, time.Time{}, nil
}

// readExistingLegacyEncryptedSeed reopens an already-created legacy store,
// verifies the retry root key matches the wallet that was originally created,
// and reads its encrypted master HD key. It is used on the Create retry path,
// where the legacy wallet exists from an earlier attempt that failed before
// the runtime row was committed.
//
// It also returns the legacy wallet's original (safety-margin-applied)
// birthday so the runtime row reuses it instead of the retry's birthday:
// callers commonly pass a fresh time.Now() per attempt, and the runtime
// birthday drives the initial SyncedTo tip, so persisting a later retry
// birthday would make the wallet skip deposits made before it.
func readExistingLegacyEncryptedSeed(ctx context.Context, cfg Config,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) ([]byte,
	time.Time, error) {

	legacyStore, err := openLegacyStore(cfg)
	if err != nil {
		return nil, time.Time{}, err
	}

	// Guard against a retry that supplies different key material from the
	// original create, or that would downgrade a spendable wallet to
	// watch-only, before we read the seed and derive any runtime metadata
	// from rootKey.
	err = verifyRootKeyMatchesLegacy(
		ctx, legacyStore, cfg.Name, rootKey, params.WatchOnly,
	)
	if err != nil {
		return nil, time.Time{}, errors.Join(err, legacyStore.Close())
	}

	info, err := legacyStore.Store.GetWallet(ctx, cfg.Name)
	if err != nil {
		return nil, time.Time{}, errors.Join(
			fmt.Errorf("read existing legacy wallet: %w", err),
			legacyStore.Close(),
		)
	}

	encryptedSeed, err := legacyEncryptedSeed(
		ctx, legacyStore, params, rootKey,
	)
	if err != nil {
		return nil, time.Time{}, errors.Join(err, legacyStore.Close())
	}

	err = legacyStore.Close()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf(
			"close legacy store: %w", err,
		)
	}

	return encryptedSeed, info.Birthday, nil
}

// verifyRootKeyMatchesLegacy guards the Create retry path against a root key
// that differs from the one the legacy wallet was originally created with.
// The legacy wallet persists the master HD public key derived from its root;
// a retry that supplies a different seed or extended key would otherwise
// derive the SQL runtime row's master pubkey and the default accounts from key
// material that does not match the legacy store, silently committing an
// inconsistent wallet. Compare the neutered retry root against the stored
// master public key and reject a mismatch.
//
// Wallets that persist no master public key (shell, and watch-only with no
// root key) have nothing to compare against, so they are accepted.
//
// watchOnly is the retry's requested watch-only flag, needed because a retry
// can request a watch-only downgrade even while supplying a matching root key.
func verifyRootKeyMatchesLegacy(ctx context.Context,
	legacyStore *kvdb.StoreHandle, name string,
	rootKey *hdkeychain.ExtendedKey, watchOnly bool) error {

	info, err := legacyStore.Store.GetWallet(ctx, name)
	if err != nil {
		return fmt.Errorf("read existing legacy wallet: %w", err)
	}

	if len(info.MasterPubKey) == 0 {
		return nil
	}

	// The existing legacy wallet persisted a master public key, so it is not
	// rootless/watch-only and holds spendable root material (only a private
	// root persists a master HD key in waddrmgr; a rootless shell persists
	// none). A retry that would have the SQL runtime row recorded watch-only
	// for this spendable wallet is a silent downgrade, so reject it. This
	// covers a retry with no root key (a rootless shell), one whose root is a
	// neutered xpub (it cannot sign), and one that asks for WatchOnly even with
	// a matching private root: each would persist a watch-only row with no
	// master private key for a wallet that can in fact sign (F2).
	if rootKey == nil || !rootKey.IsPrivate() || watchOnly {
		return fmt.Errorf("%w: retry cannot downgrade the existing "+
			"spendable wallet %q to watch-only; it requires a "+
			"matching private root key and WatchOnly=false",
			ErrWalletParams, name)
	}

	retryPub, err := rootKey.Neuter()
	if err != nil {
		return fmt.Errorf("neuter retry root key: %w", err)
	}

	if retryPub.String() != string(info.MasterPubKey) {
		return fmt.Errorf("%w: retry root key does not match the "+
			"existing wallet %q", ErrWalletParams, name)
	}

	return nil
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

	// Validate the configuration and parameters before touching the cache or
	// any store, so a malformed request fails on its own merits rather than
	// on a name collision or store error.
	err := cfg.validate()
	if err != nil {
		return nil, err
	}

	err = params.validate()
	if err != nil {
		return nil, err
	}

	// Claim the create-in-progress guard for this name before opening or
	// creating any store. If this manager already has the wallet loaded,
	// beginCreate rejects the over-create with ErrWalletExists immediately,
	// without touching the stores and without disturbing the live wallet
	// (task 285). If another Create for the same name is in flight, it waits
	// for that one to finish rather than opening the stores concurrently
	// (task 284). A name that merely has durable rows on disk but no live
	// cache entry is not rejected here, so the partial-create retry path
	// below still runs.
	release, err := m.beginCreate(cfg.Name)
	if err != nil {
		return nil, err
	}
	defer release()

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
	// persist the same blob (F2). legacyExisted reports whether a legacy
	// wallet was already present (a fresh create vs a retry over a partial
	// one); legacyBirthday carries that earlier wallet's original birthday.
	encryptedSeed, legacyExisted, legacyBirthday, err := createLegacyStore(
		context.Background(), cfg, params, rootKey,
	)
	if err != nil {
		return nil, fmt.Errorf("create legacy wallet: %w", err)
	}

	// Resolve the birthday to persist in the SQL runtime row. A fresh create
	// uses the requested birthday backed off by the safety margin; a retry
	// that reuses an existing legacy wallet must reuse that wallet's original
	// birthday instead. Callers commonly pass a fresh time.Now() per attempt
	// and the runtime birthday drives the initial SyncedTo tip, so persisting
	// a later retry birthday would make the wallet skip deposits made before
	// it.
	birthday := birthdayWithSafetyMargin(params.Birthday)
	if legacyExisted {
		birthday = legacyBirthday
	}

	runtimeExisted, err := createRuntimeWallet(
		context.Background(), cfg, params, rootKey, encryptedSeed, birthday,
	)
	if err != nil {
		return nil, err
	}

	// preCreated reports whether the wallet's durable rows were already
	// present before this call: for SQL backends both the legacy wallet and
	// the runtime row, for kvdb the legacy wallet alone (kvdb has no separate
	// row). It is not sufficient on its own to reject the create as existing:
	// an earlier attempt may have committed the rows but failed before its
	// post-load init (default-account seeding or initial-account import)
	// finished. discardUnstarted only cleans in-memory state, not the durable
	// rows, so such a partial create must be allowed to replay its init
	// rather than be wedged. We classify it as fully created only after the
	// replay below reports it had nothing left to do.
	isKVDB := cfg.DB.withDefaults().Backend == DBBackendKVDB
	preCreated := legacyExisted && (isKVDB || runtimeExisted)

	// Build the wallet without publishing it into the manager cache. The
	// create-in-progress guard guarantees no other caller holds this name, so
	// w is unconditionally owned by this create until it is published below.
	// Holding w back until its post-load initialization completes is what
	// keeps a concurrent Load, Start, or Unlock from observing a wallet whose
	// key vault seeding is still in flight (task 284).
	w, err := m.buildWallet(cfg)
	if err != nil {
		return nil, err
	}

	// Any failure past this point owns w with open stores but has not
	// published it, so it must tear w down before returning; otherwise its
	// stores stay open and its name would block a corrected retry. The guard
	// guarantees w is the freshly built create-owned wallet and never a live
	// instance a prior Load is handing out, so discarding it here is always
	// safe (task 285 ensures an already-cached wallet was rejected before any
	// store was opened).
	discardOnErr := func(err error) error {
		return errors.Join(err, w.discardUnstarted())
	}

	// Replay the post-load initialization. Both steps are idempotent and
	// report how many rows they actually created, so a fresh create completes
	// its init while a retry over a partial create finishes only the rows the
	// earlier attempt left undone. created accumulates that work across both
	// steps; a non-zero total means this call advanced an incomplete wallet.
	created := 0

	// Seed the default accounts for spendable SQL wallets (F1). The kvdb
	// backend already seeds account 0 per scope during legacy create; the
	// SQL create path does not, so a fresh SQL wallet would otherwise fail
	// to derive its first receiving address.
	spendable := !params.WatchOnly && rootKey != nil && rootKey.IsPrivate()
	if !isKVDB && spendable {
		seeded, err := seedDefaultAccounts(
			context.Background(), w, rootKey, params.PrivatePassphrase,
		)
		if err != nil {
			return nil, discardOnErr(
				fmt.Errorf("seed default accounts: %w", err),
			)
		}

		created += seeded
	}

	// If we are in shell mode and have initial accounts, we import them now.
	if params.Mode == ModeShell && len(params.InitialAccounts) > 0 {
		imported, err := w.importInitialAccounts(
			context.Background(), params.InitialAccounts,
		)
		if err != nil {
			return nil, discardOnErr(err)
		}

		created += imported
	}

	// Reject a create that targets an already fully created wallet. The rows
	// existed before this call and the idempotent init replay had nothing
	// left to create, so the wallet is complete end to end. Without this an
	// over-create would silently return the existing wallet instead of an
	// exists error. A wallet whose rows existed but whose init the replay
	// just completed (created > 0) falls through and is returned as the
	// now-finished wallet.
	if preCreated && created == 0 {
		return nil, discardOnErr(
			fmt.Errorf("%w: %q", ErrWalletExists, cfg.Name),
		)
	}

	// Post-load initialization succeeded, so the wallet is now ready for
	// normal runtime use. Publish it into the manager cache while the create
	// guard still prevents any other caller from racing in, making the
	// transition from create-only to live atomic (task 284). The deferred
	// release then lets waiting Load/Create callers observe the published
	// wallet.
	m.publish(cfg.Name, w)

	return w, nil
}

// importInitialAccounts imports a list of watch-only accounts into the wallet.
// This is typically used during wallet initialization in shell mode.
//
// It is replayable: a Create that failed after importing only some of the
// initial accounts is retried against the same wallet, so an account that an
// earlier attempt already imported is verified to match and then skipped
// rather than re-inserted (which would hit the unique (wallet, scope, name)
// constraint and wedge the retry). It returns the number of accounts it
// actually imported, so a zero count means every initial account was already
// present.
func (w *Wallet) importInitialAccounts(ctx context.Context,
	accounts []WatchOnlyAccount) (int, error) {

	created := 0
	for _, account := range accounts {
		exists, err := w.initialAccountAlreadyImported(ctx, account)
		if err != nil {
			return 0, fmt.Errorf("failed to import account %s: %w",
				account.Name, err)
		}

		if exists {
			continue
		}

		_, err = w.importAccountInternal(
			ctx, account.Name, account.XPub, account.MasterKeyFingerprint,
			account.AddrType, false,
		)
		if err != nil {
			return 0, fmt.Errorf("failed to import account %s: %w",
				account.Name, err)
		}

		created++
	}

	return created, nil
}

// initialAccountAlreadyImported reports whether the given initial account is
// already present from an earlier create attempt, verifying that the stored
// account matches the retry's key material. It resolves the scope from the
// xpub exactly as importAccountInternal does, so the lookup targets the scope
// the account was originally stored under (which need not equal the caller's
// declared account.Scope). A stored account whose public key differs from the
// retry's is rejected so a retry cannot silently rebind an existing name to
// new key material.
func (w *Wallet) initialAccountAlreadyImported(ctx context.Context,
	account WatchOnlyAccount) (bool, error) {

	err := validateExtendedPubKey(account.XPub, true, w.cfg.ChainParams)
	if err != nil {
		return false, err
	}

	addrType := account.AddrType

	scope, _, err := keyScopeFromPubKey(account.XPub, &addrType)
	if err != nil {
		return false, err
	}

	name := account.Name

	info, err := w.store.GetAccount(ctx, db.GetAccountQuery{
		WalletID:    w.id,
		Scope:       db.KeyScope(scope),
		Name:        &name,
		SkipBalance: true,
	})
	switch {
	case err == nil:

	// Not imported yet by an earlier attempt.
	case errors.Is(err, db.ErrAccountNotFound):
		return false, nil

	default:
		return false, fmt.Errorf("check imported account: %w", err)
	}

	if string(info.PublicKey) != account.XPub.String() {
		return false, fmt.Errorf("%w: initial account %q already "+
			"exists with different key material", ErrWalletParams,
			account.Name)
	}

	return true, nil
}

// Load loads an existing wallet from the provided configuration. It opens the
// database, initializes the wallet structure, and registers it with the manager
// for tracking.
func (m *Manager) Load(cfg Config) (*Wallet, error) {
	err := cfg.validate()
	if err != nil {
		return nil, err
	}

	// Wait out any in-progress Create for this name before checking the
	// cache, so Load never returns a wallet that Create is still
	// initializing. awaitCreate returns the cached wallet if one is now
	// published, or signals that we must build it ourselves (no live wallet
	// and no create in flight).
	existingW, ok := m.awaitCreate(cfg.Name)
	if ok {
		return existingW, nil
	}

	w, err := m.buildWallet(cfg)
	if err != nil {
		return nil, err
	}

	// Register the wallet. A wallet built here is immediately ready for
	// runtime use, so it is published as soon as it is constructed.
	m.publish(cfg.Name, w)

	return w, nil
}

// buildWallet opens the wallet's stores and constructs the in-memory Wallet
// without publishing it into the manager cache. Manager.Load publishes the
// result immediately, while Manager.Create holds it back until its post-load
// initialization completes, so the cache never exposes a wallet that is still
// being created (task 284).
func (m *Manager) buildWallet(cfg Config) (*Wallet, error) {
	// Apply the safe default for auto-lock duration if not specified.
	if cfg.AutoLockDuration == 0 {
		cfg.AutoLockDuration = defaultLockDuration
	}

	legacyStore, err := openLegacyStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("load legacy wallet: %w", err)
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

	return w, nil
}

// publish registers a fully constructed wallet in the manager cache under
// name, making it available to subsequent Load callers.
func (m *Manager) publish(name string, w *Wallet) {
	m.Lock()
	m.wallets[name] = w
	m.Unlock()
}

// beginCreate claims the create-in-progress guard for name before any store is
// opened or created. It coordinates a Create against both a wallet this
// manager already has loaded and a concurrent Create of the same name:
//
//   - if the name is already published in the cache, the wallet is a live
//     managed wallet and this is an over-create, so it returns ErrWalletExists
//     immediately without touching any store (task 285);
//   - if another Create for the same name holds the guard, it waits for that
//     create to finish and then re-checks rather than opening the stores
//     concurrently. The earlier create either published the wallet (now a
//     cache hit, so ErrWalletExists) or failed before publishing (the durable
//     rows may remain, so this call proceeds into the partial-create retry
//     path);
//   - otherwise it installs the guard channel and returns a release func the
//     caller must invoke once the create publishes or fails.
//
// The returned release func is idempotent.
func (m *Manager) beginCreate(name string) (func(), error) {
	m.Lock()
	defer m.Unlock()

	for {
		// A wallet already published under this name is a live managed
		// wallet, never a partial create to recover. Reject the
		// over-create before opening any store and without disturbing the
		// live instance (task 285).
		if _, ok := m.wallets[name]; ok {
			return nil, fmt.Errorf("%w: %q", ErrWalletExists, name)
		}

		// Another Create for this name is mid-flight. Wait for it to
		// finish, then loop to re-evaluate: it may have published the
		// wallet (cache hit above) or failed before publishing (proceed).
		ch, ok := m.creating[name]
		if !ok {
			break
		}

		m.Unlock()
		<-ch
		m.Lock()
	}

	ch := make(chan struct{})
	m.creating[name] = ch

	var once sync.Once

	release := func() {
		once.Do(func() {
			m.Lock()
			delete(m.creating, name)
			close(ch)
			m.Unlock()
		})
	}

	return release, nil
}

// awaitCreate blocks until any in-progress Create for name has finished, so a
// Load never races a Create's publish. It returns the cached wallet if one is
// present once no create is in flight; ok is false when the name is neither
// cached nor being created, signaling the caller to build the wallet itself.
func (m *Manager) awaitCreate(name string) (*Wallet, bool) {
	m.Lock()
	defer m.Unlock()

	for {
		if w, ok := m.wallets[name]; ok {
			return w, true
		}

		ch, ok := m.creating[name]
		if !ok {
			return nil, false
		}

		// A Create for this name is initializing the wallet. Wait for it
		// to publish or fail before re-checking the cache.
		m.Unlock()
		<-ch
		m.Lock()
	}
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
		return m.genRootKey(cfg, params)

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

// genRootKey resolves the master extended private key for a ModeGenSeed
// create. A fresh create mints a new random seed and derives its master key. A
// retry over a partial create instead reuses the master key the earlier
// attempt already persisted in the legacy store: ModeGenSeed minting a new
// random root on every call would derive key material that no longer matches
// the persisted legacy wallet, so verifyRootKeyMatchesLegacy would reject the
// retry and a partial ModeGenSeed wallet could never be completed (T2).
func (m *Manager) genRootKey(cfg Config,
	params CreateWalletParams) (*hdkeychain.ExtendedKey, error) {

	// Reuse the persisted master key if a prior attempt already created the
	// legacy wallet, so the retry derives the same material it committed.
	rootKey, err := m.recoverLegacyMasterRoot(cfg, params)
	if err != nil {
		return nil, err
	}

	if rootKey != nil {
		return rootKey, nil
	}

	// No legacy wallet exists yet, so this is a fresh create: generate a new
	// random seed using the recommended length and derive its master key.
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	return m.deriveFromSeed(cfg, seed)
}

// recoverLegacyMasterRoot returns the decrypted master HD private key of an
// already-created legacy wallet, or a nil key when none exists yet. It backs
// the ModeGenSeed retry path: a partial create leaves the spendable legacy
// wallet behind, and the retry must reuse its persisted master key rather than
// mint a fresh random one that would no longer match the stored wallet.
//
// A nil key with a nil error means no legacy wallet is present (a fresh
// create) or it is a rootless/watch-only wallet with no master private key to
// recover; the caller then falls back to generating a new random seed.
func (m *Manager) recoverLegacyMasterRoot(cfg Config,
	params CreateWalletParams) (*hdkeychain.ExtendedKey, error) {

	ctx := context.Background()

	// With no configured kvdb path there is no on-disk legacy wallet to
	// recover from, so this is a fresh create. The full Create path validates
	// the path before reaching here; this guard also lets genRootKey be
	// exercised in isolation without a backing store.
	if cfg.DB.KVDB.DBPath == "" {
		return nil, nil //nolint:nilnil
	}

	legacyStore, err := openLegacyStore(cfg)
	switch {
	// No legacy wallet exists yet: this is a fresh create, so there is
	// nothing to recover and the caller generates a new random seed.
	case errors.Is(err, walletdb.ErrDbDoesNotExist):
		return nil, nil //nolint:nilnil

	case err != nil:
		return nil, err
	}

	info, err := legacyStore.Store.GetWallet(ctx, cfg.Name)
	if err != nil {
		return nil, closeStoresAfterError(
			fmt.Errorf("read existing legacy wallet: %w", err),
			nil, legacyStore,
		)
	}

	// A rootless/watch-only legacy wallet persists no master private key, so
	// there is nothing to reuse; let the caller generate a fresh seed.
	if len(info.MasterPubKey) == 0 {
		err = legacyStore.Close()
		if err != nil {
			return nil, fmt.Errorf("close legacy store: %w", err)
		}

		return nil, nil //nolint:nilnil
	}

	rootKey, err := m.decryptLegacyMasterRoot(ctx, params, legacyStore)
	if err != nil {
		return nil, err
	}

	err = legacyStore.Close()
	if err != nil {
		return nil, fmt.Errorf("close legacy store: %w", err)
	}

	return rootKey, nil
}

// decryptLegacyMasterRoot unlocks the legacy manager vault and decrypts the
// stored encrypted master HD private key into an extended key. On any failure
// it closes legacyStore before returning the wrapped error, mirroring the
// cleanup the caller performs on success.
func (m *Manager) decryptLegacyMasterRoot(ctx context.Context,
	params CreateWalletParams, legacyStore *kvdb.StoreHandle) (
	*hdkeychain.ExtendedKey, error) {

	// Unlock the legacy manager so its vault can decrypt the encrypted master
	// HD private key. A negative timeout disables the vault's auto-lock; the
	// deferred Lock re-locks it before this store handle is closed.
	vault := kvdb.NewLegacyManagerVault(
		legacyStore.DB, legacyStore.AddrStore,
	)

	err := vault.Unlock(ctx, params.PrivatePassphrase, -1)
	if err != nil {
		return nil, closeStoresAfterError(
			fmt.Errorf("unlock legacy vault: %w", err), nil,
			legacyStore,
		)
	}
	defer vault.Lock()

	encrypted, err := legacyStore.Store.GetEncryptedHDSeed(ctx, 0)
	if err != nil {
		return nil, closeStoresAfterError(
			fmt.Errorf("read legacy master HD key: %w", err), nil,
			legacyStore,
		)
	}

	plaintext, err := vault.Decrypt(waddrmgr.CKTPrivate, encrypted)
	if err != nil {
		return nil, closeStoresAfterError(
			fmt.Errorf("decrypt legacy master HD key: %w", err), nil,
			legacyStore,
		)
	}

	rootKey, err := hdkeychain.NewKeyFromString(string(plaintext))
	zero.Bytes(plaintext)

	if err != nil {
		return nil, closeStoresAfterError(
			fmt.Errorf("parse legacy master HD key: %w", err), nil,
			legacyStore,
		)
	}

	return rootKey, nil
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
