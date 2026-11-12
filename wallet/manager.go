package wallet

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// ErrManagerStopped is returned when an operation targets an inactive
	// Manager, including before Start or after Stop has claimed shutdown.
	ErrManagerStopped = errors.New("manager stopped")

	// ErrWalletParams is returned when the creation parameters are invalid.
	ErrWalletParams = errors.New("invalid wallet params")

	// ErrWalletExists reports duplicate creation without changing the existing
	// Wallet. SQL names are unique; kvdb admits only one Wallet per database.
	ErrWalletExists = errors.New("wallet already exists")

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

// ImportAccountParams contains the input shared by ImportAccount and
// initial wallet imports.
type ImportAccountParams struct {
	// Scope declares purpose and coin type. The retained account number comes
	// from XPub's hardened child; callers with a separate expected number must
	// compare it before importing. Nil infers scope without retaining a number.
	Scope *waddrmgr.KeyScope

	// AddrSchema selects branch types and requires Scope. Custom scopes need
	// it; canonical scopes default to their existing schema.
	AddrSchema *waddrmgr.ScopeAddrSchema

	// XPub is the extended public key for the account.
	XPub *hdkeychain.ExtendedKey

	// MasterKeyFingerprint optionally identifies the caller's root key.
	// SQL preserves nil as absent and non-nil zero as a valid fingerprint.
	// Legacy kvdb defaults omitted metadata to its native scalar zero.
	MasterKeyFingerprint *MasterFingerprint

	// Name is the name of the account.
	Name string

	// AddrType is the address type of the account.
	AddrType waddrmgr.AddressType

	// NoChainSync excludes the account from automatic chain synchronization
	// on SQL backends. The default is false; kvdb ignores it and reports false.
	NoChainSync bool
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
	InitialAccounts []ImportAccountParams

	// RecoveryWindow overrides the Manager's discovery lookahead for this
	// Wallet before its first scan. Nil inherits the default; zero disables
	// recovery. The override is runtime policy and is not persisted.
	RecoveryWindow *uint32

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

// Manager owns the lifecycle and shared database of its Wallet set.
//
// The Manager enables a one-to-many relationship, allowing a single application
// to manage multiple distinct wallets (e.g., for different coins or different
// accounts) simultaneously.
type Manager struct {
	// RWMutex serializes Start, Stop and terminal failure cleanup.
	sync.RWMutex

	// started claims the one active lifetime. The Manager lock serializes
	// lifecycle changes, loop registration and terminal failure cleanup.
	started atomic.Bool

	// wallets holds fully initialized and started Wallets keyed by unique
	// name. The runtime loop serializes creation, delivery and rollback after
	// synchronous startup publishes the initial set.
	wallets map[string]*Wallet

	// backend owns the database and resolves the storage dependencies for
	// every wallet this Manager serves.
	backend managerBackend

	// config is the immutable shared policy retained at construction.
	config ManagerConfig

	// chainSyncer owns live routing for every Wallet served by this Manager.
	chainSyncer chainRouter

	// lifetimeCtx outlives construction and startup requests. Wallets keep
	// their own lifetimes; canceling this one releases shared event delivery.
	//nolint:containedctx // Manager owns and joins the shared reader lifetime.
	lifetimeCtx context.Context

	// cancel signals terminal reader shutdown before draining Wallet work.
	cancel context.CancelFunc

	// chainEvents borrows the already-started source's one native stream.
	chainEvents <-chan any

	// requestChan transfers creation to the same owner as native delivery.
	requestChan chan createWalletReq

	// wg joins the runtime before normal Stop disposes Wallets and storage.
	wg sync.WaitGroup
}

// NewManager opens the one database described by cfg and returns a Manager that
// owns it.
//
// Every Wallet shares that database and remains stopped until Start. Call
// Start once, then Stop after successful startup. Failed startup closes the
// owned resources; discard the Manager after failure or Stop. The legacy kvdb
// backend remains single-wallet until it is removed.
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

	// Runtime ownership is independent of the request that opened storage.
	lifetimeCtx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		wallets:     make(map[string]*Wallet),
		requestChan: make(chan createWalletReq),
		chainEvents: cfg.ChainSource.Notifications(),
		backend:     backend,
		config:      cfg,
		lifetimeCtx: lifetimeCtx,
		cancel:      cancel,
	}

	m.chainSyncer = newChainSyncer(m.config.ChainSource, &m.config.ChainParams)

	return m, nil
}

// startWallets assembles and starts durable Wallets in stable identifier order.
// It publishes only the complete set while the caller holds the write lock.
func (m *Manager) startWallets(ctx context.Context) ([]*Wallet, error) {
	data, err := m.backend.listWallets(ctx)
	if err != nil {
		return nil, err
	}

	wallets := make([]*Wallet, 0, len(data))
	for _, walletData := range data {
		cfg, err := m.config.walletConfig(walletData.name)
		if err != nil {
			return wallets, err
		}

		wallet := newManagedWallet(cfg, walletData, m.chainSyncer)
		wallets = append(wallets, wallet)

		err = wallet.start(ctx)
		if err != nil {
			return wallets, err
		}
	}

	for _, wallet := range wallets {
		m.wallets[wallet.cfg.Name] = wallet
	}

	return wallets, nil
}

// stopWallets stops all Wallets before closing storage. The slice holds Wallets
// from failed Start/Create calls that are not in m.wallets.
// The caller holds the lifecycle lock or has joined the loop; backend is open.
func (m *Manager) stopWallets(wallets []*Wallet) error {
	m.cancel()

	for _, wallet := range m.wallets {
		wallets = append(wallets, wallet)
	}

	// Keep shutdown errors in Wallet-ID order.
	sort.Slice(wallets, func(i, j int) bool {
		return wallets[i].id < wallets[j].id
	})

	// Private stop joins accepted requests and workers before their shared
	// storage closes. Preserve each Wallet's identity in any teardown error.
	errs := make([]error, 0, len(wallets))
	for _, wallet := range wallets {
		err := wallet.stop()
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"stop wallet %q: %w", wallet.cfg.Name, err,
			))
		}
	}

	// Wallet work and accepted rollback settle before storage closes. A nil
	// backend records released resources so a concurrent lifecycle caller
	// cannot dispose them twice after joining the owner.
	err := errors.Join(errs...)
	err = errors.Join(err, m.backend.close())
	m.backend = nil

	clear(m.wallets)
	m.started.Store(false)

	return err
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

// Start starts every durable Wallet in stable Wallet-ID order. Call it once
// on a newly constructed Manager. Another Start on a running Manager returns
// ErrStateForbidden; after Stop or failed startup it returns ErrManagerStopped.
// Startup failure closes owned resources before returning; create a fresh
// Manager rather than restarting this instance.
func (m *Manager) Start(ctx context.Context) ([]*Wallet, error) {
	m.Lock()
	defer m.Unlock()

	// Check shutdown before claiming the flag under the same lock as Stop,
	// so cancellation cannot race a later startup claim.
	if m.lifetimeCtx.Err() != nil {
		return nil, ErrManagerStopped
	}

	if !m.started.CompareAndSwap(false, true) {
		return nil, fmt.Errorf(
			"manager already started: %w", ErrStateForbidden,
		)
	}

	wallets, err := m.startWallets(ctx)
	if err != nil {
		// Failed candidates remain private until their workers and storage
		// close; the original startup caller owns the joined error.
		return nil, errors.Join(err, m.stopWallets(wallets))
	}

	// Register the loop before unlocking so Stop cannot miss a goroutine
	// that has not yet been scheduled.
	m.wg.Go(m.mainLoop)

	return wallets, nil
}

// Stop cancels the active lifetime, joins its owner, then drains Wallets and
// closes storage. Call it once after successful Start. An inactive or duplicate
// Stop returns ErrManagerStopped without joining another caller's cleanup.
func (m *Manager) Stop() error {
	if !m.started.Load() {
		return ErrManagerStopped
	}

	// Cancel blocked delivery before waiting for startup to finish. Clear
	// the flag under Start's lock to prevent a late startup claim.
	m.cancel()
	m.Lock()

	if !m.started.CompareAndSwap(true, false) {
		m.Unlock()
		return ErrManagerStopped
	}

	m.Unlock()

	// Failed work may need the lifecycle lock during cleanup, so release it
	// before joining. A failed operation may already have closed storage.
	m.wg.Wait()

	if m.backend == nil {
		return ErrManagerStopped
	}

	return m.stopWallets(nil)
}

// createWalletReq transfers creation and its result to the runtime owner.
type createWalletReq struct {
	params CreateWalletParams
	resp   chan createWalletResp
}

// createWalletResp returns a started Wallet or the settled creation error.
type createWalletResp struct {
	wallet *Wallet
	err    error
}

// mainLoop serializes creation, source delivery and shared rollback until the
// lifetime is canceled. Normal Stop joins the owner before disposing resources.
func (m *Manager) mainLoop() {
	for {
		select {
		case <-m.lifetimeCtx.Done():
			return

		case req := <-m.requestChan:
			err := m.handleCreateWalletReq(req)
			if err != nil {
				return
			}

		case event, ok := <-m.chainEvents:
			var err error
			if !ok {
				err = errors.New("chain notification source closed")
			} else {
				err = m.dispatchChainEvent(m.lifetimeCtx, event)
			}

			if err == nil {
				continue
			}

			// Serialize terminal cleanup with Start. A Stop that already
			// canceled owns disposal and its errors after joining this loop.
			m.Lock()

			if m.lifetimeCtx.Err() != nil {
				m.Unlock()
				return
			}

			err = errors.Join(err, m.stopWallets(nil))
			m.Unlock()

			log.Warnf("Chain notification processing stopped: %v", err)

			return
		}
	}
}

// chainRecipients snapshots the current Wallets owned by this loop turn.
func (m *Manager) chainRecipients() []*Wallet {
	wallets := make([]*Wallet, 0, len(m.wallets))
	for _, w := range m.wallets {
		wallets = append(wallets, w)
	}

	return wallets
}

// dispatchChainEvent admits source-ordered events to existing Wallet workers.
// Capacity-one mailboxes deliberately backpressure the sole reader; Wallet
// and reader cancellation both release delivery during terminal shutdown.
// Shared storage disconnects settle rollback before the next source event.
func (m *Manager) dispatchChainEvent(ctx context.Context, n any) error {
	// A disconnect changes the history that Wallet workers are writing.
	// Settle their earlier writes and rewind Store once before the next
	// source event; independent Wallet delivery cannot order that rewind.
	if disconnect, ok := n.(chain.BlockDisconnected); ok {
		return m.handleRollbackEvent(ctx, disconnect)
	}

	wallets := m.chainRecipients()

	events := m.chainSyncer.routeChainEvent(n, wallets)
	log.Debugf("Routing chain event %T to %d Wallets", n, len(events))

	for _, w := range wallets {
		event, relevant := events[w.id]
		if !relevant {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.lifetimeCtx.Done():
		case w.chainEventChan <- event:
		}
	}

	return nil
}

// prepareWalletsForRollback waits for earlier sync writes on every Wallet.
// The caller keeps the Wallet set fixed while each worker pauses for rollback.
func (m *Manager) prepareWalletsForRollback(ctx context.Context,
	resume <-chan struct{}) error {

	for _, wallet := range m.wallets {
		err := wallet.pauseForRollback(ctx, resume)
		if err != nil {
			return err
		}
	}

	return nil
}

// handleRollbackEvent settles published writers around one backend rollback.
// Success releases workers and lets the source reader dispatch its next event.
// A rollback error stops every Wallet before any worker can write again.
func (m *Manager) handleRollbackEvent(ctx context.Context,
	event chain.BlockDisconnected) error {

	// Preserve hash and time as well as height for storage that needs to
	// distinguish a stale disconnect from a replacement at the same height.
	block, err := storeBlockFromBlockMeta(wtxmgr.BlockMeta(event))
	if err != nil {
		return fmt.Errorf("disconnect block: %w", err)
	}

	// Manager alone signals rollback completion. Terminal cleanup stops
	// workers first, so a failed rewind cannot resume old writes.
	rollbackDone := make(chan struct{})

	err = m.prepareWalletsForRollback(ctx, rollbackDone)
	if err != nil {
		// Only Stop's lifetime cancellation interrupts preparation. Leave
		// completion held and cleanup to that waiting caller so it receives
		// close errors; prepared workers exit through Wallet cancellation.
		return fmt.Errorf("wait for rollback writers: %w", err)
	}

	// Accepted persistence settles even if its caller or Stop cancels.
	// The owner keeps Store open until this one rollback completes.
	err = m.backend.rollbackToBlock(context.WithoutCancel(ctx), *block)
	if err != nil {
		err = fmt.Errorf("rollback chain: %w", err)
		// Leave paused workers to the owner, which drains them on failure
		// or handles the accepted Stop before another operation can run.
		log.Errorf("Unable to roll back chain to height %d: %v",
			block.Height, err)

		return err
	}

	close(rollbackDone)

	return nil
}

// validateManagedWalletName rejects an absent durable identity before cache,
// key-derivation, or Store work can obscure the caller error.
func validateManagedWalletName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: Name", ErrMissingParam)
	}

	return nil
}

// Create persists, starts and publishes one Wallet while Manager is active.
// An inactive Manager returns ErrManagerStopped before validating the request.
// Duplicates return ErrWalletExists without changing the existing Wallet.
//
// TODO(yy): Add caller context with atomic creation in the context follow-up.
func (m *Manager) Create(params CreateWalletParams) (*Wallet, error) {
	if !m.started.Load() {
		return nil, ErrManagerStopped
	}

	// Cancellation releases callers waiting to send. Once transferred,
	// creation settles its result before the owner can close storage.
	req := createWalletReq{
		params: params,
		resp:   make(chan createWalletResp, 1),
	}
	select {
	case m.requestChan <- req:
	case <-m.lifetimeCtx.Done():
		return nil, ErrManagerStopped
	}

	result := <-req.resp

	return result.wallet, result.err
}

// handleCreateWalletReq replies on every path. It returns an error only after
// terminal candidate cleanup, so the owner exits without accepting more work.
func (m *Manager) handleCreateWalletReq(req createWalletReq) error {
	params := req.params
	if params.Name != "" && m.wallets[params.Name] != nil {
		req.resp <- createWalletResp{err: fmt.Errorf(
			"wallet %q: %w", params.Name, ErrWalletExists,
		)}

		return nil
	}

	// Accepted preparation failures return through the response. Only a
	// known candidate's initialization failure terminates the owner below.
	ctx := context.WithoutCancel(m.lifetimeCtx)

	wallet, err := m.createWallet(ctx, params)
	if err == nil {
		err = wallet.importInitialAccounts(ctx, params.InitialAccounts)
		if err == nil {
			err = wallet.start(ctx)
		}

		if err != nil {
			// Serialize terminal disposal with Start's lock. A waiting
			// Stop observes this failed operation's completed cleanup.
			m.Lock()
			err = errors.Join(err, m.stopWallets([]*Wallet{wallet}))
			m.Unlock()

			req.resp <- createWalletResp{err: err}

			return err
		}

		m.wallets[wallet.cfg.Name] = wallet
	}

	// Keep duplicate classification at creation's response boundary; the
	// preparation helper retains its native backend error and root cleanup.
	if errors.Is(err, db.ErrWalletExists) {
		err = fmt.Errorf("%w: %w", ErrWalletExists, err)
	}

	req.resp <- createWalletResp{wallet: wallet, err: err}

	return nil
}

// createWallet validates and prepares a durable candidate. Its caller owns
// initialization and cleanup; preparation errors never expose a partial Wallet.
func (m *Manager) createWallet(ctx context.Context,
	params CreateWalletParams) (*Wallet, error) {

	// Validate identity before key derivation or Store work can produce a less
	// useful error or side effect.
	err := validateManagedWalletName(params.Name)
	if err != nil {
		return nil, err
	}

	err = params.validate(&m.config.ChainParams)
	if err != nil {
		return nil, err
	}

	// Reject bad import inputs before persistence can turn their errors into
	// a shutdown of the Manager and its running Wallets.
	err = m.validateInitialAccounts(params.InitialAccounts)
	if err != nil {
		return nil, err
	}

	rootKey, err := m.deriveRootKey(params)
	if err != nil {
		return nil, err
	}

	// Validation makes shell roots nil and imported XPrvs the same pointer as
	// params.RootKey. Only derived roots differ, so destroy those on every
	// preparation exit while preserving the caller's borrowed key.
	if rootKey != params.RootKey {
		defer rootKey.Zero()
	}

	// The owner keeps assembly, Store mutation and publication together so
	// no partial Wallet becomes observable between runtime operations.
	walletCfg, err := m.config.walletConfig(params.Name)
	if err != nil {
		return nil, err
	}

	// A creation override belongs to this snapshot, leaving siblings and
	// subsequent creations on the Manager default.
	if params.RecoveryWindow != nil {
		walletCfg.RecoveryWindow = *params.RecoveryWindow
	}

	data, err := m.backend.create(ctx, params, rootKey)
	if err != nil {
		return nil, err
	}

	return newManagedWallet(walletCfg, data, m.chainSyncer), nil
}

// validateInitialAccounts checks resolved scope and script ownership before
// backend access, sharing import validation and the Store's collision rules.
func (m *Manager) validateInitialAccounts(
	accounts []ImportAccountParams) error {

	// These request-local indexes enforce occupied account slots and script
	// ownership while retaining each account's independently resolved schema.
	numbers := make(map[[3]uint32]struct{})
	identities := make(map[string][]db.ScopeAddrSchema)

	for _, account := range accounts {
		params, err := importAccountParams(
			account, 0, &m.config.ChainParams, false,
		)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWalletParams, err)
		}

		// Declared imports retain a number; reject an occupied scope/number
		// before the Store's unique constraint could leave partial genesis.
		if params.AccountNumber != nil {
			slot := [3]uint32{
				params.Scope.Purpose, params.Scope.Coin,
				*params.AccountNumber,
			}
			if _, exists := numbers[slot]; exists {
				return fmt.Errorf("%w: %w", ErrWalletParams,
					ErrAccountAlreadyExists)
			}

			numbers[slot] = struct{}{}
		}

		// Normalize once: origin fields and serialization versions cannot
		// distinguish scripts derived from the same key and chain code.
		payload := db.AccountXPubPayload(params.PublicKey)
		if payload == nil {
			return fmt.Errorf("%w: %w", ErrWalletParams,
				ErrInvalidAccountKey)
		}

		identity := string(payload)

		overlaps := slices.ContainsFunc(identities[identity],
			func(previous db.ScopeAddrSchema) bool {
				return db.AccountSchemasOverlap(
					previous, *params.AddrSchema,
				)
			},
		)
		if overlaps {
			return fmt.Errorf("%w: %w", ErrWalletParams,
				ErrAccountIdentityCollision)
		}

		// Retain only validated identities for the following peer checks.
		identities[identity] = append(
			identities[identity], *params.AddrSchema,
		)
	}

	return nil
}

// importInitialAccounts imports a list of watch-only accounts into the wallet.
// This is typically used during wallet initialization in shell mode.
func (w *Wallet) importInitialAccounts(ctx context.Context,
	accounts []ImportAccountParams) error {

	for _, account := range accounts {
		_, err := w.importAccountInternal(ctx, account, false)
		if err != nil {
			return fmt.Errorf("failed to import account %s: %w",
				account.Name, err)
		}
	}

	return nil
}

// validate checks the creation mode and imported-root identity against the
// Manager network before key preparation or dependency access.
//
// We skip cyclop because this method performs exhaustive validation of
// mutually exclusive fields across all creation modes.
//
//nolint:cyclop
func (p *CreateWalletParams) validate(chainParams *chaincfg.Params) error {
	// Refuse invalid lookahead before root derivation or Store mutation can
	// leave an identity that cannot complete startup.
	if p.RecoveryWindow != nil && *p.RecoveryWindow > MaxRecoveryWindow {
		return fmt.Errorf("%w: recovery window exceeds %d",
			ErrWalletParams, MaxRecoveryWindow)
	}

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
		// Ordered cases preserve the nil guard and first-error policy
		// without nesting another validation tree inside the mode switch.
		switch {
		case p.RootKey == nil:
			return fmt.Errorf("%w: root key is required for "+
				"ModeImportExtKey", ErrWalletParams)

		case len(p.Seed) != 0:
			return fmt.Errorf("%w: seed should not be set for "+
				"ModeImportExtKey", ErrWalletParams)

		case !p.RootKey.IsPrivate():
			return fmt.Errorf("%w: XPub-root wallet creation is "+
				"unsupported; use ModeShell", ErrWalletParams)

		// Descendant metadata must not become the wallet's master
		// identity, even when the key contains private material.
		case p.RootKey.Depth() != 0,
			p.RootKey.ParentFingerprint() != 0,
			p.RootKey.ChildIndex() != 0:

			return fmt.Errorf("%w: root key has non-root metadata",
				ErrWalletParams)

		case p.WatchOnly:
			return fmt.Errorf("%w: ModeImportExtKey must be spendable",
				ErrWalletParams)

		// The earlier cases establish a valid private root before its
		// network is compared with the Manager's selected chain.
		case !p.RootKey.IsForNet(chainParams):
			return fmt.Errorf("%w: root key network mismatch",
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
func validateInitialAccountKeys(accounts []ImportAccountParams) error {
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

// deriveRootKey resolves the master extended key after creation parameters have
// passed validation. The caller owns derived roots; imported XPrvs remain
// borrowed.
func (m *Manager) deriveRootKey(
	params CreateWalletParams) (*hdkeychain.ExtendedKey, error) {

	if params.Mode == ModeGenSeed {
		return m.genRootKey(hdkeychain.GenerateSeed)
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

// genRootKey derives a master from an owned generated seed. generateSeed is
// hdkeychain.GenerateSeed in production and exposes the original seed buffer
// to cleanup tests. The caller owns the returned master.
func (m *Manager) genRootKey(
	generateSeed func(uint8) ([]byte, error)) (*hdkeychain.ExtendedKey, error) {

	seed, err := generateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	// NewMaster does not retain the seed, so its lifetime ends when derivation
	// finishes, including error or panic unwinding.
	defer clear(seed)

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
