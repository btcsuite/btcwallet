package wallet

import (
	"context"
	"errors"
	"fmt"
	"maps"
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
	// ErrManagerStopped is returned when an operation targets a Manager that
	// is inactive after its owned resources have closed.
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
	sync.RWMutex

	// started rejects another Start while starting, running or stopping.
	// The Manager lock serializes resource changes and terminal admission.
	started atomic.Bool

	// wallets holds fully initialized and started Wallets keyed by unique
	// name. The Manager lock serializes Store access, runtime assembly, and
	// publication after initial-account import and private startup complete.
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

	// requestChan transfers public operations to the runtime owner.
	requestChan chan any

	// wg joins routing after releasing the lock needed by recipient snapshots.
	wg sync.WaitGroup
}

// NewManager opens the one database described by cfg and returns a Manager that
// owns it.
//
// Every Wallet the Manager serves shares that database. NewManager does not
// start durable Wallets; callers use Start and eventually Stop. The legacy kvdb
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
		backend:     backend,
		config:      cfg,
		lifetimeCtx: lifetimeCtx,
		cancel:      cancel,
		requestChan: make(chan any),
	}

	m.chainSyncer = newChainSyncer(
		m.config.ChainSource, &m.config.ChainParams, m.requestChan,
	)

	//nolint:contextcheck // Runtime work outlives the construction context.
	go m.mainLoop()

	return m, nil
}

// startManagerReq retains the caller's startup context until the loop settles
// the operation, including any failed candidate cleanup.
type startManagerReq struct {
	reqCtx

	resp chan startManagerResp
}

// startManagerResp returns only a complete published set or a startup error.
type startManagerResp struct {
	wallets []*Wallet
	err     error
}

// createWalletReq transfers creation to the same owner as live delivery.
type createWalletReq struct {
	params CreateWalletParams
	resp   chan createWalletResp
}

// createWalletResp keeps the exact published pointer beside its result.
type createWalletResp struct {
	wallet *Wallet
	err    error
	retry  <-chan struct{}
}

// managerInfoReq reads membership without exposing the loop's mutable map.
type managerInfoReq struct {
	resp chan string
}

// chainEventReq bounds intake until the owner finishes one source event.
type chainEventReq struct {
	event any
	err   error
	done  chan struct{}
}

// startManagerResultReq transfers startup candidates back to their owner.
type startManagerResultReq struct {
	req     startManagerReq
	wallets []*Wallet
	err     error
}

// createWalletResultReq transfers a prepared candidate and its startup outcome.
type createWalletResultReq struct {
	req    createWalletReq
	wallet *Wallet
	err    error
}

// managerRuntime holds one loop's state for its handlers, without shared locks.
type managerRuntime struct {
	manager   *Manager
	operation chan struct{}
	pending   *chainEventReq
	wallets   []*Wallet
	events    map[uint32]chainEvent
	cursor    int
}

// mainLoop drains accepted I/O after legacy Stop cancels its lifetime.
func (m *Manager) mainLoop() {
	runtime := managerRuntime{manager: m}
	cancelled := m.lifetimeCtx.Done()
	for cancelled != nil || runtime.operation != nil {
		delivery, event := runtime.nextDelivery(m.lifetimeCtx)
		select {
		case delivery <- event:
			runtime.cursor++

		case req := <-m.requestChan:
			runtime.handleReq(m.lifetimeCtx, req)

		case <-cancelled:
			// Observe cancellation once while accepted results settle.
			cancelled = nil
		}
	}
}

// handleReq dispatches requests on the one runtime owner.
func (r *managerRuntime) handleReq(ctx context.Context, raw any) {
	switch req := raw.(type) {
	case startManagerReq:
		r.start(ctx, req)

	case startManagerResultReq:
		r.completeStart(req)

	case createWalletResultReq:
		r.completeCreate(req)

	case createWalletReq:
		r.create(ctx, req)

	case managerInfoReq:
		m := r.manager
		if r.operation == nil {
			m.RLock()
		}
		names := slices.Sorted(maps.Keys(m.wallets))
		if r.operation == nil {
			m.RUnlock()
		}
		req.resp <- fmt.Sprintf("active_wallets=%v", names)
	case chainEventReq:
		r.pending = &req
	}
}

// start captures startup inputs while retaining legacy Stop exclusion.
func (r *managerRuntime) start(_ context.Context, req startManagerReq) {
	m := r.manager
	var err error
	switch {
	case m.lifetimeCtx.Err() != nil:
		err = ErrManagerStopped
	case req.ctx.Err() != nil:
		err = req.ctx.Err()
	case m.started.Swap(true):
		err = ErrStateForbidden
	default:
		m.Lock()
		if m.lifetimeCtx.Err() != nil {
			m.started.Store(false)
			m.Unlock()
			req.resp <- startManagerResp{err: ErrManagerStopped}
			return
		}
		r.operation = make(chan struct{})
		cfg, backend, router := m.config, m.backend, m.chainSyncer
		requests, wg := m.requestChan, &m.wg
		wg.Add(1)
		go m.startChainSyncer()
		wg.Go(func() {
			candidates, err := startWallets(req.ctx, cfg, backend, router)
			requests <- startManagerResultReq{req, candidates, err}
		})
		return
	}
	req.resp <- startManagerResp{err: err}
}

// create reuses admission checks before launching the one accepted operation.
func (r *managerRuntime) create(ctx context.Context, req createWalletReq) {
	if r.operation != nil {
		req.resp <- createWalletResp{retry: r.operation}
		return
	}

	// Finish preceding fanout before a native Create registration.
	if r.pending != nil {
		req.resp <- createWalletResp{retry: r.pending.done}
		return
	}

	m := r.manager
	m.Lock()
	err := m.checkCreate()
	if err != nil {
		m.Unlock()
		req.resp <- createWalletResp{err: err}
		return
	}
	if req.params.Name != "" && m.wallets[req.params.Name] != nil {
		m.Unlock()
		req.resp <- createWalletResp{err: ErrWalletExists}
		return
	}

	r.operation = make(chan struct{})
	cfg, backend, router := m.config, m.backend, m.chainSyncer
	requests, wg := m.requestChan, &m.wg
	ctx = context.WithoutCancel(ctx)
	wg.Go(func() {
		w, err := createWallet(ctx, req.params, cfg, backend, router)
		if err == nil {
			err = w.importInitialAccounts(ctx, req.params.InitialAccounts)
			if err == nil {
				err = w.start(ctx, backend.prepareLiveWatches)
			}
		}
		requests <- createWalletResultReq{req, w, err}
	})
}

// completeStart settles candidates before releasing inherited Stop exclusion.
func (r *managerRuntime) completeStart(req startManagerResultReq) {
	m := r.manager
	defer m.Unlock()
	close(r.operation)
	r.operation = nil
	if req.err != nil {
		req.err = errors.Join(req.err, m.stopWallets(req.wallets))
		req.req.resp <- startManagerResp{err: req.err}
		return
	}
	for _, w := range req.wallets {
		m.wallets[w.cfg.Name] = w
	}
	req.req.resp <- startManagerResp{wallets: req.wallets}
}

// completeCreate publishes only a started candidate while Store remains open.
func (r *managerRuntime) completeCreate(req createWalletResultReq) {
	m := r.manager
	defer m.Unlock()
	close(r.operation)
	r.operation = nil
	if req.err != nil && req.wallet != nil {
		req.err = errors.Join(req.err, m.stopWallets([]*Wallet{req.wallet}))
		req.wallet = nil
	} else if req.err == nil {
		m.wallets[req.wallet.cfg.Name] = req.wallet
	} else if errors.Is(req.err, db.ErrWalletExists) {
		req.err = fmt.Errorf("%w: %w", ErrWalletExists, req.err)
	}
	req.req.resp <- createWalletResp{wallet: req.wallet, err: req.err}
}

// prepareEvent reuses rollback ordering and the inherited recipient snapshot.
func (r *managerRuntime) prepareEvent(ctx context.Context) {
	if r.pending == nil {
		return
	}
	if event, ok := r.pending.event.(chain.BlockDisconnected); ok {
		_ = r.manager.handleRollbackEvent(ctx, event)
		close(r.pending.done)
		r.pending = nil
		return
	}
	r.wallets = r.manager.chainRecipients()
	r.events = r.manager.chainSyncer.routeChainEvent(r.pending.event, r.wallets)
}

// nextDelivery leaves a blocked mailbox selectable beside owner requests.
func (r *managerRuntime) nextDelivery(ctx context.Context) (
	chan chainEvent, chainEvent) {

	if r.manager.lifetimeCtx.Err() != nil || r.operation != nil {
		return nil, chainEvent{}
	}

	if r.events == nil {
		r.prepareEvent(ctx)
	}

	for r.pending != nil && r.cursor < len(r.wallets) {
		w := r.wallets[r.cursor]
		event, relevant := r.events[w.id]

		if relevant && w.lifetimeCtx.Err() == nil {
			return w.chainEventChan, event
		}

		r.cursor++
	}

	if r.pending != nil {
		close(r.pending.done)
		r.pending, r.events, r.wallets, r.cursor = nil, nil, nil, 0
	}

	return nil, chainEvent{}
}

// sendReq transfers ownership only while the Manager and caller are live.
// Accepted Start/Create callers wait for their buffered result to settle.
func (m *Manager) sendReq(ctx context.Context, req any) error {
	select {
	case m.requestChan <- req:
		return nil
	case <-m.lifetimeCtx.Done():
		return ErrManagerStopped
	case <-ctx.Done():
		return ctx.Err()
	}
}

// startWallets assembles and starts durable Wallets in stable identifier order.
// The runtime loop publishes only the complete set after startup succeeds.
func startWallets(ctx context.Context, cfg ManagerConfig,
	backend managerBackend, router chainRouter) ([]*Wallet, error) {

	data, err := backend.listWallets(ctx)
	if err != nil {
		return nil, err
	}

	wallets := make([]*Wallet, 0, len(data))
	for _, walletData := range data {
		walletCfg, err := cfg.walletConfig(walletData.name)
		if err != nil {
			return wallets, err
		}

		wallet := newManagedWallet(walletCfg, walletData, router)
		wallets = append(wallets, wallet)

		err = wallet.start(ctx, backend.prepareLiveWatches)
		if err != nil {
			return wallets, err
		}
	}

	// Cancellation must settle before publication so failed startup leaves
	// only local candidates for the caller to drain.
	err = ctx.Err()
	if err != nil {
		return wallets, err
	}

	return wallets, nil
}

// stopWallets stops all Wallets before closing storage. The slice holds Wallets
// from failed Start/Create calls that are not in m.wallets.
// The caller holds the write lock and must have a non-nil backend.
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

	// Clear runtime ownership after shutdown has settled. The nil backend
	// keeps later Start calls from reopening a terminal Manager. Wallet work
	// is drained. Reader rollback holds this same lock through Store use;
	// the reader itself joins only after its caller unlocks.
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

// Start starts every durable Wallet and returns the complete active set in
// stable Wallet-ID order. Another Start while starting, running, or stopping
// returns ErrStateForbidden. Stop and accepted startup failure are terminal;
// construct a fresh Manager to reopen the database.
// Cancellation or failure cleans up all candidates before returning an error.
func (m *Manager) Start(ctx context.Context) ([]*Wallet, error) {
	// Preserve immediate rejection while another operation holds the loop.
	if m.started.Load() {
		return nil, fmt.Errorf(
			"manager already started: %w", ErrStateForbidden,
		)
	}

	req := startManagerReq{
		reqCtx: reqCtx{ctx: ctx},
		resp:   make(chan startManagerResp, 1),
	}

	err := m.sendReq(ctx, req)
	if err != nil {
		return nil, err
	}

	// Startup cancellation must unwind candidates before returning; the
	// caller cannot abandon accepted cleanup as ordinary Wallet calls can.
	result := <-req.resp

	return result.wallets, result.err
}

// Stop terminally drains every Wallet and closes the owned database.
// It waits for startup, accepted creation, and any other Stop to finish.
// After shutdown, Stop is a no-op.
func (m *Manager) Stop() error {
	// Release a reader blocked on a full mailbox before waiting for admission.
	m.cancel()

	m.Lock()

	// LIFO releases membership before joining, including repeated Stop after
	// storage closed. The reader can be parked on its recipient snapshot.
	defer m.wg.Wait()
	defer m.Unlock()

	// Preserve terminal admission on repeated no-op shutdown calls.
	if m.backend == nil {
		return nil
	}

	// Construction already owns an open backend, so shutdown must reject
	// Start even when no startup attempt has claimed the guard yet.
	m.started.Store(true)

	return m.stopWallets(nil)
}

// startChainSyncer reads the shared stream until shutdown or source loss.
// Its caller enrolls it before launch so terminal shutdown joins the reader.
func (m *Manager) startChainSyncer() {
	err := m.chainSyncer.run(m.lifetimeCtx, m.dispatchChainEvent)

	// No reader work follows Done. Automatic teardown can therefore
	// reuse Stop without waiting for this goroutine to join itself.
	m.wg.Done()

	if err != nil && m.lifetimeCtx.Err() == nil {
		log.Warnf("Chain notification reader stopped: %v", err)

		err := m.Stop()
		if err != nil {
			log.Errorf("Unable to stop manager: %v", err)
		}
	}
}

// chainRecipients fixes active membership without holding the Manager lock
// across matching or potentially blocked delivery to a Wallet mailbox.
func (m *Manager) chainRecipients() []*Wallet {
	m.RLock()
	defer m.RUnlock()

	wallets := make([]*Wallet, 0, len(m.wallets))
	for _, w := range m.wallets {
		wallets = append(wallets, w)
	}

	return wallets
}

// dispatchChainEvent retains source order until the owner completes delivery.
func (m *Manager) dispatchChainEvent(ctx context.Context, event any) error {
	req := chainEventReq{event: event, done: make(chan struct{})}

	err := m.sendReq(ctx, req)
	if err != nil {
		return err
	}

	select {
	case <-req.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-m.lifetimeCtx.Done():
		return ErrManagerStopped
	}
}

// prepareWalletsForRollback waits for each worker to finish earlier chain
// writes. The caller holds the Manager lock, keeping membership fixed;
// Manager cancellation interrupts either request delivery or readiness wait.
func (m *Manager) prepareWalletsForRollback(
	rollbackDone <-chan struct{}) error {

	for _, wallet := range m.wallets {
		req := prepareRollbackReq{
			readyForRollback: make(chan struct{}),
			rollbackDone:     rollbackDone,
		}

		select {
		case wallet.chainEventChan <- chainEvent{notification: req}:
		case <-m.lifetimeCtx.Done():
			return ErrManagerStopped
		}

		select {
		case <-req.readyForRollback:
		case <-m.lifetimeCtx.Done():
			return ErrManagerStopped
		}
	}

	return nil
}

// handleRollbackEvent settles published writers around one backend rollback.
// Success releases workers and lets the source reader dispatch its next event.
// A rollback error stops every Wallet before any worker can write again.
func (m *Manager) handleRollbackEvent(ctx context.Context,
	event chain.BlockDisconnected) error {

	// Keep the Wallet set fixed, exclude Create's new writers, and prevent
	// Stop from closing Store until rollback or terminal cleanup finishes.
	m.Lock()
	defer m.Unlock()

	// Stop may have cleared backend before this callback acquired the lock.
	// Reject that stopped Manager before using its storage.
	err := m.checkCreate()
	if err != nil {
		return err
	}

	// Preserve hash and time as well as height for storage that needs to
	// distinguish a stale disconnect from a replacement at the same height.
	block, err := storeBlockFromBlockMeta(wtxmgr.BlockMeta(event))
	if err != nil {
		return fmt.Errorf("disconnect block: %w", err)
	}

	err = ctx.Err()
	if err != nil {
		return err
	}

	// Manager alone signals rollback completion. Terminal cleanup stops
	// workers first, so a failed rewind cannot resume old writes.
	rollbackDone := make(chan struct{})

	err = m.prepareWalletsForRollback(rollbackDone)
	if err != nil {
		// Only Stop's lifetime cancellation interrupts preparation. Leave
		// completion held and cleanup to that waiting caller so it receives
		// close errors; prepared workers exit through Wallet cancellation.
		return fmt.Errorf("wait for rollback writers: %w", err)
	}

	// Accepted persistence settles even if its caller or Stop cancels.
	// The Manager lock keeps Store open until this one rollback completes.
	err = m.backend.rollbackToBlock(context.WithoutCancel(ctx), *block)
	if err != nil {
		err = fmt.Errorf("rollback chain: %w", err)
		if m.lifetimeCtx.Err() == nil {
			// No Stop owns cleanup yet. Cancel and join writers on this
			// reader without self-joining, then release its completion.
			err = errors.Join(err, m.stopWallets(nil))

			close(rollbackDone)
		}

		// If Stop already canceled, it owns cleanup and its close error.
		// Otherwise cleanup canceled the reader's outer report, so include
		// the joined close failure in this single persistence error log.
		log.Errorf("Unable to roll back chain to height %d: %v",
			block.Height, err)

		return err
	}

	close(rollbackDone)

	return nil
}

// String returns a summary of the active wallets managed by the Manager.
func (m *Manager) String() string {
	req := managerInfoReq{resp: make(chan string, 1)}

	err := m.sendReq(context.Background(), req)
	if err != nil {
		return "active_wallets=[]"
	}

	return <-req.resp
}

// validateManagedWalletName rejects an absent durable identity before cache,
// key-derivation, or Store work can obscure the caller error.
func validateManagedWalletName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: Name", ErrMissingParam)
	}

	return nil
}

// Create persists, starts, and publishes one Wallet while Manager is running.
// Duplicate creation returns no Wallet and ErrWalletExists while preserving
// the existing Wallet and its credentials, including all aliases on kvdb.
//
// TODO(yy): Add a context parameter once wallet creation uses a single atomic
// database transaction.
func (m *Manager) Create(params CreateWalletParams) (*Wallet, error) {
	for {
		req := createWalletReq{params, make(chan createWalletResp, 1)}

		err := m.sendReq(context.Background(), req)
		if err != nil {
			return nil, err
		}

		result := <-req.resp
		if result.retry == nil {
			return result.wallet, result.err
		}
		// Busy callers retain their own request instead of an owner queue.
		select {
		case <-result.retry:
		case <-m.lifetimeCtx.Done():
			return nil, ErrManagerStopped
		}
	}
}

// checkCreate rejects terminal admission after Stop cancels the reader, even
// before Stop obtains admission and closes storage. The caller holds the lock.
func (m *Manager) checkCreate() error {
	if m.lifetimeCtx.Err() != nil {
		return ErrManagerStopped
	}

	if !m.started.Load() {
		return ErrStateForbidden
	}

	return nil
}

// createWallet prepares an unpublished candidate for owner-controlled startup.
func createWallet(ctx context.Context, params CreateWalletParams,
	cfg ManagerConfig, backend managerBackend,
	router chainRouter) (*Wallet, error) {

	// Validate identity before key derivation or Store work can produce a less
	// useful error or side effect.
	err := validateManagedWalletName(params.Name)
	if err != nil {
		return nil, err
	}

	err = params.validate(&cfg.ChainParams)
	if err != nil {
		return nil, err
	}

	// Reject bad import inputs before persistence can turn their errors into
	// a shutdown of the Manager and its running Wallets.
	err = cfg.validateInitialAccounts(params.InitialAccounts)
	if err != nil {
		return nil, err
	}

	rootKey, err := cfg.deriveRootKey(params)
	if err != nil {
		return nil, err
	}

	// Validation makes shell roots nil and imported XPrvs the same pointer as
	// params.RootKey. Only derived roots differ, so destroy those on every
	// preparation exit while preserving the caller's borrowed key.
	if rootKey != params.RootKey {
		defer rootKey.Zero()
	}

	// Loop ownership keeps runtime assembly, Store mutation and publication
	// ordered so no partial Wallet becomes observable.
	walletCfg, err := cfg.walletConfig(params.Name)
	if err != nil {
		return nil, err
	}

	data, err := backend.create(ctx, params, rootKey)
	if err != nil {
		return nil, err
	}

	return newManagedWallet(walletCfg, data, router), nil
}

// validateInitialAccounts checks resolved scope and script ownership before
// backend access, sharing import validation and the Store's collision rules.
func (cfg ManagerConfig) validateInitialAccounts(
	accounts []ImportAccountParams) error {

	// These request-local indexes enforce occupied account slots and script
	// ownership while retaining each account's independently resolved schema.
	numbers := make(map[[3]uint32]struct{})
	identities := make(map[string][]db.ScopeAddrSchema)

	for _, account := range accounts {
		params, err := importAccountParams(
			account, 0, &cfg.ChainParams, false,
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
func (cfg ManagerConfig) deriveRootKey(
	params CreateWalletParams) (*hdkeychain.ExtendedKey, error) {

	if params.Mode == ModeGenSeed {
		return cfg.genRootKey(hdkeychain.GenerateSeed)
	}

	if params.Mode == ModeImportSeed {
		return cfg.deriveFromSeed(params.Seed)
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
func (cfg ManagerConfig) genRootKey(
	generateSeed func(uint8) ([]byte, error)) (*hdkeychain.ExtendedKey, error) {

	seed, err := generateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	// NewMaster does not retain the seed, so its lifetime ends when derivation
	// finishes, including error or panic unwinding.
	defer clear(seed)

	return cfg.deriveFromSeed(seed)
}

// deriveFromSeed derives the master extended private key from the provided
// seed.
func (cfg ManagerConfig) deriveFromSeed(seed []byte) (
	*hdkeychain.ExtendedKey, error) {

	// Ensure a seed was provided for restoration.
	if len(seed) == 0 {
		return nil, fmt.Errorf("%w: seed is required", ErrWalletParams)
	}

	// Derive the master extended private key from the provided seed.
	key, err := hdkeychain.NewMaster(seed, &cfg.ChainParams)
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key: %w", err)
	}

	return key, nil
}
