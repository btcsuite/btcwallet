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
	// started lets public Start reject immediately while the runtime loop
	// is occupied. Only that loop changes the observed lifecycle guard.
	started atomic.Bool

	// wallets holds fully initialized and started Wallets keyed by unique
	// name. The runtime loop owns membership and publishes each Wallet only
	// after its initial accounts and native watches are ready.
	wallets map[string]*Wallet

	// backend owns the database and resolves the storage dependencies for
	// every wallet this Manager serves.
	backend managerBackend

	// config is the immutable shared policy retained at construction.
	config ManagerConfig

	// chainSyncer owns live routing for every Wallet served by this Manager.
	chainSyncer chainRouter

	// lifetimeCtx outlives construction and startup requests. Wallets keep
	// their own lifetimes; this closes after aggregate cleanup finishes.
	//nolint:containedctx // Manager owns and joins the shared reader lifetime.
	lifetimeCtx context.Context

	// cancel publishes completion after owned work and Store closure finish.
	cancel context.CancelFunc

	// requestChan transfers public operations to the sole runtime owner.
	// Each request carries a buffered response so the loop can finish it.
	requestChan chan any

	// wg joins owned intake and I/O before Store closure.
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

// stopManagerReq reserves cleanup errors for the first accepted Stop caller.
type stopManagerReq struct {
	resp chan error
}

// chainEventReq bounds intake until the owner finishes this source event.
type chainEventReq struct {
	event any
	err   error
	done  chan struct{}
}

// recoveryReq offers one proven-fork identity without waiting for its writer.
type recoveryReq struct {
	event chainRecoveryRequest
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

// rollbackResultReq keeps prepared writers fenced until their owner decides.
type rollbackResultReq struct {
	barrier chan struct{}
	receipt chan struct{}
	err     error
}

// managerRuntime holds one loop's state for its handlers, without shared locks.
type managerRuntime struct {
	manager               *Manager
	operation             chan struct{}
	rollingBack, stopping bool
	pending               *chainEventReq
	wallets               []*Wallet
	events                map[uint32]chainEvent
	cursor                int
	hint                  *chainRecoveryRequest
	stopReply             chan error
	failedStart           *startManagerResultReq
	failedCreate          *createWalletResultReq
}

// mainLoop selects delivery alongside requests until accepted I/O settles.
func (m *Manager) mainLoop() {
	workerCtx, cancelWork := context.WithCancel(m.lifetimeCtx)

	runtime := managerRuntime{manager: m}

	for !runtime.stopping || runtime.operation != nil {
		delivery, event := runtime.nextDelivery(workerCtx)
		select {
		case delivery <- event:
			runtime.cursor++

		case req := <-m.requestChan:
			runtime.handleReq(workerCtx, req)
		}

		// Startup/Create retains watch-time intake until its result arrives;
		// rollback preparation can be interrupted without that handoff.
		if runtime.stopping && runtime.rollingBack {
			cancelWork()
		}
	}

	cancelWork()
	runtime.finish()
	m.cancel()
}

// handleReq routes lifecycle requests to this loop's existing state owner.
func (r *managerRuntime) handleReq(ctx context.Context, raw any) {
	switch req := raw.(type) {
	case startManagerReq:
		r.start(ctx, req)

	case createWalletReq:
		r.create(ctx, req)

	case managerInfoReq:
		names := slices.Sorted(maps.Keys(r.manager.wallets))
		req.resp <- fmt.Sprintf("active_wallets=%v", names)

	case stopManagerReq:
		if r.stopReply == nil && !r.stopping {
			r.stopReply = req.resp
		}

		r.stopping = true

	default:
		r.handleChainReq(ctx, raw)
	}
}

// handleChainReq receives reports and results even during a held I/O operation.
func (r *managerRuntime) handleChainReq(ctx context.Context, raw any) {
	switch req := raw.(type) {
	case startManagerResultReq:
		r.completeStart(req)

	case createWalletResultReq:
		r.completeCreate(req)

	case rollbackResultReq:
		r.completeRollback(ctx, req)

	case chainEventReq:
		if req.err != nil {
			log.Warnf("Chain notification reader stopped: %v", req.err)

			r.stopping = true
		}

		if r.stopping {
			close(req.done)
			return
		}

		r.pending = &req

	case recoveryReq:
		// A terminal owner never consumes the retained hint; otherwise one
		// slot coalesces workers that recheck committed history on retry.
		if r.hint == nil {
			r.hint = &req.event
		}
	}
}

// start enrolls intake before startup watches and returns assembly as a result.
func (r *managerRuntime) start(ctx context.Context, req startManagerReq) {
	m := r.manager

	var err error
	switch {
	case r.stopping:
		err = ErrManagerStopped

	case req.ctx.Err() != nil:
		err = req.ctx.Err()

	case m.started.Swap(true):
		err = ErrStateForbidden

	default:
		r.operation = make(chan struct{})
		cfg, backend, router := m.config, m.backend, m.chainSyncer
		requests, wg := m.requestChan, &m.wg
		wg.Add(1)

		go m.startChainSyncer(ctx)

		wg.Go(func() {
			candidates, err := startWallets(req.ctx, cfg, backend, router)
			requests <- startManagerResultReq{req, candidates, err}
		})

		return
	}

	req.resp <- startManagerResp{err: err}
}

// create preserves caller-owned waiting instead of growing an owner queue.
func (r *managerRuntime) create(ctx context.Context, req createWalletReq) {
	m := r.manager

	var result createWalletResp
	switch {
	case r.stopping:
		result.err = ErrManagerStopped

	case !m.started.Load():
		result.err = ErrStateForbidden

	case r.operation != nil:
		result.retry = r.operation

	case r.pending != nil:
		result.retry = r.pending.done

	case req.params.Name != "" && m.wallets[req.params.Name] != nil:
		result.err = ErrWalletExists

	default:
		r.operation = make(chan struct{})
		cfg, backend, router := m.config, m.backend, m.chainSyncer
		requests, wg := m.requestChan, &m.wg
		// Accepted creation retains its ordinary result through Stop.
		ctx = context.WithoutCancel(ctx)

		wg.Go(func() {
			w, err := createWallet(ctx, req.params, cfg, backend, router)
			if err == nil {
				err = w.importInitialAccounts(
					ctx, req.params.InitialAccounts,
				)
				if err == nil {
					err = w.start(ctx, backend.prepareLiveWatches)
				}
			}

			requests <- createWalletResultReq{req, w, err}
		})

		return
	}

	req.resp <- result
}

// completeStart publishes only a complete successful set on the owner loop.
func (r *managerRuntime) completeStart(req startManagerResultReq) {
	close(r.operation)
	r.operation = nil

	if req.err != nil {
		r.failedStart, r.stopping = &req, true
		return
	}

	for _, w := range req.wallets {
		r.manager.wallets[w.cfg.Name] = w
	}

	req.req.resp <- startManagerResp{wallets: req.wallets}
}

// completeCreate keeps failed candidates under joined cleanup before replying.
func (r *managerRuntime) completeCreate(req createWalletResultReq) {
	close(r.operation)
	r.operation = nil

	if req.err != nil && req.wallet != nil {
		r.failedCreate, r.stopping = &req, true
		return
	}

	if req.err == nil {
		r.manager.wallets[req.wallet.cfg.Name] = req.wallet
	} else if errors.Is(req.err, db.ErrWalletExists) {
		req.err = fmt.Errorf("%w: %w", ErrWalletExists, req.err)
	}

	req.req.resp <- createWalletResp{wallet: req.wallet, err: req.err}
}

// beginRollback gives the one I/O task a fixed backend and recipient snapshot.
func (r *managerRuntime) beginRollback(ctx context.Context,
	event chain.BlockDisconnected, recovery bool, receipt chan struct{}) {

	r.operation = make(chan struct{})
	r.rollingBack = true
	m := r.manager
	backend, wallets := m.backend, slices.Collect(maps.Values(m.wallets))
	requests, wg := m.requestChan, &m.wg
	barrier := make(chan struct{})

	wg.Go(func() {
		err := handleRollbackEvent(
			ctx, backend, wallets, event, recovery, barrier,
		)
		requests <- rollbackResultReq{barrier, receipt, err}
	})
}

// completeRollback releases writers only after successful Store settlement.
func (r *managerRuntime) completeRollback(ctx context.Context,
	req rollbackResultReq) {

	r.rollingBack = false
	close(r.operation)
	r.operation = nil

	if req.err != nil {
		if ctx.Err() == nil {
			log.Errorf("Unable to roll back chain: %v", req.err)
		}

		r.stopping = true
	} else {
		close(req.barrier)
	}

	if req.receipt != nil {
		close(req.receipt)
	}
}

// prepareEvent starts recovery or matches one source event after publication.
func (r *managerRuntime) prepareEvent(ctx context.Context) {
	if r.pending == nil {
		if r.hint != nil {
			r.beginRollback(ctx, chain.BlockDisconnected(*r.hint), true, nil)
			r.hint = nil
		}

		return
	}

	if event, ok := r.pending.event.(chain.BlockDisconnected); ok {
		r.beginRollback(ctx, event, false, r.pending.done)
		r.pending = nil

		return
	}

	r.wallets = slices.Collect(maps.Values(r.manager.wallets))
	r.events = r.manager.chainSyncer.routeChainEvent(
		r.pending.event, r.wallets,
	)
}

// nextDelivery leaves a blocked mailbox selectable beside owner requests.
func (r *managerRuntime) nextDelivery(ctx context.Context) (
	chan chainEvent, chainEvent) {

	if r.stopping || r.operation != nil {
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

		// Recovery accepted during fanout must run before the next wait.
		r.prepareEvent(ctx)
	}

	return nil, chainEvent{}
}

// finish joins failed candidates and assigns cleanup errors to their owner.
func (r *managerRuntime) finish() {
	var candidates []*Wallet
	if r.failedStart != nil {
		candidates = r.failedStart.wallets
	}

	if r.failedCreate != nil {
		candidates = append(candidates, r.failedCreate.wallet)
	}

	err := r.manager.stop(candidates)
	if r.stopReply != nil {
		r.stopReply <- err

		err = nil
	}

	switch {
	case r.failedStart != nil:
		r.failedStart.req.resp <- startManagerResp{
			err: errors.Join(r.failedStart.err, err),
		}

	case r.failedCreate != nil:
		r.failedCreate.req.resp <- createWalletResp{
			err: errors.Join(r.failedCreate.err, err),
		}

	case err != nil:
		log.Errorf("Unable to stop manager: %v", err)
	}
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

// stop joins Wallets and intake before closing their Store.
func (m *Manager) stop(wallets []*Wallet) error {
	m.started.Store(true)

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

	// Intake must stop borrowing Store before its connection is released.
	m.wg.Wait()

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

// Stop joins accepted work and returns the first caller's cleanup errors.
func (m *Manager) Stop() error {
	req := stopManagerReq{resp: make(chan error, 1)}
	_ = m.sendReq(context.Background(), req)
	<-m.lifetimeCtx.Done()

	// The first caller's buffered outcome wins over final completion;
	// later callers join without replaying another caller's cleanup error.
	select {
	case err := <-req.resp:
		return err
	default:
		return nil
	}
}

// startChainSyncer reports source loss through the same inbox as normal events.
func (m *Manager) startChainSyncer(ctx context.Context) {
	defer m.wg.Done()

	err := m.chainSyncer.run(ctx, m.dispatchChainEvent)
	if err != nil && ctx.Err() == nil {
		req := chainEventReq{err: err, done: make(chan struct{})}
		_ = m.sendReq(ctx, req)
	}
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

// prepareWalletsForRollback fences a fixed recipient set before shared writes.
func prepareWalletsForRollback(ctx context.Context, wallets []*Wallet,
	rollbackDone <-chan struct{}) error {

	for _, wallet := range wallets {
		req := prepareRollbackReq{make(chan struct{}), rollbackDone}
		select {
		case wallet.chainEventChan <- chainEvent{notification: req}:
		case <-ctx.Done():
			return ctx.Err()
		}

		select {
		case <-req.readyForRollback:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// handleRollbackEvent fences writers while the owner receives reports.
func handleRollbackEvent(ctx context.Context, backend managerBackend,
	wallets []*Wallet, event chain.BlockDisconnected, recovery bool,
	barrier chan struct{}) error {

	block, err := storeBlockFromBlockMeta(wtxmgr.BlockMeta(event))
	if err != nil {
		return fmt.Errorf("disconnect block: %w", err)
	}

	err = prepareWalletsForRollback(ctx, wallets, barrier)
	if err != nil {
		return fmt.Errorf("wait for rollback writers: %w", err)
	}

	if recovery {
		needed, err := recoveryStillNeeded(ctx, wallets, *block)
		if err != nil {
			log.Warnf("Unable to check recovery hint: %v", err)

			needed = false
		}

		if !needed {
			return nil
		}
	}

	// Accepted durable writes settle before the owner can close Store.
	err = backend.rollbackToBlock(context.WithoutCancel(ctx), *block)
	if err != nil {
		return fmt.Errorf("rollback chain: %w", err)
	}

	return nil
}

// recoveryStillNeeded rejects hints for absent or replaced stored blocks.
func recoveryStillNeeded(ctx context.Context, wallets []*Wallet,
	block db.Block) (bool, error) {

	if len(wallets) == 0 {
		return false, nil
	}

	wallet := wallets[0]
	blocks, err := wallet.store.ListSyncedBlocks(ctx, db.ListSyncedBlocksQuery{
		StartHeight: block.Height,
		EndHeight:   block.Height,
	})

	if errors.Is(err, db.ErrBlockNotFound) {
		return false, nil
	}

	return len(blocks) != 0 && blocks[0].Hash == block.Hash, err
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
