// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package sqlwallet is the Stage 3 Phase 2B minimal SQL wallet lifecycle
// harness. It creates, opens, unlocks, and derives addresses over a native SQL
// backend with no walletdb (KV) sidecar, proving that the salvage schema and
// the semantic runtime store can back a real openable wallet before the Phase 3
// recovery vertical begins.
//
// It is the seed of Workstream B's SQLWallet/SQLLoader public API. The types
// here are deliberately narrowed: SQLWallet exposes no Database(),
// AddrManager(), exported Manager/TxStore, or raw walletdb callback, so a path
// built on the SQL wallet cannot reach a bucket or a concrete manager.
// Construction runs entirely through the semantic db.RuntimeStore, never the
// low-level, callback-oriented PersistenceStore. The final home for these types
// is the wallet package once the shared BehavioralWallet method set is frozen
// from the existing backend-neutral callers; this package is the minimal,
// self-contained harness that keeps that work independent of the giant wallet
// package for now.
package sqlwallet

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlstore"
	"github.com/btcsuite/btcwallet/wallet/internal/runtime"
	sqlbackend "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	sqlitedb "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// operationIDSize is the length in bytes of a runtime operation id the wallet
// generates for a derivation commit.
const operationIDSize = 32

// SQLConfig configures a SQL-backed wallet loader.
type SQLConfig struct {
	// DBPath is the path to the SQLite database file backing the wallet.
	DBPath string

	// Params is the Bitcoin network the wallet derives addresses for.
	Params *chaincfg.Params

	// Scrypt overrides the key-derivation cost used when creating a wallet.
	// A nil value uses the secure default.
	Scrypt *waddrmgr.ScryptOptions
}

// CreateParams are the inputs to creating a new SQL wallet.
type CreateParams struct {
	// Name uniquely identifies the wallet within its database.
	Name string

	// RootKey is the wallet's BIP0032 master node. It is required; this
	// minimal path does not create watch-only wallets.
	RootKey *hdkeychain.ExtendedKey

	// PubPassphrase protects the public key material and is required on every
	// subsequent open.
	PubPassphrase []byte

	// PrivPassphrase protects the private key material and is required to
	// unlock the wallet.
	PrivPassphrase []byte

	// Birthday is the earliest time the wallet could hold funds. It defaults
	// to the network genesis timestamp when zero.
	Birthday time.Time

	// Scopes are the key scopes to create. It defaults to the manager's
	// default key scopes when empty.
	Scopes []waddrmgr.KeyScope
}

// OpenParams are the inputs to opening an existing SQL wallet.
type OpenParams struct {
	// Name identifies the wallet to open within its database.
	Name string

	// PubPassphrase decrypts the public key material.
	PubPassphrase []byte
}

// SQLLoader creates and opens SQL-backed wallets without exposing walletdb
// callbacks or a concrete manager. It is the narrowed, backend-neutral entry
// point Workstream B introduces for the opt-in SQL runtime.
type SQLLoader struct {
	cfg SQLConfig
}

// NewSQLLoader constructs a SQL wallet loader from the given configuration.
func NewSQLLoader(cfg SQLConfig) (*SQLLoader, error) {
	if cfg.DBPath == "" {
		return nil, errors.New("sqlwallet: a database path is required")
	}

	if cfg.Params == nil {
		return nil, errors.New("sqlwallet: chain params are required")
	}

	return &SQLLoader{cfg: cfg}, nil
}

// CreateWallet creates one SQL wallet with no KV sidecar. It prepares the KDF,
// crypto keys, encrypted material, and default scope and account data outside
// the write transaction, opens and migrates the salvage-schema database,
// commits the manager root and sync state, then commits the scopes and default
// accounts through the semantic runtime store. The returned wallet is loaded
// and locked; afterCreate, if non-nil, runs after the wallet is fully
// constructed and receives the narrowed SQL wallet, never a raw transaction.
//
//nolint:cyclop // A linear create sequence with per-step error handling.
func (l *SQLLoader) CreateWallet(ctx context.Context, params CreateParams,
	afterCreate func(context.Context, *SQLWallet) error) (*SQLWallet, error) {

	if params.Name == "" {
		return nil, errors.New("sqlwallet: a wallet name is required")
	}

	scopes := params.Scopes
	if len(scopes) == 0 {
		scopes = waddrmgr.DefaultKeyScopes
	}

	// Prepare all secret material outside any write transaction.
	secrets, err := waddrmgr.PrepareWalletSecrets(
		params.RootKey, params.PubPassphrase, params.PrivPassphrase,
		l.cfg.Scrypt, scopes,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlwallet: prepare secrets: %w", err)
	}

	birthday := params.Birthday
	if birthday.IsZero() {
		birthday = l.cfg.Params.GenesisBlock.Header.Timestamp
	}

	// Open and migrate the salvage-schema database, then commit the manager
	// root and initial sync state.
	conn, err := sqlbackend.OpenAndMigrate(ctx, sqlbackend.Config{
		DBPath: l.cfg.DBPath,
	})
	if err != nil {
		return nil, fmt.Errorf("sqlwallet: open database: %w", err)
	}

	walletID, err := l.commitWalletRoot(
		ctx, conn, params.Name, secrets.Manager, birthday,
	)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	// Commit the scopes and default accounts through the semantic runtime
	// store, exercising the Phase 2A1 EnsureScope and EnsureAccount ops.
	runtimeStore := sqlstore.NewRuntimeStore(
		dbsqlite.NewStore(conn, walletID).Store,
	)
	if err := commitScopes(ctx, runtimeStore, secrets.Scopes); err != nil {
		_ = conn.Close()

		return nil, err
	}

	// Load the wallet back through the same runtime path Open uses, so create
	// and open produce an identical in-memory wallet.
	wallet, err := l.load(
		ctx, conn, walletID, params.Name, params.PubPassphrase,
	)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	if afterCreate != nil {
		if err := afterCreate(ctx, wallet); err != nil {
			_ = wallet.Close()

			return nil, fmt.Errorf("sqlwallet: after-create: %w", err)
		}
	}

	return wallet, nil
}

// OpenWallet opens an existing SQL wallet by name. It reconstructs the
// in-memory caches from durable state through the semantic runtime store before
// any further operation, so a restart never reaches the low-level
// PersistenceStore boundary and never reads a legacy walletdb file.
func (l *SQLLoader) OpenWallet(ctx context.Context, params OpenParams) (
	*SQLWallet, error) {

	if params.Name == "" {
		return nil, errors.New("sqlwallet: a wallet name is required")
	}

	conn, err := sqlbackend.OpenAndMigrate(ctx, sqlbackend.Config{
		DBPath: l.cfg.DBPath,
	})
	if err != nil {
		return nil, fmt.Errorf("sqlwallet: open database: %w", err)
	}

	walletID, err := lookupWalletID(ctx, conn, params.Name)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	wallet, err := l.load(
		ctx, conn, walletID, params.Name, params.PubPassphrase,
	)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	return wallet, nil
}

// load reconstructs a SQLWallet from durable state. It reads the manager
// snapshot through the semantic runtime store, rebuilds the secret core and the
// scope and account caches, and constructs the runtime coordinator. It is
// shared by CreateWallet and OpenWallet so both produce an identical wallet.
func (l *SQLLoader) load(ctx context.Context, conn *sql.DB, walletID int64,
	name string, pubPassphrase []byte) (*SQLWallet, error) {

	runtimeStore := sqlstore.NewRuntimeStore(
		dbsqlite.NewStore(conn, walletID).Store,
	)

	snapshot, err := runtimeStore.LoadManagerSnapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("sqlwallet: load snapshot: %w", err)
	}

	// The keyring error is returned unwrapped so callers can classify a wrong
	// public passphrase with waddrmgr.IsError, which does not unwrap.
	keyring, err := waddrmgr.OpenManagerKeyring(
		snapshot.Manager, pubPassphrase, l.cfg.Params,
	)
	if err != nil {
		return nil, err
	}

	scopes := make(map[waddrmgr.KeyScope]*scopeCache, len(snapshot.Scopes))
	for _, scope := range snapshot.Scopes {
		cache := &scopeCache{
			schema:   scope.Scope.AddrSchema,
			accounts: make(map[uint32]waddrmgr.AccountState),
		}
		for _, account := range scope.Accounts {
			cache.accounts[account.Account] = account
		}

		scopes[scope.Scope.Scope] = cache
	}

	return &SQLWallet{
		name:         name,
		walletID:     walletID,
		params:       l.cfg.Params,
		conn:         conn,
		coordinator:  runtime.New(runtimeStore),
		runtimeStore: runtimeStore,
		keyring:      keyring,
		scopes:       scopes,
		syncedTip:    syncedTip(snapshot.SyncState),
	}, nil
}

// commitWalletRoot inserts the genesis block, the wallet row carrying the
// manager root state, the initial sync state, and the runtime-state row in one
// write transaction. Wallet-row creation is owned by the backend, so it uses
// the generated queries directly rather than the manager store surface. It
// returns the new wallet id.
func (l *SQLLoader) commitWalletRoot(ctx context.Context, conn *sql.DB,
	name string, manager waddrmgr.ManagerState, birthday time.Time) (int64,
	error) {

	genesisHash := l.cfg.Params.GenesisHash
	genesisTime := l.cfg.Params.GenesisBlock.Header.Timestamp

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("sqlwallet: begin create: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	queries := sqlitedb.New(tx)

	err = queries.PutBlock(ctx, sqlitedb.PutBlockParams{
		BlockHeight:    0,
		HeaderHash:     genesisHash[:],
		BlockTimestamp: genesisTime.Unix(),
	})
	if err != nil {
		return 0, fmt.Errorf("sqlwallet: put genesis block: %w", err)
	}

	walletID, err := queries.CreateWallet(ctx, sqlitedb.CreateWalletParams{
		WalletName:               name,
		ManagerVersion:           int64(manager.Version),
		ManagerCreatedAt:         manager.CreatedAt.Unix(),
		IsWatchOnly:              manager.WatchOnly,
		MasterPubParams:          manager.MasterPubParams,
		MasterPrivParams:         manager.MasterPrivParams,
		EncryptedCryptoPubKey:    manager.EncryptedCryptoPubKey,
		EncryptedCryptoPrivKey:   manager.EncryptedCryptoPrivKey,
		EncryptedCryptoScriptKey: manager.EncryptedCryptoScriptKey,
		EncryptedMasterHdPubKey:  manager.EncryptedMasterHDPubKey,
		EncryptedMasterHdPrivKey: manager.EncryptedMasterHDPrivKey,
	})
	if err != nil {
		return 0, fmt.Errorf("sqlwallet: create wallet row: %w", err)
	}

	err = queries.PutWalletSyncState(ctx, sqlitedb.PutWalletSyncStateParams{
		WalletID:              walletID,
		StartBlockHash:        genesisHash[:],
		SyncedBlockHash:       genesisHash[:],
		BirthdayTimestamp:     birthday.Unix(),
		BirthdayBlockHash:     nil,
		BirthdayBlockVerified: false,
	})
	if err != nil {
		return 0, fmt.Errorf("sqlwallet: put sync state: %w", err)
	}

	if err := queries.EnsureRuntimeState(ctx, walletID); err != nil {
		return 0, fmt.Errorf("sqlwallet: ensure runtime state: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("sqlwallet: commit create: %w", err)
	}

	return walletID, nil
}

// commitScopes creates each prepared scope and its default account through the
// semantic runtime coordinator, reusing the Phase 2A1 EnsureScope and
// EnsureAccount operations. Each is idempotent, so a retried creation is safe.
func commitScopes(ctx context.Context, runtimeStore walletstore.RuntimeStore,
	scopes []waddrmgr.ScopeSecrets) error {

	coord := runtime.New(runtimeStore)

	for _, scope := range scopes {
		_, err := coord.EnsureScope(ctx, scope.State)
		if err != nil {
			return fmt.Errorf("sqlwallet: ensure scope %v: %w",
				scope.State.Scope, err)
		}

		account := scope.Account
		prepare := func(newAccount uint32) (waddrmgr.AccountState, error) {
			// This minimal path prepares only the default account, whose
			// keys were derived for account zero. A fresh scope always
			// allocates zero first, so a different number means runtime
			// account creation, which is deferred to a later phase.
			if newAccount != waddrmgr.DefaultAccountNum {
				return waddrmgr.AccountState{}, fmt.Errorf(
					"sqlwallet: runtime account creation is not "+
						"supported yet (allocated %d)", newAccount)
			}

			return account, nil
		}

		_, err = coord.EnsureAccount(
			ctx, scope.State.Scope, account.Name, prepare,
		)
		if err != nil {
			return fmt.Errorf("sqlwallet: ensure account for scope "+
				"%v: %w", scope.State.Scope, err)
		}
	}

	return nil
}

// lookupWalletID resolves a wallet's surrogate id from its name using the
// generated wallet query.
func lookupWalletID(ctx context.Context, conn *sql.DB, name string) (int64,
	error) {

	wallet, err := sqlitedb.New(conn).GetWalletByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("sqlwallet: wallet %q not found", name)
	}

	if err != nil {
		return 0, fmt.Errorf("sqlwallet: look up wallet %q: %w", name, err)
	}

	return wallet.ID, nil
}

// randomOperationID returns a fresh random runtime operation id. Each
// derivation commit uses a distinct id, so the compare-and-swap on the branch
// index is the sole allocation guard. A production wallet would derive a
// deterministic id so a crash-retry is served idempotently from the journal;
// that is a later concern.
func randomOperationID() ([]byte, error) {
	id := make([]byte, operationIDSize)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("sqlwallet: generate operation id: %w", err)
	}

	return id, nil
}

// syncedTip projects a durable sync state into the neutral synced-tip reference
// the wallet caches.
func syncedTip(state waddrmgr.SyncState) walletstore.BlockRef {
	return walletstore.BlockRef{
		Height:    state.SyncedTo.Height,
		Hash:      state.SyncedTo.Hash,
		Timestamp: state.SyncedTo.Timestamp,
	}
}

// scopeCache holds the in-memory account state reconstructed for one key scope,
// standing in for the scoped manager's account map. It is guarded by the owning
// wallet's mutex.
type scopeCache struct {
	// schema is the scope's address schema, used to select the address type
	// for a derivation branch.
	schema waddrmgr.ScopeAddrSchema

	// accounts maps an account number to its durable state.
	accounts map[uint32]waddrmgr.AccountState
}
