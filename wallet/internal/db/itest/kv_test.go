package itest

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// The manager namespaces the kvdb adapter binds. They match the well-known
// legacy top-level bucket keys.
var (
	kvAddrmgrNamespace = []byte("waddrmgr")
	kvTxmgrNamespace   = []byte("wtxmgr")

	// kvPubPassphrase is the public passphrase used to create and open the
	// KV conformance manager.
	kvPubPassphrase = []byte("public")
)

const kvDBTimeout = 10 * time.Second

// kvWallet holds the walletdb-backed managers for one KV conformance wallet.
type kvWallet struct {
	dbPath string
	db     walletdb.DB
	mgr    *waddrmgr.Manager
	txs    *wtxmgr.Store
	store  db.Store
}

// kvBackend builds walletdb-backed db.Store instances for the shared manager
// conformance vector.
type kvBackend struct {
	params  *chaincfg.Params
	nextID  int64
	wallets map[int64]*kvWallet
}

// createWallet builds an isolated walletdb-backed store seeded with the given
// start and synced blocks, mirroring the SQL createWallet helper.
func (b *kvBackend) createWallet(t *testing.T, start,
	synced waddrmgr.BlockStamp) int64 {

	t.Helper()

	b.nextID++
	id := b.nextID
	dbPath := filepath.Join(t.TempDir(), fmt.Sprintf("kv-%d.db", id))
	b.wallets[id] = b.openWallet(t, dbPath, true, start, synced)

	t.Cleanup(func() {
		w := b.wallets[id]
		w.mgr.Close()
		require.NoError(t, w.db.Close())
	})

	return id
}

// reopen closes and reopens the walletdb file for one wallet, rebinding fresh
// managers so persisted state can be verified.
func (b *kvBackend) reopen(t *testing.T, walletID int64) {
	t.Helper()

	w := b.wallets[walletID]
	w.mgr.Close()
	require.NoError(t, w.db.Close())

	b.wallets[walletID] = b.openWallet(
		t, w.dbPath, false, waddrmgr.BlockStamp{}, waddrmgr.BlockStamp{},
	)
}

// openWallet creates or opens a walletdb database and binds the address and
// transaction managers to it through the kvdb adapter. When create is true it
// also records the initial start and synced blocks.
func (b *kvBackend) openWallet(t *testing.T, dbPath string, create bool,
	start, synced waddrmgr.BlockStamp) *kvWallet {

	t.Helper()

	var (
		wdb walletdb.DB
		err error
	)
	if create {
		wdb, err = walletdb.Create("bdb", dbPath, true, kvDBTimeout, false)
	} else {
		wdb, err = walletdb.Open("bdb", dbPath, true, kvDBTimeout, false)
	}
	require.NoError(t, err)

	if create {
		b.initWallet(t, wdb, start, synced)
	}

	var (
		mgr *waddrmgr.Manager
		txs *wtxmgr.Store
	)
	err = walletdb.View(wdb, func(tx walletdb.ReadTx) error {
		mgr, err = waddrmgr.Open(
			tx.ReadBucket(kvAddrmgrNamespace), kvPubPassphrase, b.params,
		)
		if err != nil {
			return err
		}
		txs, err = wtxmgr.Open(tx.ReadBucket(kvTxmgrNamespace), b.params)

		return err
	})
	require.NoError(t, err)

	return &kvWallet{
		dbPath: dbPath,
		db:     wdb,
		mgr:    mgr,
		txs:    txs,
		store:  kvdb.NewStore(wdb, mgr, txs),
	}
}

// initWallet creates the manager namespaces and records the requested start and
// synced blocks in a freshly created walletdb database.
func (b *kvBackend) initWallet(t *testing.T, wdb walletdb.DB, start,
	synced waddrmgr.BlockStamp) {

	t.Helper()

	err := walletdb.Update(wdb, func(tx walletdb.ReadWriteTx) error {
		addrNS, err := tx.CreateTopLevelBucket(kvAddrmgrNamespace)
		if err != nil {
			return err
		}
		txNS, err := tx.CreateTopLevelBucket(kvTxmgrNamespace)
		if err != nil {
			return err
		}

		// A nil root key creates a bare watch-only manager with no
		// default scopes, matching the empty starting state of the SQL
		// createWallet helper.
		err = waddrmgr.Create(
			addrNS, nil, kvPubPassphrase, nil, b.params,
			&waddrmgr.FastScryptOptions, time.Unix(1, 0),
		)
		if err != nil {
			return err
		}
		if err := wtxmgr.Create(txNS); err != nil {
			return err
		}

		// Record the requested start and synced blocks through the bound
		// store.
		return waddrmgr.BindManagerReadWriteStore(addrNS).PutSyncState(
			waddrmgr.SyncState{
				StartBlock: start,
				SyncedTo:   synced,
				Birthday:   time.Unix(1, 0),
			},
		)
	})
	require.NoError(t, err)
}

// TestKVManagerStore runs the backend-neutral manager-store conformance vector
// against the walletdb (KV) backend.
//
//nolint:tparallel // The ordered conformance cases share one backend.
func TestKVManagerStore(t *testing.T) {
	t.Parallel()

	backend := &kvBackend{
		params:  &chaincfg.MainNetParams,
		wallets: make(map[int64]*kvWallet),
	}
	harness := &managerStoreHarness{kv: backend}
	harness.newStore = func(walletID int64) db.Store {
		return backend.wallets[walletID].store
	}
	harness.newRuntimeStore = func(walletID int64) db.RuntimeStore {
		w := backend.wallets[walletID]

		return kvdb.NewRuntimeStore(w.db, w.txs)
	}

	testManagerStore(t, harness)
}
