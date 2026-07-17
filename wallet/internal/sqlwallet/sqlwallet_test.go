// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sqlwallet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/stretchr/testify/require"
)

var (
	// lifecycleParams is the chain the lifecycle tests derive addresses for.
	lifecycleParams = &chaincfg.MainNetParams

	// lifecycleSeed is a fixed BIP-32 seed the lifecycle tests build the
	// wallet root key from, so derivations are deterministic across a restart.
	lifecycleSeed = []byte{
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
	}

	lifecyclePubPass  = []byte("public-passphrase")
	lifecyclePrivPass = []byte("private-passphrase")

	// lifecycleScope is the single scope the lifecycle tests create and
	// derive under, keeping the harness fast and focused.
	lifecycleScope = waddrmgr.KeyScopeBIP0084
)

const lifecycleWalletName = "lifecycle"

// newLoader builds a SQL wallet loader over a fresh database file in a
// dedicated directory, returning the loader and the directory so tests can
// inspect the on-disk files.
func newLoader(t *testing.T) (*SQLLoader, string) {
	t.Helper()

	dir := t.TempDir()
	loader, err := NewSQLLoader(SQLConfig{
		DBPath: filepath.Join(dir, "wallet.db"),
		Params: lifecycleParams,
		Scrypt: &waddrmgr.FastScryptOptions,
	})
	require.NoError(t, err)

	return loader, dir
}

// lifecycleRootKey returns the deterministic wallet root key.
func lifecycleRootKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	root, err := hdkeychain.NewMaster(lifecycleSeed, lifecycleParams)
	require.NoError(t, err)

	return root
}

// createLifecycleWallet creates one wallet with the single lifecycle scope.
func createLifecycleWallet(t *testing.T, loader *SQLLoader) *SQLWallet {
	t.Helper()

	wallet, err := loader.CreateWallet(context.Background(), CreateParams{
		Name:           lifecycleWalletName,
		RootKey:        lifecycleRootKey(t),
		PubPassphrase:  lifecyclePubPass,
		PrivPassphrase: lifecyclePrivPass,
		Scopes:         []waddrmgr.KeyScope{lifecycleScope},
	}, nil)
	require.NoError(t, err)

	return wallet
}

// durableAddresses reads all persisted addresses for one account directly from
// the wallet's live SQL connection, bypassing every in-memory cache.
func durableAddresses(t *testing.T, wallet *SQLWallet, scope waddrmgr.KeyScope,
	account uint32) []waddrmgr.AddressState {

	t.Helper()

	store := dbsqlite.NewStore(wallet.conn, wallet.walletID)

	var addrs []waddrmgr.AddressState
	err := store.View(context.Background(), func(tx walletstore.ReadTx) error {
		var err error

		addrs, err = tx.Addr().AccountAddresses(scope, account)

		return err
	}, func() {})
	require.NoError(t, err)

	return addrs
}

// TestSQLWalletCreateOpenUnlockDerive proves the core lifecycle: a wallet
// creates over SQLite, unlocks with the private passphrase, and derives one
// address end to end through the runtime coordinator, matching the manager's
// own derivation and persisting the durable row.
func TestSQLWalletCreateOpenUnlockDerive(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	loader, _ := newLoader(t)

	wallet := createLifecycleWallet(t, loader)
	defer func() {
		require.NoError(t, wallet.Close())
	}()

	require.NoError(t, wallet.Unlock(ctx, lifecyclePrivPass))

	addr, err := wallet.NextAddress(
		ctx, lifecycleScope, waddrmgr.DefaultAccountNum,
		waddrmgr.ExternalBranch,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(0), addr.Index)
	require.NotEmpty(t, addr.ScriptAddress)

	// The derived identity matches the manager's own chained derivation from
	// the same account key.
	root := lifecycleRootKey(t)
	acctKey := deriveExpectedAccountKey(t, root, lifecycleScope)
	want, wantNext, err := waddrmgr.DeriveChainedAddresses(
		acctKey, waddrmgr.ExternalBranch, waddrmgr.WitnessPubKey,
		lifecycleParams, 0, 1,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), wantNext)
	require.Equal(t, want[0].AddressID, addr.ScriptAddress)

	// The address row is durable.
	persisted := durableAddresses(
		t, wallet, lifecycleScope, waddrmgr.DefaultAccountNum,
	)
	require.Len(t, persisted, 1)
	require.Equal(t, uint32(0), *persisted[0].Index)
}

// TestSQLWalletRestartReconstructsCache proves the Phase 2B restart exit gate:
// after deriving address A, closing, and reopening, the wallet reconstructs its
// caches from durable state, derives address B at A's index plus one, and both
// addresses (and the synced tip) persist identically.
func TestSQLWalletRestartReconstructsCache(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	loader, _ := newLoader(t)

	// Derive address A, then close the wallet.
	first := createLifecycleWallet(t, loader)
	require.NoError(t, first.Unlock(ctx, lifecyclePrivPass))

	addrA, err := first.NextAddress(
		ctx, lifecycleScope, waddrmgr.DefaultAccountNum,
		waddrmgr.ExternalBranch,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(0), addrA.Index)

	tipBefore := first.SyncedTip()
	require.NoError(t, first.Close())

	// Reopen the wallet: the caches are reconstructed from durable state.
	second, err := loader.OpenWallet(ctx, OpenParams{
		Name:          lifecycleWalletName,
		PubPassphrase: lifecyclePubPass,
	})
	require.NoError(t, err)
	defer func() {
		require.NoError(t, second.Close())
	}()

	// The synced tip was reconstructed from durable state before any op.
	require.Equal(t, tipBefore, second.SyncedTip())

	require.NoError(t, second.Unlock(ctx, lifecyclePrivPass))

	addrB, err := second.NextAddress(
		ctx, lifecycleScope, waddrmgr.DefaultAccountNum,
		waddrmgr.ExternalBranch,
	)
	require.NoError(t, err)

	// B is A's index plus one, and the two addresses differ.
	require.Equal(t, addrA.Index+1, addrB.Index)
	require.NotEqual(t, addrA.ScriptAddress, addrB.ScriptAddress)

	// Both addresses persist durably at their respective indices.
	persisted := durableAddresses(
		t, second, lifecycleScope, waddrmgr.DefaultAccountNum,
	)
	require.Len(t, persisted, 2)

	indexes := make(map[uint32][]byte)
	for _, addr := range persisted {
		require.NotNil(t, addr.Index)
		indexes[*addr.Index] = addr.Hash
	}
	require.Contains(t, indexes, uint32(0))
	require.Contains(t, indexes, uint32(1))
}

// TestSQLWalletNoBboltSidecar proves the no-legacy-database exit gate: the full
// create-unlock-derive lifecycle over SQLite creates and reads no walletdb
// (bbolt) file. Only the SQLite database and its journal side files exist, and
// the database carries the SQLite file header, not a bbolt one.
func TestSQLWalletNoBboltSidecar(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	loader, dir := newLoader(t)

	wallet := createLifecycleWallet(t, loader)
	require.NoError(t, wallet.Unlock(ctx, lifecyclePrivPass))
	_, err := wallet.NextAddress(
		ctx, lifecycleScope, waddrmgr.DefaultAccountNum,
		waddrmgr.ExternalBranch,
	)
	require.NoError(t, err)
	require.NoError(t, wallet.Close())

	// Every file in the wallet directory belongs to the single SQLite
	// database; no separately named KV sidecar was created.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	for _, entry := range entries {
		require.Truef(t, strings.HasPrefix(entry.Name(), "wallet.db"),
			"unexpected non-SQLite file %q suggests a KV sidecar",
			entry.Name())
	}

	// The database file is a SQLite database, not a bbolt one.
	header := make([]byte, 16)
	file, err := os.Open(filepath.Join(dir, "wallet.db"))
	require.NoError(t, err)
	_, err = file.Read(header)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	require.True(t, bytes.HasPrefix(header, []byte("SQLite format 3\x00")))
}

// TestSQLWalletRuntimeStoreConstruction proves the wallet is constructed over
// the semantic RuntimeStore and never the low-level, callback-oriented
// PersistenceStore, so a path built on the SQL wallet cannot reach the raw
// View/Update transaction boundary.
func TestSQLWalletRuntimeStoreConstruction(t *testing.T) {
	t.Parallel()

	loader, _ := newLoader(t)
	wallet := createLifecycleWallet(t, loader)
	defer func() {
		require.NoError(t, wallet.Close())
	}()

	require.NotNil(t, wallet.runtimeStore)
	require.NotNil(t, wallet.coordinator)

	// The runtime store must not satisfy the low-level PersistenceStore
	// (View/Update) contract.
	_, isPersistence := wallet.runtimeStore.(walletstore.PersistenceStore)
	require.False(t, isPersistence,
		"wallet must be constructed over RuntimeStore, not PersistenceStore")
}

// TestSQLWalletAPISurface proves the narrowed API: the SQL wallet exposes no
// Database, AddrManager, exported Manager, or exported TxStore accessor, and
// all of its fields are unexported, so it offers no storage or concrete-manager
// escape hatch. This is the reflection-based negative surface check the exit
// gate requires, since Go has no direct negative interface assertion.
func TestSQLWalletAPISurface(t *testing.T) {
	t.Parallel()

	walletType := reflect.TypeFor[*SQLWallet]()
	for _, forbidden := range []string{
		"Database", "AddrManager", "Manager", "TxStore",
	} {
		_, has := walletType.MethodByName(forbidden)
		require.Falsef(t, has,
			"SQLWallet must not expose the %s escape hatch", forbidden)
	}

	structType := reflect.TypeFor[SQLWallet]()
	for i := range structType.NumField() {
		field := structType.Field(i)
		require.Falsef(t, field.IsExported(),
			"SQLWallet field %s must be unexported", field.Name)
	}
}

// TestSQLWalletLockedDerivation proves a locked wallet still derives addresses
// from the public account key, and that unlocking then deriving continues the
// same index sequence, so locking never diverges the address stream.
func TestSQLWalletLockedDerivation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	loader, _ := newLoader(t)

	wallet := createLifecycleWallet(t, loader)
	defer func() {
		require.NoError(t, wallet.Close())
	}()

	// Derive while locked: only the public account key is needed.
	locked, err := wallet.NextAddress(
		ctx, lifecycleScope, waddrmgr.DefaultAccountNum,
		waddrmgr.ExternalBranch,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(0), locked.Index)

	// Unlock and continue the same sequence.
	require.NoError(t, wallet.Unlock(ctx, lifecyclePrivPass))
	unlocked, err := wallet.NextAddress(
		ctx, lifecycleScope, waddrmgr.DefaultAccountNum,
		waddrmgr.ExternalBranch,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), unlocked.Index)
	require.NotEqual(t, locked.ScriptAddress, unlocked.ScriptAddress)
}

// TestSQLWalletWrongPassphrase proves a wrong public passphrase fails the open
// and a wrong private passphrase fails the unlock.
func TestSQLWalletWrongPassphrase(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	loader, _ := newLoader(t)

	wallet := createLifecycleWallet(t, loader)
	require.NoError(t, wallet.Close())

	// A wrong public passphrase fails the open.
	_, err := loader.OpenWallet(ctx, OpenParams{
		Name:          lifecycleWalletName,
		PubPassphrase: []byte("wrong-public"),
	})
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase))

	// A wrong private passphrase fails the unlock.
	reopened, err := loader.OpenWallet(ctx, OpenParams{
		Name:          lifecycleWalletName,
		PubPassphrase: lifecyclePubPass,
	})
	require.NoError(t, err)
	defer func() {
		require.NoError(t, reopened.Close())
	}()

	err = reopened.Unlock(ctx, []byte("wrong-private"))
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase))
}

// deriveExpectedAccountKey derives the default-account extended key m/
// purpose'/coin'/0' for a scope directly from the root using the public
// hdkeychain API, so a test can compare the wallet's derivation against an
// independent one that shares no code with the manager or the wallet.
func deriveExpectedAccountKey(t *testing.T, root *hdkeychain.ExtendedKey,
	scope waddrmgr.KeyScope) *hdkeychain.ExtendedKey {

	t.Helper()

	//nolint:staticcheck // DeriveNonStandard mirrors the manager's derivation.
	purpose, err := root.DeriveNonStandard(
		scope.Purpose + hdkeychain.HardenedKeyStart,
	)
	require.NoError(t, err)

	//nolint:staticcheck // DeriveNonStandard mirrors the manager's derivation.
	coin, err := purpose.DeriveNonStandard(
		scope.Coin + hdkeychain.HardenedKeyStart,
	)
	require.NoError(t, err)

	//nolint:staticcheck // DeriveNonStandard mirrors the manager's derivation.
	acct, err := coin.DeriveNonStandard(
		waddrmgr.DefaultAccountNum + hdkeychain.HardenedKeyStart,
	)
	require.NoError(t, err)

	return acct
}
