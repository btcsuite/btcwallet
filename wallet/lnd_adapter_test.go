package wallet

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	storesqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	"github.com/stretchr/testify/require"
)

// TestStoreLndKeyAdapterRestart verifies concurrent key allocation and key
// recovery across restart without exposing a walletdb database to the caller.
func TestStoreLndKeyAdapterRestart(t *testing.T) {
	t.Parallel()

	params := &chaincfg.TestNet3Params
	pubPass := []byte("public-pass")
	privPass := []byte("private-pass")
	scope := waddrmgr.KeyScope{
		Purpose: 1017,
		Coin:    1,
	}
	schema := waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.WitnessPubKey,
		InternalAddrType: waddrmgr.WitnessPubKey,
	}

	dbPath := filepath.Join(t.TempDir(), "wallet.sqlite")
	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	require.NoError(t, storesqlite.ApplyMigrations(conn))

	store := dbsqlite.NewNamedStore(conn, "lnd-adapter")
	loader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err := loader.CreateNewWallet(
		pubPass, privPass, nil, time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	require.Nil(t, wallet.Database())
	require.NoError(t, wallet.Unlock(privPass, nil))
	require.NoError(t, wallet.InitializeKeyScope(
		scope, schema, []uint32{0, 1}, false,
	))

	const numKeys = 8
	type keyResult struct {
		index uint32
		key   []byte
		err   error
	}
	results := make(chan keyResult, numKeys)
	var workers sync.WaitGroup
	for i := 0; i < numKeys; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()

			pubKey, index, err := wallet.NextExternalKey(scope, 1)
			var serialized []byte
			if pubKey != nil {
				serialized = pubKey.SerializeCompressed()
			}
			results <- keyResult{
				index: index,
				key:   serialized,
				err:   err,
			}
		}()
	}
	workers.Wait()
	close(results)

	keys := make(map[uint32][]byte, numKeys)
	for result := range results {
		require.NoError(t, result.err)
		require.NotContains(t, keys, result.index)
		keys[result.index] = result.key
	}
	for index := uint32(0); index < numKeys; index++ {
		require.Contains(t, keys, index)

		pubKey, err := wallet.DeriveManagedPubKey(
			scope, waddrmgr.DerivationPath{
				InternalAccount: 1,
				Account:         1,
				Index:           index,
			},
		)
		require.NoError(t, err)
		require.Equal(t, keys[index], pubKey.SerializeCompressed())
	}

	privKey, err := wallet.DeriveFromKeyPath(
		scope, waddrmgr.DerivationPath{
			InternalAccount: 1,
			Account:         1,
		},
	)
	require.NoError(t, err)
	require.Equal(t, keys[0], privKey.PubKey().SerializeCompressed())

	var unsupported *UnsupportedStoreOperationError
	err = wallet.DropTransactionHistory(true)
	require.ErrorAs(t, err, &unsupported)
	require.Equal(t, "DropTransactionHistory", unsupported.Operation)

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())

	conn, err = storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	store = dbsqlite.NewNamedStore(conn, "lnd-adapter")
	loader, err = NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err = loader.OpenExistingWallet(pubPass, false)
	require.NoError(t, err)
	require.NoError(t, wallet.Unlock(privPass, nil))
	require.NoError(t, wallet.InitializeKeyScope(
		scope, schema, []uint32{0, 1}, false,
	))

	pubKey, index, err := wallet.NextExternalKey(scope, 1)
	require.NoError(t, err)
	require.Equal(t, uint32(numKeys), index)
	rederived, err := wallet.DeriveManagedPubKey(
		scope, waddrmgr.DerivationPath{
			InternalAccount: 1,
			Account:         1,
			Index:           index,
		},
	)
	require.NoError(t, err)
	require.True(t, pubKey.IsEqual(rederived))

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())
}

// TestStoreLndWatchOnlyKeyAdapter verifies that imported remote-signer family
// accounts support public allocation and derivation without private keys.
func TestStoreLndWatchOnlyKeyAdapter(t *testing.T) {
	t.Parallel()

	params := &chaincfg.TestNet3Params
	pubPass := []byte("public-pass")
	scope := waddrmgr.KeyScope{
		Purpose: 1017,
		Coin:    1,
	}
	schema := waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.WitnessPubKey,
		InternalAddrType: waddrmgr.WitnessPubKey,
	}

	dbPath := filepath.Join(t.TempDir(), "watch-only.sqlite")
	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	require.NoError(t, storesqlite.ApplyMigrations(conn))

	store := dbsqlite.NewNamedStore(conn, "lnd-watch-only")
	loader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err := loader.CreateNewWatchingOnlyWallet(
		pubPass, time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	require.True(t, wallet.WatchOnly())

	seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
	require.NoError(t, err)
	rootKey, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)
	defer rootKey.Zero()
	purposeKey, err := rootKey.DeriveNonStandard(
		scope.Purpose + hdkeychain.HardenedKeyStart,
	)
	require.NoError(t, err)
	defer purposeKey.Zero()
	coinKey, err := purposeKey.DeriveNonStandard(
		scope.Coin + hdkeychain.HardenedKeyStart,
	)
	require.NoError(t, err)
	defer coinKey.Zero()

	for _, account := range []uint32{0, 1} {
		accountKey, err := coinKey.DeriveNonStandard(
			account + hdkeychain.HardenedKeyStart,
		)
		require.NoError(t, err)
		accountPubKey, err := accountKey.Neuter()
		require.NoError(t, err)

		_, err = wallet.ImportAccountWithScope(
			fmt.Sprintf("family-%d", account), accountPubKey, 0,
			scope, schema,
		)
		accountPubKey.Zero()
		accountKey.Zero()
		require.NoError(t, err)
	}

	require.NoError(t, wallet.InitializeKeyScope(
		scope, schema, []uint32{0, 1}, false,
	))
	pubKey, index, err := wallet.NextExternalKey(scope, 1)
	require.NoError(t, err)
	require.Zero(t, index)
	rederived, err := wallet.DeriveManagedPubKey(
		scope, waddrmgr.DerivationPath{
			InternalAccount: 1,
			Account:         1,
			Index:           index,
		},
	)
	require.NoError(t, err)
	require.True(t, pubKey.IsEqual(rederived))

	_, err = wallet.DeriveFromKeyPathAddAccount(
		scope, waddrmgr.DerivationPath{
			InternalAccount: 1,
			Account:         1,
		},
	)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWatchingOnly))

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())
}
