package waddrmgr

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// TestManagerStoreKVAdapter verifies that the bucket-bound adapter preserves
// the existing address-manager encodings and semantics.
func TestManagerStoreKVAdapter(t *testing.T) {
	t.Parallel()

	teardown, database, _ := setupManager(t)
	t.Cleanup(teardown)

	addressID := []byte("manager-store-address")
	branch, index := uint32(0), uint32(11)
	wantAddress := AddressState{
		Scope:      KeyScopeBIP0084,
		Account:    DefaultAccountNum,
		Type:       AddressChain,
		AddedAt:    time.Unix(7_001, 0),
		SyncStatus: AddressSyncFull,
		Branch:     &branch,
		Index:      &index,
	}
	start := BlockStamp{
		Height: 700, Hash: chainhash.Hash{70}, Timestamp: time.Unix(7_000, 0),
	}
	synced := BlockStamp{
		Height: 701, Hash: chainhash.Hash{71}, Timestamp: time.Unix(7_001, 0),
	}
	birthdayBlock := BlockStamp{
		Height: 702, Hash: chainhash.Hash{72}, Timestamp: time.Unix(7_002, 0),
	}
	wantSync := SyncState{
		StartBlock:            start,
		SyncedTo:              synced,
		Birthday:              time.Unix(6_999, 0),
		BirthdayBlock:         &birthdayBlock,
		BirthdayBlockVerified: true,
	}

	err := walletdb.Update(database, func(tx walletdb.ReadWriteTx) error {
		store := BindManagerReadWriteStore(
			tx.ReadWriteBucket(waddrmgrNamespaceKey),
		)

		err := store.PutSyncState(wantSync)
		if err != nil {
			return err
		}

		return store.PutAddress(addressID, wantAddress)
	})
	require.NoError(t, err)

	err = walletdb.View(database, func(tx walletdb.ReadTx) error {
		store := BindManagerReadStore(tx.ReadBucket(waddrmgrNamespaceKey))

		_, err := store.ManagerState()
		require.NoError(t, err)
		gotSync, err := store.SyncState()
		require.NoError(t, err)

		wantSync.StartBlock.Timestamp = time.Time{}
		require.Equal(t, wantSync, gotSync)

		scopes, err := store.KeyScopes()
		require.NoError(t, err)
		require.NotEmpty(t, scopes)

		got, err := store.Address(KeyScopeBIP0084, addressID)
		require.NoError(t, err)

		hash := sha256.Sum256(addressID)
		wantAddress.Hash = hash[:]
		require.Equal(t, wantAddress, got)

		accountAddresses, err := store.AccountAddresses(
			KeyScopeBIP0084, DefaultAccountNum,
		)
		require.NoError(t, err)
		require.Contains(t, accountAddresses, wantAddress)

		activeAddresses, err := store.ActiveAddresses(KeyScopeBIP0084)
		require.NoError(t, err)
		require.Contains(t, activeAddresses, wantAddress)

		return nil
	})
	require.NoError(t, err)

	err = walletdb.Update(database, func(tx walletdb.ReadWriteTx) error {
		store := BindManagerReadWriteStore(
			tx.ReadWriteBucket(waddrmgrNamespaceKey),
		)

		return store.MarkAddressUsed(KeyScopeBIP0084, addressID)
	})
	require.NoError(t, err)

	err = walletdb.View(database, func(tx walletdb.ReadTx) error {
		store := BindManagerReadStore(tx.ReadBucket(waddrmgrNamespaceKey))
		got, err := store.Address(KeyScopeBIP0084, addressID)
		require.NoError(t, err)
		require.True(t, got.Used)

		activeAddresses, err := store.ActiveAddresses(KeyScopeBIP0084)
		require.NoError(t, err)
		require.Len(t, activeAddresses, 1)
		require.True(t, activeAddresses[0].Used)

		return nil
	})
	require.NoError(t, err)
}

// TestManagerStoreKVNoAccount verifies an unallocated scope keeps the legacy
// account-zero sentinel instead of recording account zero as already used.
func TestManagerStoreKVNoAccount(t *testing.T) {
	teardown, database, _ := setupManager(t)
	t.Cleanup(teardown)

	scope := KeyScope{Purpose: 1_017, Coin: 1}
	want := KeyScopeState{
		Scope:       scope,
		AddrSchema:  ScopeAddrMap[KeyScopeBIP0084],
		LastAccount: NoAccount,
	}
	err := walletdb.Update(database, func(tx walletdb.ReadWriteTx) error {
		store := BindManagerReadWriteStore(
			tx.ReadWriteBucket(waddrmgrNamespaceKey),
		)

		if err := store.PutKeyScope(want); err != nil {
			return err
		}
		if err := store.SetLastAccount(scope, 2); err != nil {
			return err
		}

		return store.PutKeyScope(want)
	})
	require.NoError(t, err)

	err = walletdb.View(database, func(tx walletdb.ReadTx) error {
		store := BindManagerReadStore(tx.ReadBucket(waddrmgrNamespaceKey))
		got, err := store.KeyScope(scope)
		require.NoError(t, err)
		require.Equal(t, want, got)

		return nil
	})
	require.NoError(t, err)
}
