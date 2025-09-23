package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// defaultDBTimeout specifies the timeout value when opening the wallet
// database.
var defaultDBTimeout = 10 * time.Second

// testWallet creates a test wallet and unlocks it.
func testWallet(t *testing.T) *Wallet {
	t.Helper()
	// Set up a wallet.
	dir := t.TempDir()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
	if err != nil {
		t.Fatalf("unable to create seed: %v", err)
	}

	pubPass := []byte("hello")
	privPass := []byte("world")

	loader := NewLoader(
		&chainParams, dir, true, defaultDBTimeout, 250,
		WithWalletSyncRetryInterval(10*time.Millisecond),
	)
	w, err := loader.CreateNewWallet(pubPass, privPass, seed, time.Now())
	if err != nil {
		t.Fatalf("unable to create wallet: %v", err)
	}

	chainClient := &mockChainClient{}
	w.chainClient = chainClient

	// Start the wallet.
	w.Start()

	// Add the shutdown to the test's cleanup process.
	t.Cleanup(func() {
		w.Stop()
		w.WaitForShutdown()
	})

	if err := w.Unlock(privPass, time.After(10*time.Minute)); err != nil {
		t.Fatalf("unable to unlock wallet: %v", err)
	}

	return w
}

// mockers is a struct that holds all the mocked interfaces that can be
// used to test the wallet.
type mockers struct {
	chain     *mockChain
	addrStore *mockAddrStore
	txStore   *mockTxStore
}

// testWalletWithMocks creates a test wallet and unlocks it. In contrast to
// testWallet, this function mocks out all the wallet's dependencies so that
// we can test the wallet's logic in isolation.
func testWalletWithMocks(t *testing.T) (*Wallet, *mockers) {
	t.Helper()
	// Set up a wallet.
	dir := t.TempDir()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
	require.NoError(t, err)

	pubPass := []byte("hello")
	privPass := []byte("world")

	loader := NewLoader(
		&chainParams, dir, true, defaultDBTimeout, 250,
		WithWalletSyncRetryInterval(10*time.Millisecond),
	)
	w, err := loader.CreateNewWallet(pubPass, privPass, seed, time.Now())
	require.NoError(t, err)

	chain := &mockChain{}
	txStore := &mockTxStore{}
	addrStore := &mockAddrStore{}

	addrStore.On("IsLocked").Return(false)
	addrStore.On("Unlock", mock.Anything, mock.Anything).Return(nil)

	w.chainClient = chain
	w.txStore = txStore
	w.addrStore = addrStore

	// Start the wallet.
	w.Start()

	err = w.Unlock(privPass, time.After(60*time.Minute))
	require.NoError(t, err)

	// Create the mockers struct so it can be used by the tests to mock
	// methods.
	m := &mockers{
		chain:     chain,
		txStore:   txStore,
		addrStore: addrStore,
	}

	// When the test finishes, we need to assert the mocked methods are
	// called or not called as expected.
	t.Cleanup(func() {
		chain.AssertExpectations(t)
		txStore.AssertExpectations(t)
		addrStore.AssertExpectations(t)
	})

	return w, m
}

// testWalletWatchingOnly creates a test watch only wallet and unlocks it.
func testWalletWatchingOnly(t *testing.T) *Wallet {
	t.Helper()
	// Set up a wallet.
	dir := t.TempDir()

	pubPass := []byte("hello")
	loader := NewLoader(
		&chainParams, dir, true, defaultDBTimeout, 250,
		WithWalletSyncRetryInterval(10*time.Millisecond),
	)
	w, err := loader.CreateNewWatchingOnlyWallet(pubPass, time.Now())
	if err != nil {
		t.Fatalf("unable to create wallet: %v", err)
	}
	chainClient := &mockChainClient{}
	w.chainClient = chainClient

	err = walletdb.Update(w.Database(), func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		for scope, schema := range waddrmgr.ScopeAddrMap {
			_, err := w.addrStore.NewScopedKeyManager(
				ns, scope, schema,
			)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("unable to create default scopes: %v", err)
	}

	w.Start()
	t.Cleanup(func() {
		w.Stop()
		w.WaitForShutdown()
	})

	return w
}
