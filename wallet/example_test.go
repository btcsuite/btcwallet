package wallet

import (
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

// defaultDBTimeout specifies the timeout value when opening the wallet
// database.
var defaultDBTimeout = 10 * time.Second

// testWallet creates a test wallet and unlocks it.
func testWallet(t *testing.T) (*Wallet, func()) {
	// Set up a wallet.
	dir, err := os.MkdirTemp("", "test_wallet")
	if err != nil {
		t.Fatalf("Failed to create db dir: %v", err)
	}

	cleanup := func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("could not cleanup test: %v", err)
		}
	}

	seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
	if err != nil {
		t.Fatalf("unable to create seed: %v", err)
	}

	pubPass := []byte("hello")
	privPass := []byte("world")

	loader := NewLoader(
		&chaincfg.TestNet3Params, dir, true, defaultDBTimeout, 250,
		WithWalletSyncRetryInterval(10*time.Millisecond),
	)
	w, err := loader.CreateNewWallet(pubPass, privPass, seed, time.Now())
	if err != nil {
		t.Fatalf("unable to create wallet: %v", err)
	}
	chainClient := &mockChainClient{}
	w.chainClient = chainClient
	if err := w.Unlock(privPass, time.After(10*time.Minute)); err != nil {
		t.Fatalf("unable to unlock wallet: %v", err)
	}

	return w, cleanup
}

// testWalletWatchingOnly creates a test watch only wallet and unlocks it.
func testWalletWatchingOnly(t *testing.T) (*Wallet, func()) {
	// Set up a wallet.
	dir, err := os.MkdirTemp("", "test_wallet_watch_only")
	if err != nil {
		t.Fatalf("Failed to create db dir: %v", err)
	}

	cleanup := func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("could not cleanup test: %v", err)
		}
	}

	pubPass := []byte("hello")
	loader := NewLoader(
		&chaincfg.TestNet3Params, dir, true, defaultDBTimeout, 250,
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
			_, err := w.Manager.NewScopedKeyManager(
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

	return w, cleanup
}
