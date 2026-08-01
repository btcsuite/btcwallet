package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// TestDBCreateWallet verifies that the wallet database is correctly
// initialized with the address and transaction manager buckets.

// TestDBCreateWallet verifies that the wallet database is correctly
// initialized with the address and transaction manager buckets.
func TestDBCreateWallet(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet with a fresh database.
	// Note: createTestWalletWithMocks creates the top-level buckets, but
	// they are empty. DBCreateWallet will populate them.
	w, _ := createTestWalletWithMocks(t)

	params := CreateWalletParams{
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	// Act: Initialize the wallet database.
	err := DBCreateWallet(w.cfg, params, nil)

	// Assert: Verify initialization success.
	require.NoError(t, err)

	// Verify that the address manager and transaction manager can be
	// opened, indicating successful initialization.
	err = walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		require.NotNil(t, addrmgrNs)

		_, err := waddrmgr.Open(
			addrmgrNs, params.PubPassphrase, w.cfg.ChainParams,
		)
		if err != nil {
			return err
		}

		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, txmgrNs)

		_, err = wtxmgr.Open(txmgrNs, w.cfg.ChainParams)

		return err
	})
	require.NoError(t, err)
}

// TestDBLoadWallet verifies that the wallet database can be successfully loaded
// and the address and transaction managers retrieved.
func TestDBLoadWallet(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and initialize it.
	w, _ := createTestWalletWithMocks(t)

	pubPass := []byte("public")
	w.cfg.PubPassphrase = pubPass

	params := CreateWalletParams{
		PubPassphrase:     pubPass,
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	err := DBCreateWallet(w.cfg, params, nil)
	require.NoError(t, err)

	// Act: Load the wallet database.
	addrMgr, txMgr, err := DBLoadWallet(w.cfg)

	// Assert: Verify that both managers were loaded successfully.
	require.NoError(t, err)
	require.NotNil(t, addrMgr)
	require.NotNil(t, txMgr)
}
