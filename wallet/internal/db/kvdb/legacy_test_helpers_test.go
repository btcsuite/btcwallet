package kvdb

import (
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// testPrivPass is the private passphrase used by legacy waddrmgr test
// helpers. It must match the seed/pass setup in newSpendableAddrMgr.
var testPrivPass = []byte("priv")

// newAddrStore is an alias for newSpendableAddrMgr used by the legacy
// address-store test paths in this package.
func newAddrStore(t *testing.T, dbConn walletdb.DB) *waddrmgr.Manager {
	t.Helper()

	return newSpendableAddrMgr(t, dbConn)
}

// legacyAccountProps captures the subset of waddrmgr account metadata that
// the legacy address-store tests rely on after creating an account.
type legacyAccountProps struct {
	AccountNumber uint32
}

// createLegacyAccount creates a new account on the given scoped manager and
// returns the metadata the test path consults.
func createLegacyAccount(t *testing.T, dbConn walletdb.DB,
	addrStore *waddrmgr.Manager, scope waddrmgr.KeyScope,
	name string) *legacyAccountProps {

	t.Helper()

	manager, err := addrStore.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	var accountNumber uint32

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		require.NoError(t, addrStore.Unlock(ns, testPrivPass))

		accountNumber, err = manager.NewAccount(ns, name)

		return err
	})
	require.NoError(t, err)

	return &legacyAccountProps{AccountNumber: accountNumber}
}
