//go:build itest

package itest

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// scanBatchChainParams is the network the conformance backends share so the
// kvdb address manager and the SQL derivation callback build identical
// scripts.
var scanBatchChainParams = &chaincfg.RegressionNetParams

// scanBatchSeed is a fixed BIP32 seed used to build a deterministic kvdb
// address manager, so the derived account public key (and therefore every
// derived address) is reproducible across runs and backends.
var scanBatchSeed = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// realAddressDeriveFunc returns an AddressDerivationFunc that derives BIP32
// child addresses from the account-level extended public key, building the
// script exactly like the production wallet (and therefore the kvdb address
// manager) does. This is what lets the SQL backends reproduce kvdb's stored
// scripts byte-for-byte.
func realAddressDeriveFunc() db.AddressDerivationFunc {
	return func(_ context.Context,
		params db.AddressDerivationParams) (*db.DerivedAddressData, error) {

		accountKey, err := hdkeychain.NewKeyFromString(
			string(params.AccountPubKey),
		)
		if err != nil {
			return nil, err
		}

		branchKey, err := accountKey.Derive(params.Branch)
		if err != nil {
			return nil, err
		}

		addrKey, err := branchKey.Derive(params.Index)
		if err != nil {
			return nil, err
		}

		pubKey, err := addrKey.ECPubKey()
		if err != nil {
			return nil, err
		}

		pubKeyBytes := pubKey.SerializeCompressed()

		walletAddrType, err := addresstype.ToWallet(params.AddrType, false)
		if err != nil {
			return nil, err
		}

		addr, err := walletAddrType.AddrFromPubKeyBytes(
			pubKeyBytes, scanBatchChainParams,
		)
		if err != nil {
			return nil, err
		}

		scriptPubKey, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}

		return &db.DerivedAddressData{
			ScriptPubKey: scriptPubKey,
			PubKey:       pubKeyBytes,
		}, nil
	}
}

// kvdbScanFixture bundles a real kvdb store together with the account material
// a parallel SQL store needs to derive identical addresses.
type kvdbScanFixture struct {
	store       db.Store
	scope       db.KeyScope
	accountName string
	accountXPub string
}

// newKVDBScanFixture builds a kvdb store backed by a real waddrmgr address
// manager and wtxmgr transaction store seeded from scanBatchSeed. It returns
// the store and the BIP0084 default account's name and extended public key so
// the SQL backends can mirror the same derivation.
func newKVDBScanFixture(t *testing.T) kvdbScanFixture {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "kvdb-scan.db")
	dbConn, err := walletdb.Create(
		"bdb", dbPath, true, 10*time.Second, false,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = dbConn.Close()
	})

	rootKey, err := hdkeychain.NewMaster(scanBatchSeed, scanBatchChainParams)
	require.NoError(t, err)

	pubPass := []byte("public")
	privPass := []byte("private")

	addrmgrKey := []byte("waddrmgr")
	txmgrKey := []byte("wtxmgr")

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs, err := tx.CreateTopLevelBucket(addrmgrKey)
		if err != nil {
			return err
		}

		txmgrNs, err := tx.CreateTopLevelBucket(txmgrKey)
		if err != nil {
			return err
		}

		err = waddrmgr.Create(
			addrmgrNs, rootKey, pubPass, privPass,
			scanBatchChainParams, nil, time.Time{},
		)
		if err != nil {
			return err
		}

		return wtxmgr.Create(txmgrNs)
	})
	require.NoError(t, err)

	var (
		addrMgr *waddrmgr.Manager
		txStore *wtxmgr.Store
	)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(addrmgrKey)
		txmgrNs := tx.ReadWriteBucket(txmgrKey)

		addrMgr, err = waddrmgr.Open(
			addrmgrNs, pubPass, scanBatchChainParams,
		)
		if err != nil {
			return err
		}

		txStore, err = wtxmgr.Open(txmgrNs, scanBatchChainParams)

		return err
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		addrMgr.Close()
	})

	scope := waddrmgr.KeyScopeBIP0084

	scopedMgr, err := addrMgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	var props *waddrmgr.AccountProperties

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(addrmgrKey)
		props, err = scopedMgr.AccountProperties(
			ns, waddrmgr.DefaultAccountNum,
		)

		return err
	})
	require.NoError(t, err)
	require.NotNil(t, props.AccountPubKey)

	return kvdbScanFixture{
		store:       kvdb.NewStore(dbConn, txStore, addrMgr),
		scope:       db.KeyScope(scope),
		accountName: props.AccountName,
		accountXPub: props.AccountPubKey.String(),
	}
}

// derivedAddressKey identifies a derived address by its branch and index, the
// stable coordinates both backends agree on.
type derivedAddressKey struct {
	branch uint32
	index  uint32
}

// collectDerivedScripts returns the branch/index -> script_pub_key map for
// every derived address the store has recorded for the account.
func collectDerivedScripts(t *testing.T, store db.Store, walletID uint32,
	scope db.KeyScope, accountName string) map[derivedAddressKey][]byte {

	t.Helper()

	req, err := page.NewRequest[uint32](64)
	require.NoError(t, err)

	query := db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: accountName,
		Page:        req,
	}

	scripts := make(map[derivedAddressKey][]byte)
	for addr, err := range store.IterAddresses(t.Context(), query) {
		require.NoError(t, err)

		if addr.Origin != db.DerivedAccount {
			continue
		}

		key := derivedAddressKey{
			branch: addr.Branch,
			index:  addr.Index,
		}
		scripts[key] = addr.ScriptPubKey
	}

	return scripts
}

// listedAddress captures the listed coordinates of an address plus the
// HasDerivationPath signal, so a test can assert both the path and whether the
// row is HD-derived (a real path) versus a raw single import (no path).
type listedAddress struct {
	branch            uint32
	index             uint32
	hasDerivationPath bool
}

// collectAddressPaths returns the listed coordinates of every address the store
// lists for the account, in IterAddresses order. Unlike collectDerivedScripts
// it does not filter by origin, so it surfaces an imported-xpub account's
// HD-derived rows whose origin is ImportedAccount yet carry a real path, and it
// reports HasDerivationPath so the caller can tell those apart from raw single
// imports.
func collectAddressPaths(t *testing.T, store db.Store, walletID uint32,
	scope db.KeyScope, accountName string) []listedAddress {

	t.Helper()

	req, err := page.NewRequest[uint32](64)
	require.NoError(t, err)

	query := db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: accountName,
		Page:        req,
	}

	//nolint:prealloc // Iterator yields an unknown count.
	var paths []listedAddress
	for addr, err := range store.IterAddresses(t.Context(), query) {
		require.NoError(t, err)

		paths = append(paths, listedAddress{
			branch:            addr.Branch,
			index:             addr.Index,
			hasDerivationPath: addr.HasDerivationPath,
		})
	}

	return paths
}
