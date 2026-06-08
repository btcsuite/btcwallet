//go:build itest

package itest

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
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
			scanBatchChainParams, &waddrmgr.FastScryptOptions,
			time.Time{},
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
		WalletID: walletID,
		Scope:    &scope,
		Page:     req,
	}
	if accountName != db.DefaultImportedAccountName {
		query.AccountName = &accountName
	} else {
		query.Scope = nil
	}

	scripts := make(map[derivedAddressKey][]byte)
	for addr, err := range store.IterAddresses(t.Context(), query) {
		require.NoError(t, err)

		if !addr.HasDerivationPath {
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
		WalletID: walletID,
		Scope:    &scope,
		Page:     req,
	}
	if accountName != db.DefaultImportedAccountName {
		query.AccountName = &accountName
	} else {
		query.Scope = nil
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

// TestApplyScanBatchHorizonsConformance proves that a non-empty Horizons batch
// derives an identical set of addresses on kvdb and the SQL backend under
// test. Each SQL backend (sqlite or postgres, selected by build tag) is
// compared against an in-process kvdb store seeded from the same account key,
// so green runs on both tags establish kvdb == sqlite == postgres parity.
func TestApplyScanBatchHorizonsConformance(t *testing.T) {
	t.Parallel()

	fixture := newKVDBScanFixture(t)

	// Build the SQL store with the same real BIP32 derivation kvdb uses.
	sqlStore := NewTestStoreWithDerive(t, realAddressDeriveFunc())

	walletID := newWallet(t, sqlStore, "wallet-scan-conformance")

	// Recreate the kvdb default account inside the SQL store with the exact
	// same account extended public key so both derive identical scripts.
	deriveAccount := func(_ context.Context, _ db.KeyScope, _ uint32,
		watchOnly bool) (*db.DerivedAccountData, error) {

		data := &db.DerivedAccountData{
			PublicKey:            []byte(fixture.accountXPub),
			MasterKeyFingerprint: 0x01020304,
		}
		if !watchOnly {
			data.EncryptedPrivateKey = RandomBytes(48)
		}

		return data, nil
	}

	sqlAccount, err := sqlStore.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    fixture.scope,
			Name:     fixture.accountName,
		}, deriveAccount,
	)
	require.NoError(t, err)
	require.NotNil(t, sqlAccount.AccountID)

	// A batch that extends both branches well past index 0 forces real
	// multi-address derivation on each backend.
	kvdbHorizons := []db.ScanHorizon{
		{
			Scope:       fixture.scope,
			Account:     waddrmgr.DefaultAccountNum,
			AccountName: fixture.accountName,
			Branch:      0,
			Index:       8,
		},
		{
			Scope:       fixture.scope,
			Account:     waddrmgr.DefaultAccountNum,
			AccountName: fixture.accountName,
			Branch:      1,
			Index:       3,
		},
	}
	sqlHorizons := make([]db.ScanHorizon, len(kvdbHorizons))
	copy(sqlHorizons, kvdbHorizons)

	for i := range sqlHorizons {
		sqlHorizons[i].AccountID = sqlAccount.AccountID
	}

	kvdbParams := db.ScanBatchParams{
		WalletID: 0,
		Horizons: kvdbHorizons,
	}
	sqlParams := db.ScanBatchParams{
		WalletID: walletID,
		Horizons: sqlHorizons,
	}

	require.NoError(t, fixture.store.ApplyScanBatch(t.Context(), kvdbParams))
	require.NoError(t, sqlStore.ApplyScanBatch(t.Context(), sqlParams))

	kvdbScripts := collectDerivedScripts(
		t, fixture.store, 0, fixture.scope, fixture.accountName,
	)
	sqlScripts := collectDerivedScripts(
		t, sqlStore, walletID, fixture.scope, fixture.accountName,
	)

	// Branch 0 derives indices 0..8 (9 addresses) and branch 1 derives
	// indices 0..3 (4 addresses) for a total of 13 derived addresses.
	require.Len(t, kvdbScripts, 13)
	require.Equal(t, kvdbScripts, sqlScripts,
		"kvdb and SQL must derive identical address scripts")

	// Replaying the same batch must be a no-op on both backends: the
	// horizon early-returns once the discovered index is below the next
	// index, so no duplicate rows are inserted.
	require.NoError(t, fixture.store.ApplyScanBatch(t.Context(), kvdbParams))
	require.NoError(t, sqlStore.ApplyScanBatch(t.Context(), sqlParams))

	kvdbReplay := collectDerivedScripts(
		t, fixture.store, 0, fixture.scope, fixture.accountName,
	)
	sqlReplay := collectDerivedScripts(
		t, sqlStore, walletID, fixture.scope, fixture.accountName,
	)
	require.Equal(t, kvdbScripts, kvdbReplay)
	require.Equal(t, sqlScripts, sqlReplay)
}

// TestApplyScanBatchResolvesHorizonByAccountID proves the SQL backend resolves
// a scan horizon's owning account by its durable account row ID, not by mutable
// account name or masked account number. An imported-xpub account stores a NULL
// account_number that the AccountInfo contract masks to 0, the same number the
// default derived account uses, so a by-number resolution would extend the
// wrong account. The test creates both accounts in one scope and asserts the
// imported account ID is the one extended even when the horizon carries stale
// name metadata, a derived account still resolves by ID, and a missing ID fails
// the batch instead of silently extending the default account 0.
//
// Extension is verified two ways. The advanced next-index counters are the
// direct evidence of which account the extension targeted, the same signal the
// sibling invalid-child tests assert. The listing assertions then prove the
// imported-xpub account's HD-derived rows are listable: an imported-xpub
// account is HD, so its derived rows carry a real branch/index that
// IterAddresses must surface (origin ImportedAccount with a populated path),
// not reject as it once did.
func TestApplyScanBatchResolvesHorizonByAccountID(t *testing.T) {
	t.Parallel()

	// A watch-only wallet is required because an imported-xpub account is
	// public-only and the ADR 0012 spendable-wallet invariant rejects it on
	// a spendable wallet.
	const (
		derivedAccount  = "derived-account"
		importedAccount = "imported-xpub-account"
	)

	scope := db.KeyScopeBIP0084

	store := NewTestStoreWithDerive(t, realAddressDeriveFunc())
	walletID := newWatchOnlyWallet(t, store, "wallet-scan-by-name")

	// A real account extended public key so the horizon extension can derive
	// valid child addresses from the imported account's xpub. The mock derive
	// callback ignores the key, but CreateDerivedAccount stores it verbatim
	// and the imported xpub below must parse, so a real key keeps both paths
	// consistent.
	fixture := newKVDBScanFixture(t)

	importedKey, err := hdkeychain.NewKeyFromString(fixture.accountXPub)
	require.NoError(t, err)

	importedKey, err = importedKey.Derive(0)
	require.NoError(t, err)

	importedXPub := importedKey.String()

	// The default derived account allocates account number 0; an
	// imported-xpub account stores a NULL number that masks to 0 too, so
	// both share the by-number fast-path identity and only AccountName can
	// disambiguate them.
	deriveAccount := func(_ context.Context, _ db.KeyScope, _ uint32,
		_ bool) (*db.DerivedAccountData, error) {

		return &db.DerivedAccountData{
			PublicKey:            []byte(fixture.accountXPub),
			MasterKeyFingerprint: 0x01020304,
		}, nil
	}

	derivedInfo, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    scope,
			Name:     derivedAccount,
		}, deriveAccount,
	)
	require.NoError(t, err)
	require.Equal(t, uint32Ptr(0), derivedInfo.AccountNumber)
	require.NotNil(t, derivedInfo.AccountID)

	importedInfo, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:  walletID,
			Name:      importedAccount,
			Scope:     scope,
			PublicKey: []byte(importedXPub),
		},
	)
	require.NoError(t, err)
	require.NotNil(t, importedInfo.AccountID)

	// Emit a horizon for the imported account: Account is masked to 0 (the
	// default derived account's number) and AccountName is stale metadata, so
	// only AccountID resolves the intended target.
	err = store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: walletID,
		Horizons: []db.ScanHorizon{{
			AccountID:   importedInfo.AccountID,
			Scope:       scope,
			Account:     0,
			AccountName: "stale-imported-name",
			Branch:      0,
			Index:       3,
		}},
	})
	require.NoError(t, err)

	// The imported account's external next index must advance to 4 (indices
	// 0..3 derived); the default derived account (also number 0) must stay at
	// 0, proving the horizon resolved by ID and not by mutable name metadata or
	// the masked number.
	imported := getAccountByName(t, store, walletID, scope, importedAccount)
	require.Equal(t, uint32(4), imported.ExternalKeyCount,
		"imported account ID must be the one extended")

	derived := getAccountByName(t, store, walletID, scope, derivedAccount)
	require.Equal(t, uint32(0), derived.ExternalKeyCount,
		"default derived account must not be extended by an imported "+
			"account ID horizon")

	// The extended imported-xpub account is HD, so its derived rows must be
	// listable with their branch/index, not rejected as a branch/index path on
	// an imported account. IterAddresses surfaces them with the account's
	// ImportedAccount origin and the external branch the horizon extended.
	// Each row is HD-derived, so HasDerivationPath must be true: this is what
	// lets the wallet-layer mapper tell an imported-xpub child at (0, 0) apart
	// from a raw single import at the same zero coordinates.
	paths := collectAddressPaths(
		t, store, walletID, scope, importedAccount,
	)
	require.Equal(t, []listedAddress{
		{branch: 0, index: 0, hasDerivationPath: true},
		{branch: 0, index: 1, hasDerivationPath: true},
		{branch: 0, index: 2, hasDerivationPath: true},
		{branch: 0, index: 3, hasDerivationPath: true},
	}, paths, "imported-xpub HD addresses must list with their path")

	// A raw single import is the contrasting shape: it lands in the keyless
	// "imported" bucket with no chain position, so it must read back with no
	// path and HasDerivationPath false, the inverse of the imported-xpub HD
	// children above. This is the signal's whole reason to exist, since both
	// shapes share the ImportedAccount origin.
	rawImport, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     walletID,
			AddressType:  db.WitnessPubKey,
			PubKey:       RandomBytes(33),
			ScriptPubKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)
	require.True(t, rawImport.IsImported)
	require.False(t, rawImport.HasDerivationPath,
		"a raw single import must not carry a derivation path")

	rawPaths := collectAddressPaths(
		t, store, walletID, scope, db.DefaultImportedAccountName,
	)
	require.Equal(t, []listedAddress{
		{branch: 0, index: 0, hasDerivationPath: false},
	}, rawPaths, "raw import must list with no path and "+
		"HasDerivationPath false")

	// A horizon carrying the derived account ID still resolves and extends only
	// the derived account, regardless of its AccountName metadata.
	err = store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: walletID,
		Horizons: []db.ScanHorizon{{
			AccountID:   derivedInfo.AccountID,
			Scope:       scope,
			Account:     0,
			AccountName: "stale-derived-name",
			Branch:      0,
			Index:       1,
		}},
	})
	require.NoError(t, err)

	derived = getAccountByName(t, store, walletID, scope, derivedAccount)
	require.Equal(t, uint32(2), derived.ExternalKeyCount,
		"derived account ID must resolve and extend")

	// A horizon without an account ID must fail the batch outright. The
	// fail-safe forbids falling back to mutable names or the default account 0.
	err = store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: walletID,
		Horizons: []db.ScanHorizon{{
			Scope:       scope,
			Account:     0,
			AccountName: importedAccount,
			Branch:      0,
			Index:       5,
		}},
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)

	// The failed batch must not have extended either account.
	imported = getAccountByName(t, store, walletID, scope, importedAccount)
	require.Equal(t, uint32(4), imported.ExternalKeyCount,
		"failed batch must not extend the imported account")

	derived = getAccountByName(t, store, walletID, scope, derivedAccount)
	require.Equal(t, uint32(2), derived.ExternalKeyCount,
		"failed batch must not extend the derived account")
}

// TestApplyScanBatchSkipsInvalidChild verifies that the SQL horizon extension
// skips an HD-invalid child index instead of failing, matching the kvdb
// ScopedKeyManager.ExtendAddresses behaviour. kvdb cannot be coerced into an
// invalid child at a chosen low index, so the skip is exercised directly
// against the SQL backend with a derivation callback that reports
// hdkeychain.ErrInvalidChild for one index.
func TestApplyScanBatchSkipsInvalidChild(t *testing.T) {
	t.Parallel()

	const invalidIndex = 2

	scope := db.KeyScopeBIP0084
	accountName := "skip-account"

	// The callback errors with ErrInvalidChild only for the chosen index and
	// otherwise returns a deterministic script derived from the coordinates.
	derive := func(_ context.Context,
		params db.AddressDerivationParams) (*db.DerivedAddressData, error) {

		if params.Branch == 0 && params.Index == invalidIndex {
			return nil, hdkeychain.ErrInvalidChild
		}

		script := make([]byte, 22)
		script[0] = 0x00
		script[1] = 0x14
		script[2] = byte(params.Branch)
		script[3] = byte(params.Index)

		return &db.DerivedAddressData{ScriptPubKey: script}, nil
	}

	store := NewTestStoreWithDerive(t, derive)
	walletID := newWallet(t, store, "wallet-scan-skip")
	createDerivedAccount(t, store, walletID, scope, accountName)
	accountInfo := getAccountByName(t, store, walletID, scope, accountName)
	require.NotNil(t, accountInfo.AccountID)

	err := store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: walletID,
		Horizons: []db.ScanHorizon{{
			AccountID:   accountInfo.AccountID,
			Scope:       scope,
			Account:     0,
			AccountName: accountName,
			Branch:      0,
			Index:       4,
		}},
	})
	require.NoError(t, err)

	scripts := collectDerivedScripts(t, store, walletID, scope, accountName)

	// Indices 0,1,3,4 must be derived; index 2 is skipped as invalid.
	require.Len(t, scripts, 4)

	for _, idx := range []uint32{0, 1, 3, 4} {
		_, ok := scripts[derivedAddressKey{branch: 0, index: idx}]
		require.Truef(t, ok, "expected derived index %d", idx)
	}

	_, skipped := scripts[derivedAddressKey{branch: 0, index: invalidIndex}]
	require.False(t, skipped, "invalid child index must be skipped")

	// The next external index must advance past the discovered horizon so a
	// subsequent allocation does not collide with the derived range.
	account := getAccountByName(t, store, walletID, scope, accountName)
	require.Equal(t, uint32(5), account.ExternalKeyCount)
}
