// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"iter"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestAddressManagerFallbackDuringStop keeps oldest-unused selection, fallback
// allocation, and registration inside the accepted request during shutdown.
func TestAddressManagerFallbackDuringStop(t *testing.T) {
	t.Parallel()

	// Arrange: Pause an unused-address scan until shutdown closes admission.
	// An empty result then forces allocation through the accepted request.
	w, deps := createTestWalletWithMocks(t)
	startLoadedWalletForTest(t, w)

	enteredChan := make(chan struct{})
	releaseChan := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(releaseChan) })
	t.Cleanup(unblock)

	name := "fallback"
	selector := NewAccountSelectorByName(waddrmgr.KeyScopeBIP0084, name)
	expectReceivingAccount(t, w, deps, selector, &db.AccountInfo{
		AccountName: name,
	})
	expectAddressScan(t, w, deps, name, waddrmgr.KeyScopeBIP0084).
		Run(func(mock.Arguments) {
			close(enteredChan)

			<-releaseChan
		})

	addr, stored := storeChild(
		t, storeDerivationAccountPubKey(t), db.WitnessPubKey, false, 0,
	)
	expectFreshAddress(t, w, deps, selector, false, stored)
	deps.chain.On(
		"WatchAddrsFromTip", w.lifetimeCtx, []address.Address{addr},
	).Return(nil).Once()
	deps.vault.On("Lock").Return().Once()

	resultChan := make(chan addressInfoResp, 1)
	go func() {
		info, err := w.NewAddress(t.Context(), selector, false)
		resultChan <- addressInfoResp{info: info, err: err}
	}()

	<-enteredChan

	// Act: Begin shutdown while the accepted scan is paused. Its fallback
	// must still allocate and register an address without another admission.
	stoppedChan := make(chan error, 1)
	go func() { stoppedChan <- w.stop() }()

	<-w.lifetimeCtx.Done()

	// Assert: Stop waits for accepted work, and release permits the fallback
	// to return its address. Fixture cleanup verifies chain registration.
	select {
	case err := <-stoppedChan:
		t.Fatalf("Stop returned before address work: %v", err)
	default:
	}

	unblock()

	result := <-resultChan
	require.NoError(t, result.err)
	require.Equal(t, addr, result.info.Addr)
	require.NoError(t, <-stoppedChan)
}

// TestGetUnusedAddressFallbackDuringStop keeps nested address derivation and
// notification inside the accepted unused-address request during shutdown.
func TestGetUnusedAddressFallbackDuringStop(t *testing.T) {
	t.Parallel()

	// Arrange: Pause an unused-address scan until shutdown closes admission.
	// An empty result then forces derivation through the accepted request.
	w, deps := createTestWalletWithMocks(t)
	startLoadedWalletForTest(t, w)

	enteredChan := make(chan struct{})
	releaseChan := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(releaseChan) })
	t.Cleanup(unblock)

	scope := db.KeyScope(waddrmgr.KeyScopeBIP0084)
	name := "fallback"
	page, err := addressPageRequest()
	require.NoError(t, err)
	deps.store.On("IterAddresses", mock.Anything, db.ListAddressesQuery{
		WalletID:    w.id,
		AccountName: &name,
		Scope:       &scope,
		Page:        page,
	}).Run(func(mock.Arguments) {
		close(enteredChan)

		<-releaseChan
	}).Return(addressIter()).Once()

	addr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	require.NoError(t, err)
	expectStoreNewAddress(
		t, w, deps, name, waddrmgr.KeyScopeBIP0084, false, addr,
	)
	deps.vault.On("Lock").Return().Once()

	resultChan := make(chan addressResp, 1)
	go func() {
		addr, err := w.GetUnusedAddress(
			t.Context(), name, waddrmgr.WitnessPubKey, false,
		)
		resultChan <- addressResp{addr: addr, err: err}
	}()

	<-enteredChan

	// Act: Begin shutdown while the accepted scan is paused. Its fallback
	// must still derive and register an address without another admission.
	stoppedChan := make(chan error, 1)
	go func() { stoppedChan <- w.stop() }()

	<-w.lifetimeCtx.Done()

	// Assert: Stop waits for accepted work, and release permits the fallback
	// to return its address. Fixture cleanup verifies chain registration.
	select {
	case err := <-stoppedChan:
		t.Fatalf("Stop returned before address work: %v", err)
	default:
	}

	unblock()

	result := <-resultChan
	require.NoError(t, result.err)
	require.Equal(t, addr, result.addr)
	require.NoError(t, <-stoppedChan)
}

// storeDerivationAccountPubKey returns a deterministic account-level public key
// for store-native address derivation tests.
func storeDerivationAccountPubKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	seed := bytes.Repeat([]byte{0x42}, hdkeychain.RecommendedSeedLen)
	masterKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	purposeKey, err := masterKey.Derive(
		hdkeychain.HardenedKeyStart + waddrmgr.KeyScopeBIP0084.Purpose,
	)
	require.NoError(t, err)

	coinKey, err := purposeKey.Derive(
		hdkeychain.HardenedKeyStart + waddrmgr.KeyScopeBIP0084.Coin,
	)
	require.NoError(t, err)

	accountKey, err := coinKey.Derive(hdkeychain.HardenedKeyStart)
	require.NoError(t, err)

	accountPubKey, err := accountKey.Neuter()
	require.NoError(t, err)

	return accountPubKey
}

// expectedStoreAddress derives the expected address fields without calling the
// store-native derivation helper under test.
func expectedStoreAddress(t *testing.T,
	accountPubKey *hdkeychain.ExtendedKey, addrType db.AddressType,
	branch uint32, index uint32) (address.Address, []byte, []byte) {

	t.Helper()

	branchKey, err := accountPubKey.Derive(branch)
	require.NoError(t, err)

	defer branchKey.Zero()

	addrKey, err := branchKey.Derive(index)
	require.NoError(t, err)

	defer addrKey.Zero()

	pubKey, err := addrKey.ECPubKey()
	require.NoError(t, err)

	pubKeyBytes := pubKey.SerializeCompressed()
	addr := expectedStoreAddressFromPubKey(t, addrType, pubKey, pubKeyBytes)

	scriptPubKey, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return addr, scriptPubKey, pubKeyBytes
}

// expectedStoreAddressFromPubKey encodes an expected address for one store
// address type.
func expectedStoreAddressFromPubKey(t *testing.T, addrType db.AddressType,
	pubKey *btcec.PublicKey, pubKeyBytes []byte) address.Address {

	t.Helper()

	switch addrType {
	case db.PubKeyHash:
		addr, err := address.NewAddressPubKeyHash(
			address.Hash160(pubKeyBytes), &chainParams,
		)
		require.NoError(t, err)

		return addr

	case db.WitnessPubKey:
		addr, err := address.NewAddressWitnessPubKeyHash(
			address.Hash160(pubKeyBytes), &chainParams,
		)
		require.NoError(t, err)

		return addr

	case db.NestedWitnessPubKey:
		witnessAddr, err := address.NewAddressWitnessPubKeyHash(
			address.Hash160(pubKeyBytes), &chainParams,
		)
		require.NoError(t, err)

		witnessProgram, err := txscript.PayToAddrScript(witnessAddr)
		require.NoError(t, err)

		addr, err := address.NewAddressScriptHash(
			witnessProgram, &chainParams,
		)
		require.NoError(t, err)

		return addr

	case db.TaprootPubKey:
		outputKey := schnorr.SerializePubKey(
			txscript.ComputeTaprootKeyNoScript(pubKey),
		)

		addr, err := address.NewAddressTaproot(outputKey, &chainParams)
		require.NoError(t, err)

		return addr

	case db.RawPubKey, db.ScriptHash, db.WitnessScript, db.Anchor:
		require.FailNow(t, "unsupported address type")

		return nil

	default:
		require.FailNow(t, "unsupported address type")

		return nil
	}
}

// TestDeriveStoreAddressEncodesTypes verifies store-native derivation encodes
// the same child pubkey into the expected script family for each supported
// single-key address type.
func TestDeriveStoreAddressEncodesTypes(t *testing.T) {
	t.Parallel()

	accountPubKey := storeDerivationAccountPubKey(t)
	accountNumber := uint32(0)

	testCases := []struct {
		name     string
		addrType db.AddressType
		branch   uint32
		index    uint32
	}{
		{
			name:     "p2pkh",
			addrType: db.PubKeyHash,
			branch:   waddrmgr.ExternalBranch,
			index:    7,
		},
		{
			name:     "p2wkh",
			addrType: db.WitnessPubKey,
			branch:   waddrmgr.ExternalBranch,
			index:    8,
		},
		{
			name:     "np2wkh",
			addrType: db.NestedWitnessPubKey,
			branch:   waddrmgr.InternalBranch,
			index:    9,
		},
		{
			name:     "p2tr",
			addrType: db.TaprootPubKey,
			branch:   waddrmgr.InternalBranch,
			index:    10,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			params := db.AddressDerivationParams{
				Scope:                db.KeyScope(waddrmgr.KeyScopeBIP0084),
				DerivedAccountNumber: &accountNumber,
				Branch:               tc.branch,
				Index:                tc.index,
				AddrType:             tc.addrType,
				AccountPubKey:        []byte(accountPubKey.String()),
			}

			addr, scriptPubKey, pubKey, err := deriveStoreAddress(
				params, &chainParams,
			)
			require.NoError(t, err)

			wantAddr, wantScript, wantPubKey := expectedStoreAddress(
				t, accountPubKey, tc.addrType, tc.branch, tc.index,
			)

			require.Equal(t, wantAddr.EncodeAddress(), addr.EncodeAddress())
			require.Equal(t, wantScript, scriptPubKey)
			require.Equal(t, wantPubKey, pubKey)
		})
	}
}

// addressInfoFromAddr builds a store address record for a test address.
func addressInfoFromAddr(t *testing.T, addr address.Address) *db.AddressInfo {
	t.Helper()

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return &db.AddressInfo{ScriptPubKey: pkScript}
}

// derivedAddressInfoFromAddr builds derived store address metadata for tests.
func derivedAddressInfoFromAddr(t *testing.T, addr address.Address,
	addrType db.AddressType, accountName string, scope waddrmgr.KeyScope,
	change bool, index uint32, fingerprint uint32,
	pubKey *btcec.PublicKey) *db.AddressInfo {

	t.Helper()

	info := addressInfoFromAddr(t, addr)
	accountNumber := uint32(0)
	info.AddrType = addrType
	info.AccountName = accountName
	info.AccountNumber = &accountNumber
	info.KeyScope = db.KeyScope(scope)
	info.MasterKeyFingerprint = fingerprint
	info.HasDerivationPath = true
	info.Index = index

	if change {
		info.Branch = 1
	}

	if pubKey != nil {
		info.PubKey = pubKey.SerializeCompressed()
	}

	return info
}

// importedPubKeyAddressInfoFromAddr builds imported public-key store metadata
// for tests.
func importedPubKeyAddressInfoFromAddr(t *testing.T, addr address.Address,
	scope waddrmgr.KeyScope, pubKey *btcec.PublicKey) *db.AddressInfo {

	t.Helper()

	info := addressInfoFromAddr(t, addr)
	info.AddrType = db.WitnessPubKey
	info.IsImported = true
	info.AccountName = db.DefaultImportedAccountName
	info.KeyScope = db.KeyScope(scope)
	info.IsWatchOnly = true

	if pubKey != nil {
		info.PubKey = pubKey.SerializeCompressed()
	}

	return info
}

// expectReceivingAccount configures the account lookup NewAddress performs
// before any address is read, allocated, or registered.
func expectReceivingAccount(t *testing.T, w *Wallet, deps *mockWalletDeps,
	selector AccountSelector, account *db.AccountInfo) *mock.Call {

	t.Helper()

	return deps.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID:      w.id,
		Scope:         db.KeyScope(selector.keyScope),
		Name:          selector.accountName,
		AccountNumber: (*uint32)(selector.accountNumber),
		SkipBalance:   true,
	}).Return(account, nil).Once()
}

// expectAddressScan configures one oldest-unused scan of the resolved account.
func expectAddressScan(t *testing.T, w *Wallet, deps *mockWalletDeps,
	accountName string, scope waddrmgr.KeyScope,
	items ...db.AddressInfo) *mock.Call {

	t.Helper()

	req, err := addressPageRequest()
	require.NoError(t, err)

	dbScope := db.KeyScope(scope)

	return deps.store.On("IterAddresses", mock.Anything,
		db.ListAddressesQuery{
			WalletID:    w.id,
			AccountName: &accountName,
			Scope:       &dbScope,
			Page:        req,
		},
	).Return(addressIter(items...)).Once()
}

// expectFreshAddress configures the count-one batch allocation NewAddress
// performs when the selected branch has no unused child.
func expectFreshAddress(t *testing.T, w *Wallet, deps *mockWalletDeps,
	selector AccountSelector, internal bool,
	stored db.AddressInfo) *mock.Call {

	t.Helper()

	return deps.store.On("NewDerivedAddresses", mock.Anything,
		w.newDerivedAddressParams(selector, internal), uint32(1),
	).Return([]db.AddressInfo{stored}, nil).Once()
}

// storeChild derives one real BIP0084 account child and returns its address
// with the matching store row, so metadata conversion sees real key material.
func storeChild(t *testing.T, key *hdkeychain.ExtendedKey,
	addrType db.AddressType, internal bool,
	index uint32) (address.Address, db.AddressInfo) {

	t.Helper()

	var branch uint32
	if internal {
		branch = 1
	}

	addr, script, pubKey := expectedStoreAddress(
		t, key, addrType, branch, index,
	)
	number := uint32(0)

	return addr, db.AddressInfo{
		AddrType:          addrType,
		AccountNumber:     &number,
		KeyScope:          db.KeyScope(waddrmgr.KeyScopeBIP0084),
		HasDerivationPath: true,
		Branch:            branch,
		Index:             index,
		ScriptPubKey:      script,
		PubKey:            pubKey,
	}
}

// expectStoreNewAddress configures mock expectations for deriving an address.
func expectStoreNewAddress(t *testing.T, w *Wallet, deps *mockWalletDeps,
	accountName string, scope waddrmgr.KeyScope, change bool,
	addr address.Address) {

	t.Helper()

	// Public receiving requires the Store to reject excluded accounts before
	// allocation and forward the caller context; success requires watching.
	deps.store.On(
		"NewDerivedAddress", t.Context(),
		db.NewDerivedAddressParams{
			WalletID:         w.id,
			AccountName:      accountName,
			Scope:            db.KeyScope(scope),
			Change:           change,
			RequireChainSync: true,
		},
	).Return(addressInfoFromAddr(t, addr), nil).Once()
	deps.chain.On("NotifyReceived", []address.Address{addr}).Return(nil).Once()
}

// expectSignerAddressInfo mocks Store.GetAddress to return a minimal
// AddressInfo for tests that exercise the wallet's address-info read
// path. No call-count constraint — the same address may be looked up
// multiple times (input decoration + change output info).
func expectSignerAddressInfo(t *testing.T, w *Wallet, deps *mockWalletDeps,
	addr address.Address, addrType db.AddressType,
	internal, imported bool, pubKey *btcec.PublicKey) {

	t.Helper()
	expectSignerAddressInfoWithKeyScope(
		t, w, deps, addr, addrType, internal, imported, pubKey,
		waddrmgr.KeyScope{},
	)
}

// expectSignerDerivedAddressInfo mocks Store.GetAddress to return address
// metadata with a usable derivation scope for PSBT derivation tests. The
// helper hard-codes internal=false because every PSBT derivation test
// asserts against an external-branch address.
func expectSignerDerivedAddressInfo(t *testing.T, w *Wallet,
	deps *mockWalletDeps, addr address.Address, addrType db.AddressType,
	pubKey *btcec.PublicKey) {

	t.Helper()

	walletAddrType, err := addresstype.ToWallet(addrType, false)
	require.NoError(t, err)

	keyScope, err := walletAddrType.KeyScope()
	require.NoError(t, err)

	expectSignerAddressInfoWithKeyScope(
		t, w, deps, addr, addrType, false, false, pubKey, keyScope,
	)
}

// expectSignerAddressInfoWithKeyScope mocks Store.GetAddress with the provided
// derivation scope. A zero key scope represents missing derivation metadata.
func expectSignerAddressInfoWithKeyScope(t *testing.T, w *Wallet,
	deps *mockWalletDeps, addr address.Address, addrType db.AddressType,
	internal, imported bool, pubKey *btcec.PublicKey,
	keyScope waddrmgr.KeyScope) {

	t.Helper()

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	var branch uint32
	if internal {
		branch = 1
	}

	var pubKeyBytes []byte
	if pubKey != nil {
		pubKeyBytes = pubKey.SerializeCompressed()
	}

	storeInfo := &db.AddressInfo{
		ScriptPubKey:      pkScript,
		AddrType:          addrType,
		IsImported:        imported,
		HasDerivationPath: !imported,
		Branch:            branch,
		PubKey:            pubKeyBytes,
	}
	if !imported {
		accountNumber := uint32(0)
		storeInfo.AccountNumber = &accountNumber
	}

	if keyScope != (waddrmgr.KeyScope{}) {
		storeInfo.KeyScope = db.KeyScope(keyScope)
		storeInfo.MasterKeyFingerprint = 1
	}

	deps.store.On(
		"GetAddress", mock.Anything,
		db.GetAddressQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScript,
		},
	).Return(storeInfo, nil)
}

// addressIter returns an address iterator over static test records.
func addressIter(items ...db.AddressInfo) iter.Seq2[db.AddressInfo, error] {
	return func(yield func(db.AddressInfo, error) bool) {
		for i := range items {
			if !yield(items[i], nil) {
				return
			}
		}
	}
}

// expectStoreAddressInfo configures mock expectations for address lookup.
func expectStoreAddressInfo(t *testing.T, w *Wallet, deps *mockWalletDeps,
	addr address.Address, info *db.AddressInfo) {

	t.Helper()

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	deps.store.On(
		"GetAddress", mock.Anything,
		db.GetAddressQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScript,
		},
	).Return(info, nil).Once()
}

// TestNewAddress verifies that an empty branch allocates exactly one child for
// name and number selectors, and that the returned metadata is truthful for
// the account's stored address schema and the requested branch.
func TestNewAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		scope        waddrmgr.KeyScope
		accountName  string
		numbered     bool
		internal     bool
		storeType    db.AddressType
		wantType     waddrmgr.AddressType
		wantAddrType address.Address
	}{
		{
			name:         "external p2wkh by name",
			scope:        waddrmgr.KeyScopeBIP0084,
			accountName:  waddrmgr.DefaultAccountName,
			storeType:    db.WitnessPubKey,
			wantType:     waddrmgr.WitnessPubKey,
			wantAddrType: &address.AddressWitnessPubKeyHash{},
		},
		{
			name:         "internal p2wkh by number",
			scope:        waddrmgr.KeyScopeBIP0084,
			accountName:  waddrmgr.DefaultAccountName,
			numbered:     true,
			internal:     true,
			storeType:    db.WitnessPubKey,
			wantType:     waddrmgr.WitnessPubKey,
			wantAddrType: &address.AddressWitnessPubKeyHash{},
		},
		{
			name:         "renamed account zero by number",
			scope:        waddrmgr.KeyScopeBIP0084,
			accountName:  "renamed",
			numbered:     true,
			storeType:    db.WitnessPubKey,
			wantType:     waddrmgr.WitnessPubKey,
			wantAddrType: &address.AddressWitnessPubKeyHash{},
		},
		{
			name:         "external np2wkh",
			scope:        waddrmgr.KeyScopeBIP0049Plus,
			accountName:  waddrmgr.DefaultAccountName,
			storeType:    db.NestedWitnessPubKey,
			wantType:     waddrmgr.NestedWitnessPubKey,
			wantAddrType: &address.AddressScriptHash{},
		},
		{
			name:         "external p2tr",
			scope:        waddrmgr.KeyScopeBIP0086,
			accountName:  waddrmgr.DefaultAccountName,
			storeType:    db.TaprootPubKey,
			wantType:     waddrmgr.TaprootPubKey,
			wantAddrType: &address.AddressTaproot{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: resolve the selected account, scan only used or
			// other-branch children, then allocate exactly one child
			// through the batch path and register it on the lifetime.
			w, deps := createStartedWalletWithMocks(t)

			selector := NewAccountSelectorByName(tc.scope, tc.accountName)
			if tc.numbered {
				selector = NewAccountSelectorByNumber(tc.scope, 0)
			}

			number := uint32(0)
			expectReceivingAccount(t, w, deps, selector, &db.AccountInfo{
				AccountName:   tc.accountName,
				AccountNumber: &number,
			})

			key := storeDerivationAccountPubKey(t)
			_, used := storeChild(t, key, tc.storeType, tc.internal, 0)
			used.IsUsed = true
			_, otherBranch := storeChild(
				t, key, tc.storeType, !tc.internal, 0,
			)
			expectAddressScan(
				t, w, deps, tc.accountName, tc.scope, used, otherBranch,
			)

			addr, stored := storeChild(
				t, key, tc.storeType, tc.internal, 1,
			)
			stored.KeyScope = db.KeyScope(tc.scope)
			expectFreshAddress(t, w, deps, selector, tc.internal, stored)
			deps.chain.On(
				"WatchAddrsFromTip", w.lifetimeCtx,
				[]address.Address{addr},
			).Return(nil).Once()

			// Act: request a receiving address on the empty branch.
			info, err := w.NewAddress(t.Context(), selector, tc.internal)

			// Assert: the allocated child is returned with metadata taken
			// from its stored schema and branch. Strict mocks prove one
			// lookup, one scan, one allocation, and one registration.
			require.NoError(t, err)
			require.Equal(t, addr, info.Addr)
			require.IsType(t, tc.wantAddrType, info.Addr)
			require.Equal(t, tc.wantType, info.AddrType)
			require.Equal(t, tc.internal, info.Internal)
			require.False(t, info.Imported)
			require.NotNil(t, info.Derivation)
			require.Equal(t, tc.scope, info.Derivation.KeyScope)
			require.Equal(t, stored.Branch, info.Derivation.Branch)
			require.Equal(t, uint32(1), info.Derivation.Index)
			deps.store.AssertExpectations(t)
			deps.chain.AssertExpectations(t)
		})
	}
}

// TestNewAddressRejectsBeforeDependencies verifies malformed selectors and the
// reserved raw-import bucket are refused before admission or any lookup.
func TestNewAddressRejectsBeforeDependencies(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		selector AccountSelector
		wantErr  error
	}{
		{
			name:     "missing selector",
			selector: AccountSelector{},
			wantErr:  ErrInvalidParam,
		},
		{
			name: "reserved imported account",
			selector: NewAccountSelectorByName(
				waddrmgr.KeyScopeBIP0084,
				waddrmgr.ImportedAddrAccountName,
			),
			wantErr: ErrImportedAccountNoAddrGen,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: leave strict Store and chain mocks without
			// expectations so any dependency access fails the test.
			w, _ := createTestWalletWithMocks(t)
			startLoadedWalletForTest(t, w)

			// Act: submit the invalid selector.
			info, err := w.NewAddress(t.Context(), tc.selector, false)

			// Assert: the call is refused with a zero result.
			require.ErrorIs(t, err, tc.wantErr)
			require.Zero(t, info)
		})
	}
}

// TestNewAddressMapsAccountLookup verifies account resolution failures use the
// public account errors and that a numbered selector resolving to the
// raw-import bucket is refused before any scan or allocation.
func TestNewAddressMapsAccountLookup(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		lookupErr error
		account   *db.AccountInfo
		wantErr   error
	}{
		{
			name:      "missing account",
			lookupErr: db.ErrAccountNotFound,
			wantErr:   ErrAccountNotFound,
		},
		{
			name:      "missing scope",
			lookupErr: db.ErrKeyScopeNotFound,
			wantErr:   ErrAccountNotFound,
		},
		{
			name: "raw import bucket",
			account: &db.AccountInfo{
				AccountName: waddrmgr.ImportedAddrAccountName,
			},
			wantErr: ErrImportedAccountNoAddrGen,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: fail or redirect only the account lookup; strict
			// mocks forbid scans, allocation, and registration.
			w, deps := createStartedWalletWithMocks(t)
			selector := NewAccountSelectorByNumber(
				waddrmgr.KeyScopeBIP0084, 7,
			)
			expectReceivingAccount(t, w, deps, selector, tc.account).
				Return(tc.account, tc.lookupErr)

			// Act: request a receiving address for the selector.
			info, err := w.NewAddress(t.Context(), selector, false)

			// Assert: expose only the wallet-owned error identity.
			require.ErrorIs(t, err, tc.wantErr)
			require.NotErrorIs(t, err, db.ErrAccountNotFound)
			require.Zero(t, info)
			deps.store.AssertExpectations(t)
		})
	}
}

// TestNewAddressReusesOldestUnused verifies SQL selection returns the unused
// child with the lowest index on the exact branch even when row order differs
// from index order, and never allocates while such a child exists.
func TestNewAddressReusesOldestUnused(t *testing.T) {
	t.Parallel()

	key := storeDerivationAccountPubKey(t)
	child := func(internal bool, index uint32, used bool) db.AddressInfo {
		_, info := storeChild(t, key, db.WitnessPubKey, internal, index)
		info.IsUsed = used

		return info
	}
	rawImport := db.AddressInfo{
		AddrType:     db.WitnessPubKey,
		ScriptPubKey: child(false, 99, false).ScriptPubKey,
	}

	// Many rows in descending index order place the oldest child on the
	// final page, so selection must inspect every row of the scan.
	var manyRows []db.AddressInfo
	for index := uint32(2*addressManagerPageLimit + 1); index > 0; index-- {
		manyRows = append(manyRows, child(false, index-1, false))
	}

	testCases := []struct {
		name      string
		internal  bool
		rows      []db.AddressInfo
		wantIndex uint32
	}{
		{
			name:     "lower external hole wins over row order",
			internal: false,
			rows: []db.AddressInfo{
				child(false, 0, true), child(false, 5, false),
				child(true, 1, false), rawImport,
				child(false, 2, false), child(false, 3, false),
			},
			wantIndex: 2,
		},
		{
			name:     "used child rotates to next oldest",
			internal: false,
			rows: []db.AddressInfo{
				child(false, 0, true), child(false, 5, false),
				child(true, 1, false), child(false, 2, true),
				child(false, 3, false),
			},
			wantIndex: 3,
		},
		{
			name:     "internal branch is isolated",
			internal: true,
			rows: []db.AddressInfo{
				child(false, 0, false), child(true, 4, false),
				child(true, 1, false), child(true, 0, true),
			},
			wantIndex: 1,
		},
		{
			name:      "oldest child on last page",
			rows:      manyRows,
			wantIndex: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: scan the same stored rows for two calls. Strict
			// mocks allow no allocation, only two registrations.
			w, deps := createStartedWalletWithMocks(t)
			name := waddrmgr.DefaultAccountName
			selector := NewAccountSelectorByName(
				waddrmgr.KeyScopeBIP0084, name,
			)

			wantAddr, _ := storeChild(
				t, key, db.WitnessPubKey, tc.internal, tc.wantIndex,
			)
			for range 2 {
				expectReceivingAccount(
					t, w, deps, selector,
					&db.AccountInfo{AccountName: name},
				)
				expectAddressScan(
					t, w, deps, name, waddrmgr.KeyScopeBIP0084,
					tc.rows...,
				)
			}

			deps.chain.On(
				"WatchAddrsFromTip", w.lifetimeCtx,
				[]address.Address{wantAddr},
			).Return(nil).Twice()

			// Act: request the same branch twice.
			first, err := w.NewAddress(t.Context(), selector, tc.internal)
			require.NoError(t, err)
			second, err := w.NewAddress(t.Context(), selector, tc.internal)
			require.NoError(t, err)

			// Assert: both calls reuse the lowest unused child.
			require.Equal(t, wantAddr, first.Addr)
			require.Equal(t, first, second)
			require.Equal(t, tc.internal, first.Internal)
			require.Equal(t, tc.wantIndex, first.Derivation.Index)
			deps.store.AssertExpectations(t)
			deps.chain.AssertExpectations(t)
		})
	}
}

// TestNewAddressImportedXpubChild verifies an imported-xpub account child is
// reusable and keeps the public imported-xpub metadata semantics.
func TestNewAddressImportedXpubChild(t *testing.T) {
	t.Parallel()

	// Arrange: an imported xpub child has a derivation path but no wallet
	// account number.
	w, deps := createStartedWalletWithMocks(t)
	name := accountIdentityTestName
	selector := NewAccountSelectorByName(waddrmgr.KeyScopeBIP0084, name)
	expectReceivingAccount(t, w, deps, selector, &db.AccountInfo{
		AccountName: name,
		IsImported:  true,
	})

	addr, stored := storeChild(
		t, storeDerivationAccountPubKey(t), db.WitnessPubKey, false, 0,
	)
	stored.IsImported = true
	stored.AccountNumber = nil
	expectAddressScan(t, w, deps, name, waddrmgr.KeyScopeBIP0084, stored)
	deps.chain.On(
		"WatchAddrsFromTip", w.lifetimeCtx, []address.Address{addr},
	).Return(nil).Once()

	// Act: request a receiving address from the imported xpub account.
	info, err := w.NewAddress(t.Context(), selector, false)

	// Assert: the child is returned without a wallet BIP44 derivation.
	require.NoError(t, err)
	require.Equal(t, addr, info.Addr)
	require.False(t, info.Imported)
	require.Nil(t, info.Derivation)
	deps.store.AssertExpectations(t)
	deps.chain.AssertExpectations(t)
}

// TestNewAddressNoChainSync verifies receiving rejection for populated and
// empty NoChainSync accounts on both branches before any scan, allocation, or
// registration.
func TestNewAddressNoChainSync(t *testing.T) {
	t.Parallel()

	accountName := "key-only"

	testCases := []struct {
		name     string
		internal bool
		keys     uint32
	}{
		{name: "external populated", keys: 3},
		{name: "external empty"},
		{name: "internal populated", internal: true, keys: 3},
		{name: "internal empty", internal: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: only the account lookup is permitted.
			w, deps := createStartedWalletWithMocks(t)
			selector := NewAccountSelectorByName(
				waddrmgr.KeyScopeBIP0084, accountName,
			)
			expectReceivingAccount(t, w, deps, selector, &db.AccountInfo{
				AccountName:      accountName,
				NoChainSync:      true,
				ExternalKeyCount: tc.keys,
				InternalKeyCount: tc.keys,
			})

			// Act: request receiving from the excluded account.
			info, err := w.NewAddress(t.Context(), selector, tc.internal)

			// Assert: reject with the public diagnostic and no address;
			// strict mocks forbid scans, allocation and watching.
			require.ErrorIs(t, err, ErrAccountOperationUnsupported)
			require.NotErrorIs(t, err, db.ErrAccountOperationUnsupported)
			require.ErrorContains(t, err, accountName)
			require.ErrorContains(t, err, "chain synchronization disabled")
			require.Zero(t, info)
			deps.store.AssertExpectations(t)
			deps.chain.AssertExpectations(t)
		})
	}
}

// TestNewAddressMapsFallbackFailure verifies an empty-branch allocation keeps
// the batch path's error identities and never registers a watch.
func TestNewAddressMapsFallbackFailure(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		storeErr error
		wantErr  error
	}{
		{
			name:     "excluded account",
			storeErr: db.ErrAccountOperationUnsupported,
			wantErr:  ErrAccountOperationUnsupported,
		},
		{
			name:     "terminal exhaustion",
			storeErr: db.ErrMaxAddressIndexReached,
			wantErr:  ErrAddressDerivationExhausted,
		},
		{
			name: "ambiguous canceled commit",
			storeErr: errors.Join(
				dbruntime.ErrAmbiguousTxCommit, context.Canceled,
			),
			wantErr: ErrIndeterminateCommit,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: an empty scan reaches exactly one failing
			// allocation; no chain expectation is registered.
			w, deps := createStartedWalletWithMocks(t)
			name := "batch"
			selector := NewAccountSelectorByName(
				waddrmgr.KeyScopeBIP0084, name,
			)
			expectReceivingAccount(t, w, deps, selector,
				&db.AccountInfo{AccountName: name})
			expectAddressScan(t, w, deps, name, waddrmgr.KeyScopeBIP0084)
			deps.store.On("NewDerivedAddresses", mock.Anything,
				w.newDerivedAddressParams(selector, false), uint32(1),
			).Return(nil, tc.storeErr).Once()

			// Act: request a receiving address on the empty branch.
			info, err := w.NewAddress(t.Context(), selector, false)

			// Assert: only the wallet-owned failure escapes.
			require.ErrorIs(t, err, tc.wantErr)
			require.NotErrorIs(t, err, context.Canceled)
			require.NotErrorIs(t, err, dbruntime.ErrAmbiguousTxCommit)
			require.Zero(t, info)
			deps.store.AssertExpectations(t)
			deps.chain.AssertExpectations(t)
		})
	}
}

// TestNewAddressScanFailure verifies an iteration error is returned instead of
// being treated as an empty branch that needs allocation.
func TestNewAddressScanFailure(t *testing.T) {
	t.Parallel()

	// Arrange: the scan fails; strict mocks forbid allocation.
	w, deps := createStartedWalletWithMocks(t)
	name := waddrmgr.DefaultAccountName
	selector := NewAccountSelectorByName(waddrmgr.KeyScopeBIP0084, name)
	expectReceivingAccount(t, w, deps, selector,
		&db.AccountInfo{AccountName: name})
	expectAddressScan(t, w, deps, name, waddrmgr.KeyScopeBIP0084).
		Return(iter.Seq2[db.AddressInfo, error](
			func(yield func(db.AddressInfo, error) bool) {
				yield(db.AddressInfo{}, errDBMock)
			},
		))

	// Act: request a receiving address.
	info, err := w.NewAddress(t.Context(), selector, false)

	// Assert: the scan error escapes with no address.
	require.ErrorIs(t, err, errDBMock)
	require.Zero(t, info)
	deps.store.AssertExpectations(t)
}

// TestNewAddressWatchFailureReusesChild verifies failed registration returns
// no address and that a retry registers the same committed child instead of
// allocating a replacement.
func TestNewAddressWatchFailureReusesChild(t *testing.T) {
	t.Parallel()

	// Arrange: the first call allocates on an empty branch and fails to
	// register; the retry then scans the committed child.
	w, deps := createStartedWalletWithMocks(t)
	name := waddrmgr.DefaultAccountName
	selector := NewAccountSelectorByName(waddrmgr.KeyScopeBIP0084, name)
	addr, stored := storeChild(
		t, storeDerivationAccountPubKey(t), db.WitnessPubKey, false, 0,
	)

	for range 2 {
		expectReceivingAccount(t, w, deps, selector,
			&db.AccountInfo{AccountName: name})
	}

	expectAddressScan(t, w, deps, name, waddrmgr.KeyScopeBIP0084)
	expectFreshAddress(t, w, deps, selector, false, stored)
	expectAddressScan(t, w, deps, name, waddrmgr.KeyScopeBIP0084, stored)
	deps.chain.On(
		"WatchAddrsFromTip", w.lifetimeCtx, []address.Address{addr},
	).Return(errDBMock).Once()
	deps.chain.On(
		"WatchAddrsFromTip", w.lifetimeCtx, []address.Address{addr},
	).Return(nil).Once()

	// Act: fail the first registration, then retry.
	failed, failErr := w.NewAddress(t.Context(), selector, false)
	retried, retryErr := w.NewAddress(t.Context(), selector, false)

	// Assert: the failure exposes no address, and the retry returns the
	// same child. Strict mocks prove exactly one allocation.
	require.ErrorIs(t, failErr, errDBMock)
	require.Zero(t, failed)
	require.NoError(t, retryErr)
	require.Equal(t, addr, retried.Addr)
	deps.store.AssertExpectations(t)
	deps.chain.AssertExpectations(t)
}

// TestNewAddressCancellation verifies a canceled caller causes no dependency
// work, and that cancellation after commit still finishes registration while
// leaving the committed child for the next call.
func TestNewAddressCancellation(t *testing.T) {
	t.Parallel()

	t.Run("before work", func(t *testing.T) {
		t.Parallel()

		// Arrange: strict mocks without expectations forbid any lookup.
		w, deps := createStartedWalletWithMocks(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		// Act: request an address with an already-canceled context.
		info, err := w.NewAddress(
			ctx, NewAccountSelectorByName(
				waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountName,
			), false,
		)

		// Assert: cancellation is returned before dependency access.
		require.ErrorIs(t, err, context.Canceled)
		require.Zero(t, info)
		deps.store.AssertExpectations(t)
	})

	t.Run("after commit", func(t *testing.T) {
		t.Parallel()

		// Arrange: cancel the caller when the allocation commits. The
		// joined registration still runs on the live wallet lifetime.
		w, deps := createStartedWalletWithMocks(t)
		name := waddrmgr.DefaultAccountName
		selector := NewAccountSelectorByName(
			waddrmgr.KeyScopeBIP0084, name,
		)
		addr, stored := storeChild(
			t, storeDerivationAccountPubKey(t), db.WitnessPubKey,
			false, 0,
		)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		for range 2 {
			expectReceivingAccount(t, w, deps, selector,
				&db.AccountInfo{AccountName: name})
		}

		expectAddressScan(t, w, deps, name, waddrmgr.KeyScopeBIP0084)
		expectFreshAddress(t, w, deps, selector, false, stored).
			Run(func(mock.Arguments) { cancel() })
		expectAddressScan(
			t, w, deps, name, waddrmgr.KeyScopeBIP0084, stored,
		)
		deps.chain.On(
			"WatchAddrsFromTip", w.lifetimeCtx, []address.Address{addr},
		).Run(func(mock.Arguments) {
			require.NoError(t, w.lifetimeCtx.Err())
		}).Return(nil).Twice()

		// Act: cancel during the first call, then retry.
		canceled, cancelErr := w.NewAddress(ctx, selector, false)
		retried, retryErr := w.NewAddress(t.Context(), selector, false)

		// Assert: the canceled call exposes nothing, yet the retry
		// returns the same committed child without another allocation.
		require.ErrorIs(t, cancelErr, context.Canceled)
		require.Zero(t, canceled)
		require.NoError(t, retryErr)
		require.Equal(t, addr, retried.Addr)
		deps.store.AssertExpectations(t)
		deps.chain.AssertExpectations(t)
	})
}

// TestNewAddressConcurrentEmptyBranch verifies callers that race the first
// caller's empty-branch lookup share its single allocation instead of each
// allocating a child.
func TestNewAddressConcurrentEmptyBranch(t *testing.T) {
	t.Parallel()

	const competitors = 8

	// Arrange: the first scan has already read the empty branch when it
	// blocks until every caller has resolved the account, so competitors
	// contend while its lookup is still in progress.
	w, deps := createStartedWalletWithMocks(t)
	name := waddrmgr.DefaultAccountName
	selector := NewAccountSelectorByName(waddrmgr.KeyScopeBIP0084, name)
	addr, stored := storeChild(
		t, storeDerivationAccountPubKey(t), db.WitnessPubKey, false, 0,
	)

	var lookups sync.WaitGroup
	lookups.Add(competitors + 1)
	expectReceivingAccount(t, w, deps, selector,
		&db.AccountInfo{AccountName: name},
	).Run(func(mock.Arguments) { lookups.Done() }).Times(competitors + 1)

	firstScanning := make(chan struct{})
	expectAddressScan(t, w, deps, name, waddrmgr.KeyScopeBIP0084).
		Run(func(mock.Arguments) {
			close(firstScanning)
			lookups.Wait()
		})

	// Later scans see the branch as it is when they iterate, so a scan
	// that runs before the allocation commits finds it empty.
	var committed atomic.Bool
	expectAddressScan(t, w, deps, name, waddrmgr.KeyScopeBIP0084).
		Return(iter.Seq2[db.AddressInfo, error](
			func(yield func(db.AddressInfo, error) bool) {
				if committed.Load() {
					yield(stored, nil)
				}
			},
		)).Times(competitors)

	deps.store.On("NewDerivedAddresses", mock.Anything,
		w.newDerivedAddressParams(selector, false), uint32(1),
	).Run(func(mock.Arguments) {
		committed.Store(true)
	}).Return([]db.AddressInfo{stored}, nil)
	deps.chain.On(
		"WatchAddrsFromTip", w.lifetimeCtx, []address.Address{addr},
	).Return(nil).Times(competitors + 1)

	results := make(chan addressInfoResp, competitors+1)
	request := func() {
		info, err := w.NewAddress(t.Context(), selector, false)
		results <- addressInfoResp{info: info, err: err}
	}

	// Act: start the competitors once the first lookup is in progress.
	go request()

	<-firstScanning

	for range competitors {
		go request()
	}

	// Assert: every caller returns the child of the only allocation.
	for range competitors + 1 {
		result := <-results
		require.NoError(t, result.err)
		require.Equal(t, addr, result.info.Addr)
	}

	// The mock returns the same child for every allocation, so equal
	// addresses alone cannot reveal a second allocation; count them.
	deps.store.AssertNumberOfCalls(t, "NewDerivedAddresses", 1)
}

// TestNewAddressBlockedWatch verifies a pending registration withholds the
// address from the caller and that shutdown unblocks the joined watch.
func TestNewAddressBlockedWatch(t *testing.T) {
	t.Parallel()

	// Arrange: select an unused child whose registration waits for the
	// wallet lifetime to end.
	w, deps := createTestWalletWithMocks(t)
	startLoadedWalletForTest(t, w)

	name := waddrmgr.DefaultAccountName
	selector := NewAccountSelectorByName(waddrmgr.KeyScopeBIP0084, name)
	addr, stored := storeChild(
		t, storeDerivationAccountPubKey(t), db.WitnessPubKey, false, 0,
	)
	expectReceivingAccount(t, w, deps, selector,
		&db.AccountInfo{AccountName: name})
	expectAddressScan(t, w, deps, name, waddrmgr.KeyScopeBIP0084, stored)

	enteredChan := make(chan struct{})
	deps.chain.On(
		"WatchAddrsFromTip", w.lifetimeCtx, []address.Address{addr},
	).Run(func(args mock.Arguments) {
		ctx, _ := args.Get(0).(context.Context)
		close(enteredChan)

		<-ctx.Done()
	}).Return(context.Canceled).Once()
	deps.vault.On("Lock").Return().Once()

	resultChan := make(chan addressInfoResp, 1)
	go func() {
		info, err := w.NewAddress(t.Context(), selector, false)
		resultChan <- addressInfoResp{info: info, err: err}
	}()

	<-enteredChan

	// Assert: the handler is inside registration, so no result exists.
	select {
	case result := <-resultChan:
		t.Fatalf("address delivered before registration: %v", result)
	default:
	}

	// Act: stop the wallet, canceling the lifetime the watch waits on.
	require.NoError(t, w.stop())

	// Assert: the unblocked watch fails the call without an address.
	result := <-resultChan
	require.ErrorIs(t, result.err, context.Canceled)
	require.Zero(t, result.info)
}

// TestGetUnusedAddress tests the GetUnusedAddress method to ensure it
// correctly returns the earliest unused address.
func TestGetUnusedAddress(t *testing.T) {
	t.Parallel()

	const importedXpubName = "imported-xpub"

	// Arrange: supply stored derivation records so selection can use their
	// branch and local use metadata directly. Strict mocks permit no account
	// lookup; each selected child must be registered before it is returned.
	w, deps := createStartedWalletWithMocks(t)

	firstAddr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope(scope)
	defaultName := waddrmgr.DefaultAccountName
	req, err := addressPageRequest()
	require.NoError(t, err)

	deps.store.On(
		"IterAddresses", mock.Anything,
		db.ListAddressesQuery{
			WalletID:    w.id,
			AccountName: &defaultName,
			Scope:       &dbScope,
			Page:        req,
		},
	).Return(addressIter(*derivedAddressInfoFromAddr(
		t, firstAddr, db.WitnessPubKey, defaultName, scope, false, 0, 0,
		nil,
	))).Once()

	deps.chain.On(
		"WatchAddrsFromTip", mock.Anything, []address.Address{firstAddr},
	).Return(nil).Once()

	// Act: select the oldest external address not locally recorded as used.
	unusedAddr, err := w.GetUnusedAddress(
		t.Context(), defaultName, waddrmgr.WitnessPubKey, false,
	)

	// Assert: receiving keeps the first unused address instead of allocating.
	require.NoError(t, err)
	require.Equal(t, firstAddr.String(), unusedAddr.String())

	// Arrange: an imported xpub child has a derivation path, so its local
	// use metadata supports the same stored-address selection.
	importedXpubAddr, _ := address.NewAddressWitnessPubKeyHash(
		[]byte{
			31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
			41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
		}, w.cfg.ChainParams,
	)
	importedXpubInfo := derivedAddressInfoFromAddr(
		t, importedXpubAddr, db.WitnessPubKey, importedXpubName, scope,
		false, 0, 0, nil,
	)
	importedXpubInfo.IsImported = true
	importedXpubInfo.AccountNumber = nil
	importedXpubQueryName := importedXpubName

	deps.store.On(
		"IterAddresses", mock.Anything,
		db.ListAddressesQuery{
			WalletID:    w.id,
			AccountName: &importedXpubQueryName,
			Scope:       &dbScope,
			Page:        req,
		},
	).Return(addressIter(*importedXpubInfo)).Once()

	deps.chain.On(
		"WatchAddrsFromTip", mock.Anything, []address.Address{importedXpubAddr},
	).Return(nil).Once()

	// Act: select a receiving address from the imported xpub account.
	unusedImportedAddr, err := w.GetUnusedAddress(
		t.Context(), importedXpubName, waddrmgr.WitnessPubKey, false,
	)

	// Assert: the existing unused xpub child remains usable without allocation.
	require.NoError(t, err)
	require.Equal(t, importedXpubAddr.String(), unusedImportedAddr.String())

	// Arrange: make the stored child used so ordinary receiving must allocate
	// its next child. Strict mocks permit only the scan, allocation, and watch.
	usedFirstAddr := derivedAddressInfoFromAddr(
		t, firstAddr, db.WitnessPubKey, defaultName, scope, false, 0, 0, nil,
	)
	usedFirstAddr.IsUsed = true
	deps.store.On("IterAddresses", t.Context(), db.ListAddressesQuery{
		WalletID:    w.id,
		AccountName: &defaultName,
		Scope:       &dbScope,
		Page:        req,
	}).Return(addressIter(*usedFirstAddr)).Once()

	nextAddrVal, err := address.NewAddressWitnessPubKeyHash(
		[]byte{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		}, w.cfg.ChainParams,
	)
	require.NoError(t, err)
	expectStoreNewAddress(t, w, deps, defaultName, scope, false, nextAddrVal)

	// Act: exhaust the used-address scan and enter the existing NewAddress
	// fallback, which must make a receiving allocation request.
	nextAddr, err := w.GetUnusedAddress(
		t.Context(), defaultName, waddrmgr.WitnessPubKey, false,
	)

	// Assert: ordinary fallback still returns the new address and registers it.
	require.NoError(t, err)
	require.Equal(t, nextAddrVal, nextAddr)

	// Arrange: provide an unused internal child to preserve change selection.
	changeAddrVal, _ := address.NewAddressWitnessPubKeyHash(
		[]byte{
			21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
			31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		}, w.cfg.ChainParams,
	)

	deps.store.On(
		"IterAddresses", mock.Anything,
		db.ListAddressesQuery{
			WalletID:    w.id,
			AccountName: &defaultName,
			Scope:       &dbScope,
			Page:        req,
		},
	).Return(addressIter(*derivedAddressInfoFromAddr(
		t, changeAddrVal, db.WitnessPubKey, defaultName, scope, true, 0,
		0, nil,
	))).Once()

	deps.chain.On(
		"WatchAddrsFromTip", mock.Anything, []address.Address{changeAddrVal},
	).Return(nil).Once()

	// Act: request the unused child on the change branch of the same account.
	unusedChangeAddr, err := w.GetUnusedAddress(
		t.Context(), defaultName, waddrmgr.WitnessPubKey, true,
	)

	// Assert: selection returns the requested internal child, and every
	// expected scan, fallback allocation, and notification occurred.
	require.NoError(t, err)
	require.Equal(t, changeAddrVal.String(), unusedChangeAddr.String())
}

// TestLiveWatchUnusedAddressError verifies that failed registration returns
// an error without exposing the selected receiving address.
func TestLiveWatchUnusedAddressError(t *testing.T) {
	t.Parallel()

	// Arrange: Select a stored child but reject its live registration. The
	// shared fixture owns mock assertions and Wallet shutdown.
	w, deps := createStartedWalletWithMocks(t)

	addr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	require.NoError(t, err)
	deps.store.On("IterAddresses", mock.Anything, mock.Anything).
		Return(addressIter(*derivedAddressInfoFromAddr(
			t, addr, db.WitnessPubKey, waddrmgr.DefaultAccountName,
			waddrmgr.KeyScopeBIP0084, false, 1, 0, nil,
		))).Once()

	deps.chain.On(
		"WatchAddrsFromTip", mock.Anything, []address.Address{addr},
	).Return(errDBMock).Once()

	// Act: Request the stored child through the receiving API so its
	// registration failure is observed by the caller.
	got, err := w.GetUnusedAddress(
		t.Context(), waddrmgr.DefaultAccountName,
		waddrmgr.WitnessPubKey, false,
	)

	// Assert: The registration error rejects the receiving result rather
	// than returning an address whose live watch was not installed.
	require.ErrorIs(t, err, errDBMock)
	require.Nil(t, got)
}

// TestGetUnusedAddressNoChainSync verifies receiving rejection both when a
// stored child exposes account policy and when an empty account needs
// allocation.
func TestGetUnusedAddressNoChainSync(t *testing.T) {
	t.Parallel()

	accountName := "key-only"
	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope(scope)
	req, err := addressPageRequest()
	require.NoError(t, err)

	// Both receiving branches obey the same policy; each lookup path below
	// has independent mocks so its permitted operations remain explicit.
	testCases := []struct {
		name   string
		change bool
	}{
		{
			name:   "external",
			change: false,
		},
		{
			name:   "internal",
			change: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name+" stored child", func(t *testing.T) {
			t.Parallel()

			// Arrange: return an unused child on the requested branch
			// that would be selected without the stored policy guard.
			w, deps := createStartedWalletWithMocks(t)
			child, err := address.NewAddressWitnessPubKeyHash(
				make([]byte, 20), w.cfg.ChainParams,
			)
			require.NoError(t, err)
			info := derivedAddressInfoFromAddr(
				t, child, db.WitnessPubKey, accountName, scope,
				tc.change, 0, 0, nil,
			)
			info.NoChainSync = true
			deps.store.On("IterAddresses", t.Context(), db.ListAddressesQuery{
				WalletID:    w.id,
				AccountName: &accountName,
				Scope:       &dbScope,
				Page:        req,
			}).Return(addressIter(*info)).Once()

			// Act: request receiving reuse from the excluded account.
			addr, err := w.GetUnusedAddress(
				t.Context(), accountName, waddrmgr.WitnessPubKey, tc.change,
			)

			// Assert: reject with the public diagnostic and no address;
			// strict mocks forbid allocation, account reads and watching.
			require.ErrorIs(t, err, ErrAccountOperationUnsupported)
			require.NotErrorIs(t, err, db.ErrAccountOperationUnsupported)
			require.ErrorContains(t, err, accountName)
			require.ErrorContains(t, err, "chain synchronization disabled")
			require.Nil(t, addr)
			deps.store.AssertExpectations(t)
			deps.chain.AssertExpectations(t)
		})

		t.Run(tc.name+" empty account", func(t *testing.T) {
			t.Parallel()

			// Arrange: an empty scan reaches NewAddress, whose existing
			// allocation call refuses before consuming a child index.
			w, deps := createStartedWalletWithMocks(t)
			deps.store.On("IterAddresses", t.Context(), db.ListAddressesQuery{
				WalletID:    w.id,
				AccountName: &accountName,
				Scope:       &dbScope,
				Page:        req,
			}).Return(addressIter()).Once()
			deps.store.On("NewDerivedAddress", t.Context(),
				db.NewDerivedAddressParams{
					WalletID:         w.id,
					AccountName:      accountName,
					Scope:            dbScope,
					Change:           tc.change,
					RequireChainSync: true,
				},
			).Return((*db.AddressInfo)(nil), fmt.Errorf(
				"%w: account %q has chain synchronization disabled",
				db.ErrAccountOperationUnsupported, accountName,
			)).Once()

			// Act: exhaust the scan and request a fresh receiving child.
			addr, err := w.GetUnusedAddress(
				t.Context(), accountName, waddrmgr.WitnessPubKey, tc.change,
			)

			// Assert: translate the Store refusal to the public error;
			// strict mocks forbid extra account reads or notification.
			require.ErrorIs(t, err, ErrAccountOperationUnsupported)
			require.NotErrorIs(t, err, db.ErrAccountOperationUnsupported)
			require.ErrorContains(t, err, accountName)
			require.ErrorContains(t, err, "chain synchronization disabled")
			require.Nil(t, addr)
			deps.store.AssertExpectations(t)
			deps.chain.AssertExpectations(t)
		})
	}
}

// TestGetAddressInfo tests the GetAddressInfo method to ensure it returns
// information for both internal and external addresses.
func TestGetAddressInfo(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	extAddr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	expectStoreAddressInfo(t, w, deps, extAddr, derivedAddressInfoFromAddr(
		t, extAddr, db.WitnessPubKey, waddrmgr.DefaultAccountName,
		waddrmgr.KeyScopeBIP0084, false, 0, 0, pubKey,
	))

	extInfo, err := w.GetAddressInfo(t.Context(), extAddr)
	require.NoError(t, err)

	require.Equal(t, extAddr.String(), extInfo.Addr.String())
	require.False(t, extInfo.Internal)
	require.True(t, extInfo.Compressed)
	require.False(t, extInfo.Imported)
	require.Equal(t, waddrmgr.WitnessPubKey, extInfo.AddrType)

	intAddr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	expectStoreAddressInfo(t, w, deps, intAddr, derivedAddressInfoFromAddr(
		t, intAddr, db.WitnessPubKey, waddrmgr.DefaultAccountName,
		waddrmgr.KeyScopeBIP0084, true, 0, 0, pubKey,
	))

	intInfo, err := w.GetAddressInfo(t.Context(), intAddr)
	require.NoError(t, err)

	require.Equal(t, intAddr.String(), intInfo.Addr.String())
	require.True(t, intInfo.Internal)
	require.True(t, intInfo.Compressed)
	require.False(t, intInfo.Imported)
	require.Equal(t, waddrmgr.WitnessPubKey, intInfo.AddrType)
}

// TestGetAddressInfoMapsNotFound verifies that a Store address miss exposes
// only the wallet-owned public sentinel with address context.
func TestGetAddressInfoMapsNotFound(t *testing.T) {
	t.Parallel()

	// Arrange: configure the existing Store mock to return its normalized
	// not-found sentinel for a valid address lookup.
	w, deps := createStartedWalletWithMocks(t)
	addr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	scriptPubKey, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	deps.store.On("GetAddress", mock.Anything, db.GetAddressQuery{
		WalletID:     w.id,
		ScriptPubKey: scriptPubKey,
	}).Return((*db.AddressInfo)(nil), db.ErrAddressNotFound).Once()

	// Act: look up the unknown address through the wallet-owned API
	// boundary.
	_, err = w.GetAddressInfo(t.Context(), addr)

	// Assert: callers see the wallet sentinel and address context without
	// inheriting the Store sentinel.
	require.ErrorIs(t, err, ErrAddressNotFound)
	require.ErrorContains(t, err, addr.String())
	require.NotErrorIs(t, err, db.ErrAddressNotFound)
}

// TestGetAddressInfoPreservesStoreError verifies that an unexpected Store
// failure retains its identity and is not promoted to the public not-found
// contract.
func TestGetAddressInfoPreservesStoreError(t *testing.T) {
	t.Parallel()

	// Arrange: configure the existing Store mock to return an unexpected
	// error for an otherwise valid address query.
	w, deps := createStartedWalletWithMocks(t)
	addr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	scriptPubKey, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	deps.store.On("GetAddress", mock.Anything, db.GetAddressQuery{
		WalletID:     w.id,
		ScriptPubKey: scriptPubKey,
	}).Return((*db.AddressInfo)(nil), errDBMock).Once()

	// Act: pass the Store failure through the address lookup boundary.
	_, err = w.GetAddressInfo(t.Context(), addr)

	// Assert: the original error remains discoverable and is not
	// reclassified as an address miss.
	require.ErrorIs(t, err, errDBMock)
	require.NotErrorIs(t, err, ErrAddressNotFound)
}

// TestGetAddressInfoRejectsInvalidAddress verifies that address-to-script
// failures remain distinct from a wallet ownership miss and never reach the
// Store.
func TestGetAddressInfoRejectsInvalidAddress(t *testing.T) {
	t.Parallel()

	// Arrange: use a typed nil address that cannot be converted to a
	// script, together with the existing Store mock.
	w, deps := createStartedWalletWithMocks(t)

	var addr *address.AddressPubKeyHash

	// Act: attempt the lookup before any Store query can be built.
	_, err := w.GetAddressInfo(t.Context(), addr)

	// Assert: the script-conversion error remains distinct from a wallet
	// miss, and the Store was never queried.
	require.Error(t, err)
	require.ErrorContains(t, err, "pay to addr script")
	require.NotErrorIs(t, err, ErrAddressNotFound)
	deps.store.AssertNotCalled(t, "GetAddress", mock.Anything, mock.Anything)
}

// TestGetDerivationInfoExternalAddressSuccess tests that we can successfully
// get the derivation info for an external address.
func TestGetDerivationInfoExternalAddressSuccess(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	addr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{
		Account:              0,
		Branch:               0,
		Index:                0,
		MasterKeyFingerprint: 123,
	}
	expectStoreAddressInfo(t, w, deps, addr, derivedAddressInfoFromAddr(
		t, addr, db.WitnessPubKey, waddrmgr.DefaultAccountName, scope, false,
		path.Index, path.MasterKeyFingerprint, pubKey,
	))

	derivationInfo, err := w.GetDerivationInfo(t.Context(), addr)

	require.NoError(t, err)
	require.NotNil(t, derivationInfo)

	expectedPath := []uint32{
		scope.Purpose + hdkeychain.HardenedKeyStart,
		scope.Coin + hdkeychain.HardenedKeyStart,
		path.Account + hdkeychain.HardenedKeyStart,
		path.Branch,
		path.Index,
	}

	require.Equal(t, pubKey.SerializeCompressed(), derivationInfo.PubKey)
	require.Equal(t, path.MasterKeyFingerprint,
		derivationInfo.MasterKeyFingerprint)
	require.Equal(t, expectedPath, derivationInfo.Bip32Path)
}

// TestGetDerivationInfoInternalAddressSuccess tests that we can successfully
// get the derivation info for an internal address.
func TestGetDerivationInfoInternalAddressSuccess(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	addr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{
		Account:              0,
		Branch:               1,
		Index:                0,
		MasterKeyFingerprint: 123,
	}
	expectStoreAddressInfo(t, w, deps, addr, derivedAddressInfoFromAddr(
		t, addr, db.WitnessPubKey, waddrmgr.DefaultAccountName, scope, true,
		path.Index, path.MasterKeyFingerprint, pubKey,
	))

	derivationInfo, err := w.GetDerivationInfo(t.Context(), addr)

	require.NoError(t, err)
	require.NotNil(t, derivationInfo)

	expectedPath := []uint32{
		scope.Purpose + hdkeychain.HardenedKeyStart,
		scope.Coin + hdkeychain.HardenedKeyStart,
		path.Account + hdkeychain.HardenedKeyStart,
		path.Branch,
		path.Index,
	}
	require.Equal(t, expectedPath, derivationInfo.Bip32Path)
	require.Equal(t, uint32(1), path.Branch)
}

// TestGetDerivationInfoNoDerivationInfo tests that we get an error when trying
// to get the derivation info for an address that is not in the wallet or is
// imported.
func TestGetDerivationInfoNoDerivationInfo(t *testing.T) {
	t.Parallel()

	// Arrange: Create a new test wallet and a key and address that is not
	// in the wallet.
	w, deps := createStartedWalletWithMocks(t)
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Act & Assert: Check that we get an error for an address not in the
	// wallet.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	deps.store.On(
		"GetAddress", mock.Anything,
		db.GetAddressQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScript,
		},
	).Return(nil, errDBMock).Once()

	_, err = w.GetDerivationInfo(t.Context(), addr)
	require.Error(t, err)

	// Arrange: Import the key as a watch-only address.
	deps.store.On(
		"NewImportedAddress", mock.Anything,
		db.NewImportedAddressParams{
			WalletID:     w.id,
			AddressType:  db.WitnessPubKey,
			ScriptPubKey: pkScript,
			PubKey:       pubKey.SerializeCompressed(),
		},
	).Return(importedPubKeyAddressInfoFromAddr(
		t, addr, waddrmgr.KeyScopeBIP0084, pubKey,
	), nil).Once()
	deps.chain.On("NotifyReceived", []address.Address{addr}).
		Return(nil).Once()

	err = w.ImportPublicKey(t.Context(), pubKey, waddrmgr.WitnessPubKey)
	require.NoError(t, err)

	// Act & Assert: Check that we still get an error because it's an
	// imported key.
	expectStoreAddressInfo(t, w, deps, addr, importedPubKeyAddressInfoFromAddr(
		t, addr, waddrmgr.KeyScopeBIP0084, pubKey,
	))

	_, err = w.GetDerivationInfo(t.Context(), addr)
	require.ErrorIs(t, err, ErrDerivationPathNotFound)
}

// TestGetDerivationInfoImportedXpubNoAccountNumber verifies that an
// imported-xpub HD child (a store address that is HD-shaped and carries a
// durable AccountID but no wallet-derived BIP44 account number) exposes no
// public derivation path: GetDerivationInfo must refuse rather than fabricate a
// public account 0. Such a child is not signable either — the signer refuses it
// for lack of a wallet-derived account number, before any secret lookup.
func TestGetDerivationInfoImportedXpubNoAccountNumber(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Build a store record for an imported-xpub external child: HD path
	// present, a durable AccountID, but no wallet-derived account number.
	info := addressInfoFromAddr(t, addr)
	accountID := uint32(7)
	info.AddrType = db.WitnessPubKey
	info.IsImported = true
	info.HasDerivationPath = true
	info.AccountName = watchOnlyAccount
	info.AccountID = &accountID
	info.KeyScope = db.KeyScope(waddrmgr.KeyScopeBIP0084)
	info.Index = 3
	info.PubKey = pubKey.SerializeCompressed()

	expectStoreAddressInfo(t, w, deps, addr, info)

	// Act & Assert: the public derivation path must be refused because no
	// real account number exists.
	_, err = w.GetDerivationInfo(t.Context(), addr)
	require.ErrorIs(t, err, ErrDerivationPathNotFound)
}

// TestListAddresses tests the ListAddresses method to ensure it returns the
// correct addresses and balances for a given account.
func TestListAddresses(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	mockAddr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	addr := mockAddr

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	req, err := addressPageRequest()
	require.NoError(t, err)

	accountName := waddrmgr.DefaultAccountName
	scope := db.KeyScope(waddrmgr.KeyScopeBIP0084)

	deps.store.On(
		"IterAddresses", mock.Anything,
		db.ListAddressesQuery{
			WalletID:    w.id,
			AccountName: &accountName,
			Scope:       &scope,
			Page:        req,
		},
	).Return(addressIter(db.AddressInfo{ScriptPubKey: pkScript})).Once()
	deps.store.On(
		"ListUTXOs", mock.Anything, db.ListUtxosQuery{
			WalletID: w.id,
		},
	).Return([]db.UtxoInfo{{
		Amount:   1000,
		PkScript: pkScript,
	}}, nil).Once()

	addrs, err := w.ListAddresses(
		t.Context(), waddrmgr.DefaultAccountName, waddrmgr.WitnessPubKey,
	)
	require.NoError(t, err)

	// We should have one address with a balance of 1000.
	require.Len(t, addrs, 1)
	require.Equal(t, addr.String(), addrs[0].Address.String())
	require.Equal(t, btcutil.Amount(1000), addrs[0].Balance)
}

// TestListAddressesImportedAlias tests that raw imported addresses are listed
// through the public imported alias without a scoped account selector.
func TestListAddressesImportedAlias(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	witnessAddr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	scriptAddr, err := address.NewAddressWitnessScriptHash(
		make([]byte, 32), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	witnessScript, err := txscript.PayToAddrScript(witnessAddr)
	require.NoError(t, err)

	scriptScript, err := txscript.PayToAddrScript(scriptAddr)
	require.NoError(t, err)

	req, err := addressPageRequest()
	require.NoError(t, err)

	deps.store.On(
		"ListUTXOs", mock.Anything, db.ListUtxosQuery{
			WalletID: w.id,
		},
	).Return([]db.UtxoInfo{{
		Amount:   1000,
		PkScript: witnessScript,
	}, {
		Amount:   2000,
		PkScript: scriptScript,
	}}, nil).Once()

	deps.store.On(
		"IterAddresses", mock.Anything,
		db.ListAddressesQuery{
			WalletID: w.id,
			Page:     req,
		},
	).Return(addressIter(db.AddressInfo{
		ScriptPubKey: witnessScript,
		AddrType:     db.WitnessPubKey,
	}, db.AddressInfo{
		ScriptPubKey: scriptScript,
		AddrType:     db.WitnessScript,
		HasScript:    true,
	})).Once()

	addrs, err := w.ListAddresses(
		t.Context(), db.DefaultImportedAccountName,
		waddrmgr.WitnessPubKey,
	)
	require.NoError(t, err)
	require.Len(t, addrs, 1)
	require.Equal(t, witnessAddr.String(), addrs[0].Address.String())
	require.Equal(t, btcutil.Amount(1000), addrs[0].Balance)
}

// TestImportPublicKey tests the ImportPublicKey method to ensure it can
// import a public key as a watch-only address.
func TestImportPublicKey(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	addr, _ := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	deps.store.On(
		"NewImportedAddress", mock.Anything,
		db.NewImportedAddressParams{
			WalletID:     w.id,
			AddressType:  db.WitnessPubKey,
			ScriptPubKey: pkScript,
			PubKey:       pubKey.SerializeCompressed(),
		},
	).Return(importedPubKeyAddressInfoFromAddr(
		t, addr, waddrmgr.KeyScopeBIP0084, pubKey,
	), nil).Once()
	deps.chain.On("NotifyReceived", []address.Address{addr}).
		Return(nil).Once()

	err = w.ImportPublicKey(t.Context(), pubKey, waddrmgr.WitnessPubKey)
	require.NoError(t, err)

	expectStoreAddressInfo(t, w, deps, addr, importedPubKeyAddressInfoFromAddr(
		t, addr, waddrmgr.KeyScopeBIP0084, pubKey,
	))

	info, err := w.GetAddressInfo(t.Context(), addr)
	require.NoError(t, err)
	require.NotNil(t, info)
}

// TestImportTaprootScript tests the ImportTaprootScript method to ensure it can
// import a taproot script as a watch-only address.
func TestImportTaprootScript(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	// Create a new tapscript to import.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	script, err := txscript.NewScriptBuilder().
		AddData(pubKey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	leaf := txscript.NewTapLeaf(txscript.BaseLeafVersion, script)
	tree := txscript.AssembleTaprootScriptTree(leaf)
	rootHash := tree.RootNode.TapHash()
	tapscript := waddrmgr.Tapscript{
		Type: waddrmgr.TapscriptTypeFullTree,
		ControlBlock: &txscript.ControlBlock{
			InternalKey: pubKey,
		},
		Leaves: []txscript.TapLeaf{leaf},
	}

	addr, _ := address.NewAddressTaproot(
		schnorr.SerializePubKey(txscript.ComputeTaprootOutputKey(
			pubKey, rootHash[:],
		)), w.cfg.ChainParams,
	)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	encodedScript, err := waddrmgr.EncodeTaprootScript(&tapscript)
	require.NoError(t, err)

	encryptedScript := []byte("encrypted tapscript")
	deps.vault.On(
		"Encrypt", waddrmgr.CKTPublic, encodedScript,
	).Return(encryptedScript, nil).Once()
	deps.store.On("NewImportedAddress", mock.Anything,
		db.NewImportedAddressParams{
			WalletID:        w.id,
			AddressType:     db.TaprootPubKey,
			ScriptPubKey:    pkScript,
			EncryptedScript: encryptedScript,
		}).Return(&db.AddressInfo{
		AddrType:     db.TaprootPubKey,
		IsImported:   true,
		ScriptPubKey: pkScript,
		HasScript:    true,
		IsWatchOnly:  true,
	}, nil).Once()
	deps.chain.On("NotifyReceived", []address.Address{addr}).
		Return(nil).Once()

	info, err := w.ImportTaprootScript(t.Context(), tapscript)
	require.NoError(t, err)
	require.Equal(t, addr, info.Addr)
	require.Equal(t, waddrmgr.TaprootScript, info.AddrType)
	require.True(t, info.Imported)
}

// newTestTapscript builds a single-leaf taproot script for import tests.
func newTestTapscript(t *testing.T) waddrmgr.Tapscript {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	script, err := txscript.NewScriptBuilder().
		AddData(pubKey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	leaf := txscript.NewTapLeaf(txscript.BaseLeafVersion, script)

	return waddrmgr.Tapscript{
		Type: waddrmgr.TapscriptTypeFullTree,
		ControlBlock: &txscript.ControlBlock{
			InternalKey: pubKey,
		},
		Leaves: []txscript.TapLeaf{leaf},
	}
}

// TestScriptForOutput tests the ScriptForOutput method to ensure it returns the
// correct script for a given output.
func TestScriptForOutput(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)

	addr, _ := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	output := wire.TxOut{
		Value:    1000,
		PkScript: pkScript,
	}

	_, pubKey := deterministicPrivKey(t)
	expectStoreAddressInfo(t, w, deps, addr, derivedAddressInfoFromAddr(
		t, addr, db.WitnessPubKey, waddrmgr.DefaultAccountName,
		waddrmgr.KeyScopeBIP0084, false, 0, 0, pubKey,
	))

	script, err := w.ScriptForOutput(t.Context(), output)
	require.NoError(t, err)

	// Check that the script is correct.
	require.Equal(t, addr, script.Addr)
	require.Equal(t, waddrmgr.WitnessPubKey, script.AddrType)
	require.Equal(t, pkScript, script.WitnessProgram)
	require.Nil(t, script.RedeemScript)
}

// TestScriptForOutputNestedWitness tests that ScriptForOutput carries the
// redeem script needed for nested witness outputs.
func TestScriptForOutputNestedWitness(t *testing.T) {
	t.Parallel()

	w, deps := createStartedWalletWithMocks(t)
	_, pubKey := deterministicPrivKey(t)
	witnessProgram, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(address.Hash160(pubKey.SerializeCompressed())).
		Script()
	require.NoError(t, err)

	addr, err := address.NewAddressScriptHash(witnessProgram, w.cfg.ChainParams)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	expectedSigScript, err := txscript.NewScriptBuilder().
		AddData(witnessProgram).
		Script()
	require.NoError(t, err)

	expectStoreAddressInfo(t, w, deps, addr, derivedAddressInfoFromAddr(
		t, addr, db.NestedWitnessPubKey, waddrmgr.DefaultAccountName,
		waddrmgr.KeyScopeBIP0049Plus, false, 0, 0, pubKey,
	))

	scriptInfo, err := w.ScriptForOutput(t.Context(), wire.TxOut{
		Value:    1000,
		PkScript: pkScript,
	})
	require.NoError(t, err)
	require.Equal(t, addr, scriptInfo.Addr)
	require.Equal(t, waddrmgr.NestedWitnessPubKey,
		scriptInfo.AddrType)
	require.Equal(t, witnessProgram, scriptInfo.WitnessProgram)
	require.Equal(t, witnessProgram, scriptInfo.RedeemScript)
	require.Equal(t, expectedSigScript, scriptInfo.SigScript)
}

// TestNewBulkAddressesReturnsWatchedBatch checks the minimum and maximum batch
// sizes, preserving order for both semantic selectors and address branches.
func TestNewBulkAddressesReturnsWatchedBatch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		count    uint32
		internal bool
		numbered bool
		xpub     bool
	}{
		{
			name:  "single external by name",
			count: 1,
		},
		{
			name:     "maximum internal by number",
			count:    MaxBulkAddressCount,
			internal: true,
			numbered: true,
		},
		{
			name:  "imported xpub child",
			count: 1,
			xpub:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Start a wallet with one complete Store batch
			// and one ordered registration expectation on its lifetime context.
			w, deps := createTestWalletWithMocks(t)
			startLoadedWalletForTest(t, w)

			scope := waddrmgr.KeyScopeBIP0084
			selector := NewAccountSelectorByName(scope, "batch")

			params := db.NewDerivedAddressParams{
				WalletID:         w.id,
				AccountName:      "batch",
				Scope:            db.KeyScope(scope),
				Change:           tc.internal,
				RequireChainSync: true,
			}
			if tc.numbered {
				selector = NewAccountSelectorByNumber(scope, 0)
				params.AccountName = ""
				params.AccountNumber = new(uint32)
			}

			key := storeDerivationAccountPubKey(t)

			var branch uint32
			if tc.internal {
				branch = 1
			}

			// Imported account keys still produce HD children, but have no
			// wallet-seed account number for public derivation metadata.
			var number *uint32
			if !tc.xpub {
				number = new(uint32)
			}

			stored := make([]db.AddressInfo, 0, tc.count)

			watched := make([]address.Address, 0, tc.count)
			for index := range tc.count {
				addr, script, pubKey := expectedStoreAddress(
					t, key, db.WitnessPubKey, branch, index,
				)
				stored = append(stored, db.AddressInfo{
					AddrType:          db.WitnessPubKey,
					IsImported:        tc.xpub,
					AccountNumber:     number,
					HasDerivationPath: true,
					Branch:            branch,
					Index:             index,
					ScriptPubKey:      script,
					PubKey:            pubKey,
				})
				watched = append(watched, addr)
			}

			deps.store.On(
				"NewDerivedAddresses", t.Context(), params, tc.count,
			).Return(stored, nil).Once()
			deps.chain.On("WatchAddrsFromTip", w.lifetimeCtx, watched).
				Return(nil).Once()

			// Act: Allocate through public admission, letting the handler
			// finish persistence and watching before the result is published.
			batch, err := w.NewBulkAddresses(
				t.Context(), selector, tc.internal, tc.count,
			)

			// Assert: Every result retains its ordered destination and branch.
			// Shared cleanup checks the single allocation and registration.
			require.NoError(t, err)
			require.Len(t, batch, int(tc.count))

			for i := range batch {
				require.Equal(t, watched[i], batch[i].Addr)
				require.Equal(t, tc.internal, batch[i].Internal)
				// Public Imported distinguishes raw imports from HD children,
				// while only wallet-seed children expose a BIP44 derivation.
				require.False(t, batch[i].Imported)

				if tc.xpub {
					require.Nil(t, batch[i].Derivation)
				} else {
					require.NotNil(t, batch[i].Derivation)
				}
			}
		})
	}
}

// TestNewBulkAddressesRejectsAdmission checks invalid requests
// without registering any expected Store or chain mutation.
func TestNewBulkAddressesRejectsAdmission(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		count    uint32
		invalid  bool
		imported bool
		wantErr  error
	}{
		{
			name:    "zero count",
			count:   0,
			wantErr: ErrInvalidParam,
		},
		{
			name:    "over maximum",
			count:   MaxBulkAddressCount + 1,
			wantErr: ErrInvalidParam,
		},
		{
			name:    "missing selector",
			count:   1,
			invalid: true,
			wantErr: ErrInvalidParam,
		},
		{
			name:     "reserved imported account",
			count:    1,
			imported: true,
			wantErr:  ErrImportedAccountNoAddrGen,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Leave strict Store/chain mocks without expectations;
			// any dependency call would fail this pre-mutation guard test.
			w, _ := createTestWalletWithMocks(t)

			startLoadedWalletForTest(t, w)

			selector := NewAccountSelectorByName(
				waddrmgr.KeyScopeBIP0084, "batch",
			)
			if tc.invalid {
				selector = AccountSelector{}
			}

			// Select the raw-import bucket to verify its existing receiving
			// restriction also applies before bulk allocation.
			if tc.imported {
				selector = NewAccountSelectorByName(
					waddrmgr.KeyScopeBIP0084,
					waddrmgr.ImportedAddrAccountName,
				)
			}

			// Act: Submit the invalid count or selector
			// through the same public method used for successful allocation.
			batch, err := w.NewBulkAddresses(
				t.Context(), selector, false, tc.count,
			)

			// Assert: Admission refuses the call with no result. Strict mocks
			// and shared cleanup prove no allocation or registration occurred.
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, batch)
		})
	}
}

// TestNewBulkAddressesMapsStoreFailure keeps durable-outcome errors distinct
// from cancellation and prevents any result or watch after a failed allocation.
func TestNewBulkAddressesMapsStoreFailure(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		storeErr error
		wantErr  error
	}{
		{
			name:     "excluded account",
			storeErr: db.ErrAccountOperationUnsupported,
			wantErr:  ErrAccountOperationUnsupported,
		},
		{
			name:     "missing account",
			storeErr: db.ErrAccountNotFound,
			wantErr:  ErrAccountNotFound,
		},
		{
			name:     "terminal exhaustion",
			storeErr: db.ErrMaxAddressIndexReached,
			wantErr:  ErrAddressDerivationExhausted,
		},
		{
			name: "ambiguous canceled commit",
			storeErr: errors.Join(
				dbruntime.ErrAmbiguousTxCommit, context.Canceled,
			),
			wantErr: ErrIndeterminateCommit,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Return exactly one Store failure, with no chain
			// expectation, to prove the public method never retries it.
			w, deps := createTestWalletWithMocks(t)
			startLoadedWalletForTest(t, w)
			deps.store.On(
				"NewDerivedAddresses", t.Context(), mock.Anything,
				uint32(1),
			).Return(nil, tc.storeErr).Once()

			// Act: Use normal admission so error mapping is exercised at the
			// public boundary rather than by directly calling the mapper.
			batch, err := w.NewBulkAddresses(
				t.Context(),
				NewAccountSelectorByName(waddrmgr.KeyScopeBIP0084, "batch"),
				false, 1,
			)

			// Assert: Only the wallet-owned failure escapes, even when a
			// possibly committed allocation also reports cancellation.
			// Cleanup verifies the single Store call without any chain call.
			require.ErrorIs(t, err, tc.wantErr)
			require.NotErrorIs(t, err, context.Canceled)
			require.NotErrorIs(t, err, dbruntime.ErrAmbiguousTxCommit)
			require.Nil(t, batch)
		})
	}
}

// TestNewBulkAddressesFinishesCommittedWatch checks that failure and caller
// cancellation discard delivery without abandoning committed address watches.
func TestNewBulkAddressesFinishesCommittedWatch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		cancel bool
	}{
		{
			name: "watch failure",
		},
		{
			name:   "caller cancellation after commit",
			cancel: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Simulate a committed child and optionally cancel its
			// caller at Store return. Watching uses the wallet context.
			w, deps := createTestWalletWithMocks(t)
			startLoadedWalletForTest(t, w)

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			addr, script, _ := expectedStoreAddress(
				t, storeDerivationAccountPubKey(t), db.WitnessPubKey, 0, 0,
			)
			stored := db.AddressInfo{
				AddrType:          db.WitnessPubKey,
				ScriptPubKey:      script,
				HasDerivationPath: true,
			}
			deps.store.On(
				"NewDerivedAddresses", ctx, mock.Anything, uint32(1),
			).Run(func(mock.Arguments) {
				if tc.cancel {
					cancel()
				}
			}).Return([]db.AddressInfo{stored}, nil).Once()

			watchErr := errors.New("watch unavailable")

			wantErr := watchErr
			if tc.cancel {
				watchErr = nil
				wantErr = context.Canceled
			}

			deps.chain.On(
				"WatchAddrsFromTip", w.lifetimeCtx, []address.Address{addr},
			).Run(func(mock.Arguments) {
				require.NoError(t, w.lifetimeCtx.Err())
			}).Return(watchErr).Once()

			// Act: Finish the admitted call after the committed Store result.
			batch, err := w.NewBulkAddresses(
				ctx,
				NewAccountSelectorByName(waddrmgr.KeyScopeBIP0084, "batch"),
				false, 1,
			)

			// Assert: Failed delivery never exposes the committed child.
			// Cleanup verifies allocation and the admitted watch attempt.
			require.ErrorIs(t, err, wantErr)
			require.Nil(t, batch)
		})
	}
}

// TestNewBulkAddressesReplaysCommittedBatch verifies fresh startup watches
// destinations committed before failed delivery, using a reopened SQLite Store.
func TestNewBulkAddressesReplaysCommittedBatch(t *testing.T) {
	t.Parallel()

	// Arrange: Keep the first backend non-current so only the public batch
	// call registers; its failure captures the committed destinations.
	path := filepath.Join(t.TempDir(), "reopen.sqlite")
	chainMock := createTestChain(t)
	chainMock.On("WatchAddrsFromTip", mock.Anything, mock.Anything).Unset()

	openManager := func(chainSource chain.Interface) *Manager {
		m, err := NewManager(t.Context(), ManagerConfig{
			Backend:     DBBackendSQLite,
			DataSource:  path,
			ChainParams: chainParams,
			ChainSource: chainSource,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = m.Stop() })

		return m
	}
	m := openManager(chainMock)
	_, err := m.Start(t.Context())
	require.NoError(t, err)

	params := sqliteCreateParams(t)
	w, err := m.Create(params)
	require.NoError(t, err)
	require.NoError(t, w.keyVault.Unlock(
		t.Context(), params.PrivatePassphrase,
	))
	w.state.toUnlocked()
	_, err = w.NewAccount(t.Context(), NewAccountParams{
		Scope: waddrmgr.KeyScopeBIP0084,
		Name:  "batch",
	})
	require.NoError(t, err)
	require.NoError(t, w.store.UpdateWallet(
		t.Context(), db.UpdateWalletParams{
			WalletID: w.id,
			BirthdayBlock: &db.Block{
				Hash:      *chainParams.GenesisHash,
				Timestamp: chainParams.GenesisBlock.Header.Timestamp,
			},
		},
	))

	var committed []address.Address
	chainMock.On("WatchAddrsFromTip", w.lifetimeCtx, mock.Anything).
		Run(func(args mock.Arguments) {
			addrs, _ := args.Get(1).([]address.Address)

			committed = addrs
		}).Return(errDBMock).Once()
	// The fresh worker owns this capture. Publish it after registration
	// finishes so the test can join replay without racing its writes.
	var restored []address.Address

	replayed := make(chan []address.Address, 1)

	freshChain := createTestChain(t)
	freshChain.On("IsCurrent").Unset()
	freshChain.On("IsCurrent").Return(true).Maybe()
	freshChain.On("WatchAddrsFromTip", mock.Anything, mock.Anything).Unset()
	freshChain.On("WatchAddrsFromTip", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			restored, _ = args.Get(1).([]address.Address)
		}).Return(nil).Once()
	freshChain.On("NotifyBlocks").Run(func(mock.Arguments) {
		replayed <- restored
	}).Return(nil).Once()
	freshChain.On("Notifications").Return((<-chan any)(nil)).Maybe()

	// Act: Fail public delivery, stop the owning Manager to drain the
	// request loop and close storage, then reopen all durable Wallets.
	batch, deliveryErr := w.NewBulkAddresses(
		t.Context(),
		NewAccountSelectorByName(waddrmgr.KeyScopeBIP0084, "batch"),
		false, 2,
	)

	require.NoError(t, m.Stop())

	fresh, err := openManager(freshChain).Start(t.Context())
	require.NoError(t, err)

	// Assert: Delivery exposed no batch but both committed addresses
	// survived closing the database and were replayed by sync initialization.
	// Start itself need not join replay; bound the wait for the fresh worker.
	require.ErrorIs(t, deliveryErr, errDBMock)
	require.Nil(t, batch)
	require.Len(t, committed, 2)
	require.Len(t, fresh, 1)

	select {
	case got := <-replayed:
		require.Equal(t, committed, got)

	case <-time.After(5 * time.Second):
		t.Fatal("committed batch was not replayed after reopening")
	}
}

// TestAllocateNextKeyReturnsLocator verifies selector and branch handling,
// while preserving the Store's metadata through one allocation request.
func TestAllocateNextKeyReturnsLocator(t *testing.T) {
	t.Parallel()

	scope := waddrmgr.KeyScope{Purpose: 1017, Coin: 1}
	account := uint32(7)

	name := "key-family"
	for _, tc := range []struct {
		name        string
		selector    AccountSelector
		queryName   string
		queryNumber *uint32
		branch      uint32
		fingerprint uint32
		imported    bool
	}{
		{
			name:        "external by name",
			selector:    NewAccountSelectorByName(scope, name),
			queryName:   name,
			fingerprint: 0x12345678,
		},
		{
			name:        "internal by name",
			selector:    NewAccountSelectorByName(scope, name),
			queryName:   name,
			branch:      1,
			fingerprint: 0x12345678,
		},
		{
			name: "internal by number",
			selector: NewAccountSelectorByNumber(
				scope, AccountNumber(account),
			),
			queryNumber: &account,
			branch:      1,
		},
		{
			name: "external by number",
			selector: NewAccountSelectorByNumber(
				scope, AccountNumber(account),
			),
			queryNumber: &account,
		},
		{
			name:      "imported external by name",
			selector:  NewAccountSelectorByName(scope, name),
			queryName: name,
			imported:  true,
		},
		{
			name:      "imported internal by name",
			selector:  NewAccountSelectorByName(scope, name),
			queryName: name,
			branch:    1,
			imported:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Expect one allocation with the caller's exact selector.
			// A different cached fingerprint must not replace Store metadata.
			w, deps := createTestWalletWithMocks(t)
			w.addrStore = nil
			w.masterFingerprint = 0x87654321
			startLoadedWalletForTest(t, w)
			_, script, pubKey := expectedStoreAddress(
				t, storeDerivationAccountPubKey(t), db.WitnessPubKey,
				tc.branch, 19,
			)
			stored := db.AddressInfo{
				AccountNumber:        &account,
				KeyScope:             db.KeyScope(scope),
				MasterKeyFingerprint: tc.fingerprint,
				AddrType:             db.WitnessPubKey,
				HasDerivationPath:    true,
				Branch:               tc.branch,
				Index:                19,
				ScriptPubKey:         script,
				PubKey:               pubKey,
			}
			// Imported xpub children have a relative path but no wallet-root
			// account number, so the allocation must expose a nil origin.
			if tc.imported {
				stored.AccountNumber = nil
				stored.IsImported = true
			}

			deps.store.On("NewDerivedAddress", t.Context(),
				db.NewDerivedAddressParams{
					WalletID:      w.id,
					Scope:         db.KeyScope(scope),
					AccountName:   tc.queryName,
					AccountNumber: tc.queryNumber,
					Change:        tc.branch == 1,
				},
			).Return(&stored, nil).Once()

			// Act: Allocate through the public request loop in the selected
			// custom scope without entering receiving-address registration.
			key, err := w.AllocateNextKey(
				t.Context(), tc.selector, tc.branch == 1,
			)

			// Assert: Every locator field matches the committed row, including
			// zero fingerprints. Shared cleanup rejects extra allocation or
			// watch calls, including a separate account read.
			require.NoError(t, err)
			require.Equal(t, pubKey, key.PubKey.SerializeCompressed())
			require.Equal(t, tc.branch, key.Branch)
			require.Equal(t, stored.Index, key.Index)

			if tc.imported {
				require.Nil(t, key.Origin)
			} else {
				require.Equal(t, &KeyOrigin{
					KeyScope:             scope,
					Account:              account,
					MasterKeyFingerprint: tc.fingerprint,
				}, key.Origin)
			}
		})
	}
}

// TestAllocateNextKeyRejectsAdmission verifies a malformed selector is rejected
// before any account lookup or allocation dependency is touched.
func TestAllocateNextKeyRejectsAdmission(t *testing.T) {
	t.Parallel()

	// Arrange: Leave strict dependencies without expectations, so even a
	// read fails this test if selector validation is bypassed.
	w, _ := createTestWalletWithMocks(t)
	startLoadedWalletForTest(t, w)

	// Act: Submit an empty selector to an otherwise started Wallet.
	key, err := w.AllocateNextKey(t.Context(), AccountSelector{}, false)

	// Assert: No usable key or locator escapes. Shared cleanup checks mocks.
	require.ErrorIs(t, err, ErrInvalidParam)
	require.Nil(t, key)
}

// TestAllocateNextKeyMapsStoreFailure preserves public failure identities and
// never retries or returns a key after an uncertain durable allocation.
func TestAllocateNextKeyMapsStoreFailure(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		storeErr error
		wantErr  error
	}{
		{
			name:     "sql exhausted branch",
			storeErr: db.ErrMaxAddressIndexReached,
			wantErr:  ErrAddressDerivationExhausted,
		},
		{
			name: "kvdb exhausted branch",
			storeErr: fmt.Errorf("derive address: %w", waddrmgr.ManagerError{
				ErrorCode: waddrmgr.ErrTooManyAddresses,
			}),
			wantErr: ErrAddressDerivationExhausted,
		},
		{
			name: "ambiguous canceled commit",
			storeErr: errors.Join(
				dbruntime.ErrAmbiguousTxCommit, context.Canceled,
			),
			wantErr: ErrIndeterminateCommit,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Allow one failed native allocation. Once rejects a retry
			// after an uncertain commit; no separate account read is allowed.
			w, deps := createTestWalletWithMocks(t)
			startLoadedWalletForTest(t, w)

			deps.store.On("NewDerivedAddress", t.Context(),
				mock.Anything).Return(nil, tc.storeErr).Once()

			// Act: Exercise mapping through admitted public work so a joined
			// cancellation cannot replace the indeterminate-commit identity.
			key, err := w.AllocateNextKey(t.Context(),
				NewAccountSelectorByNumber(waddrmgr.KeyScopeBIP0084, 7), false,
			)

			// Assert: Only the wallet-owned identity is exposed, and no key or
			// path escapes. Shared cleanup verifies the single allocation.
			require.ErrorIs(t, err, tc.wantErr)
			require.NotErrorIs(t, err, dbruntime.ErrAmbiguousTxCommit)
			require.Nil(t, key)
		})
	}

	t.Run("missing account", func(t *testing.T) {
		t.Parallel()

		// Arrange: Let the allocator report its failed account lookup.
		w, deps := createTestWalletWithMocks(t)
		startLoadedWalletForTest(t, w)
		deps.store.On("NewDerivedAddress", t.Context(), mock.Anything).
			Return(nil, db.ErrAccountNotFound).Once()

		// Act: Request a nonexistent account through the public API.
		key, err := w.AllocateNextKey(t.Context(),
			NewAccountSelectorByNumber(waddrmgr.KeyScopeBIP0084, 7), false,
		)

		// Assert: The missing account has a public error and consumes no key.
		require.ErrorIs(t, err, ErrAccountNotFound)
		require.Nil(t, key)
	})
}

// TestAllocateNextKeyKvdbDurability verifies unused children remain consumed
// across concurrent public calls and a database reopen on both legacy branches.
func TestAllocateNextKeyKvdbDurability(t *testing.T) {
	t.Parallel()

	// Keep wallet goroutines and cleanup in one bubble so quiescence covers
	// the allocation requests as well as their callers.
	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		// Arrange: Create a real legacy wallet whose ordinary address metadata
		// leaves the root fingerprint at zero; key allocation must preserve it.
		dbPath := testKVDBPath(t)
		manager := testKVDBManagerAt(t, dbPath)
		params := sqliteCreateParams(t)
		w, err := manager.Create(params)
		require.NoError(t, err)

		scope := waddrmgr.KeyScopeBIP0084
		selectors := []AccountSelector{
			NewAccountSelectorByName(scope, waddrmgr.DefaultAccountName),
			NewAccountSelectorByNumber(scope, 0),
		}

		type allocation struct {
			key *AllocatedKey
			err error
		}

		const perBranch = 3

		results := make([]allocation, 2*perBranch)

		// Act: Allocate unused children concurrently, with one result slot
		// per caller. Wait for quiescence before reading the results; normal
		// completion leaves only the idle wallet request loop blocked.
		for i := range results {
			go func() {
				key, err := w.AllocateNextKey(
					t.Context(), selectors[i%2], i >= perBranch,
				)
				results[i] = allocation{
					key: key,
					err: err,
				}
			}()
		}

		synctest.Wait()

		// Assert: Every call has a distinct root locator and key, even
		// though none of the earlier children has been used on chain.
		seenPaths := make(map[[2]uint32]bool)

		seenKeys := make(map[string]bool)
		for i, result := range results {
			require.NoError(t, result.err)
			require.NotNil(t, result.key.Origin)
			require.Equal(t, scope, result.key.Origin.KeyScope)
			require.Zero(t, result.key.Origin.Account)
			require.Equal(t, uint32(i/perBranch), result.key.Branch)
			require.Zero(t, result.key.Origin.MasterKeyFingerprint)
			require.Less(t, result.key.Index, uint32(perBranch))
			locator := [2]uint32{result.key.Branch, result.key.Index}
			require.False(t, seenPaths[locator])
			seenPaths[locator] = true
			key := string(result.key.PubKey.SerializeCompressed())
			require.False(t, seenKeys[key])
			seenKeys[key] = true
		}

		// Act: Stop the owning Manager to drain its Wallet and close storage,
		// then reopen so cached counters cannot hide lost writes.
		require.NoError(t, manager.Stop())
		reopened, err := NewManager(t.Context(), ManagerConfig{
			Backend:           DBBackendKVDB,
			DataSource:        dbPath,
			ChainParams:       chainParams,
			ChainSource:       createTestChain(t),
			KVDBPubPassphrase: params.PubPassphrase,
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = reopened.Stop()
		})
		wallets, err := reopened.Start(t.Context())
		require.NoError(t, err)
		require.Len(t, wallets, 1)
		w = wallets[0]

		// Assert: Persisted keys remain available through public lookup.
		// The next allocation follows every previously consumed child.
		for _, result := range results {
			addr, err := address.NewAddressWitnessPubKeyHash(
				address.Hash160(result.key.PubKey.SerializeCompressed()),
				&chainParams,
			)
			require.NoError(t, err)
			info, err := w.GetAddressInfo(t.Context(), addr)
			require.NoError(t, err)
			require.True(t, result.key.PubKey.IsEqual(info.PubKey))
			require.Equal(t, &AddressDerivation{
				KeyScope:             result.key.Origin.KeyScope,
				Account:              result.key.Origin.Account,
				Branch:               result.key.Branch,
				Index:                result.key.Index,
				MasterKeyFingerprint: result.key.Origin.MasterKeyFingerprint,
			}, info.Derivation)
		}

		for branch, selector := range selectors {
			key, err := w.AllocateNextKey(
				t.Context(), selector, branch == 1,
			)
			require.NoError(t, err)
			require.Equal(t, uint32(perBranch), key.Index)
			require.Equal(t, uint32(branch), key.Branch)
			require.Zero(t, key.Origin.MasterKeyFingerprint)
			require.False(t, seenKeys[string(key.PubKey.SerializeCompressed())])
		}
	})
}

// newReceivingSQLiteWallet creates a durable SQLite Wallet at path with one
// empty BIP0084 account, using chainSource for registration.
func newReceivingSQLiteWallet(t *testing.T, path string,
	chainSource chain.Interface) (*Manager, *Wallet) {

	t.Helper()

	m, err := NewManager(t.Context(), ManagerConfig{
		Backend:     DBBackendSQLite,
		DataSource:  path,
		ChainParams: chainParams,
		ChainSource: chainSource,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Stop() })

	_, err = m.Start(t.Context())
	require.NoError(t, err)

	params := sqliteCreateParams(t)
	w, err := m.Create(params)
	require.NoError(t, err)
	require.NoError(t, w.keyVault.Unlock(
		t.Context(), params.PrivatePassphrase,
	))
	w.state.toUnlocked()
	_, err = w.NewAccount(t.Context(), NewAccountParams{
		Scope: waddrmgr.KeyScopeBIP0084,
		Name:  "recv",
	})
	require.NoError(t, err)
	require.NoError(t, w.store.UpdateWallet(
		t.Context(), db.UpdateWalletParams{
			WalletID: w.id,
			BirthdayBlock: &db.Block{
				Hash:      *chainParams.GenesisHash,
				Timestamp: chainParams.GenesisBlock.Header.Timestamp,
			},
		},
	))

	return m, w
}

// receivingKeyCount returns the durable derivation counter of one branch of
// the "recv" account.
func receivingKeyCount(t *testing.T, w *Wallet, internal bool) uint32 {
	t.Helper()

	name := "recv"
	account, err := w.store.GetAccount(t.Context(), db.GetAccountQuery{
		WalletID:    w.id,
		Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
		Name:        &name,
		SkipBalance: true,
	})
	require.NoError(t, err)

	if internal {
		return account.InternalKeyCount
	}

	return account.ExternalKeyCount
}

// TestNewAddressSQLiteReusesDurableChild verifies against a real SQLite Store
// that receiving reuses one child without advancing derivation, keeps branches
// apart, prefers it over later bulk children, and survives a reopen.
func TestNewAddressSQLiteReusesDurableChild(t *testing.T) {
	t.Parallel()

	// Arrange: create an empty receiving account on a durable database.
	path := filepath.Join(t.TempDir(), "reuse.sqlite")
	m, w := newReceivingSQLiteWallet(t, path, createTestChain(t))
	byName := NewAccountSelectorByName(waddrmgr.KeyScopeBIP0084, "recv")

	// Act: request external addresses by name repeatedly, then an internal
	// one, then force-allocate later external children.
	first, err := w.NewAddress(t.Context(), byName, false)
	require.NoError(t, err)
	second, err := w.NewAddress(t.Context(), byName, false)
	require.NoError(t, err)
	change, err := w.NewAddress(t.Context(), byName, true)
	require.NoError(t, err)
	bulk, err := w.NewBulkAddresses(t.Context(), byName, false, 2)
	require.NoError(t, err)
	afterBulk, err := w.NewAddress(t.Context(), byName, false)
	require.NoError(t, err)

	// Assert: one external child is reused and derivation advanced once
	// per branch until the explicit batch.
	require.Equal(t, first, second)
	require.Equal(t, first, afterBulk)
	require.Equal(t, uint32(0), first.Derivation.Index)
	require.False(t, first.Internal)
	require.True(t, change.Internal)
	require.Equal(t, uint32(0), change.Derivation.Index)
	require.NotEqual(t, first.Addr, change.Addr)
	require.Len(t, bulk, 2)
	require.Equal(t, uint32(1), bulk[0].Derivation.Index)
	require.Equal(t, uint32(3), receivingKeyCount(t, w, false))
	require.Equal(t, uint32(1), receivingKeyCount(t, w, true))

	// Act: reopen the database and request the same branch by number.
	require.NoError(t, m.Stop())

	reopened, err := NewManager(t.Context(), ManagerConfig{
		Backend:     DBBackendSQLite,
		DataSource:  path,
		ChainParams: chainParams,
		ChainSource: createTestChain(t),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Stop() })

	wallets, err := reopened.Start(t.Context())
	require.NoError(t, err)
	require.Len(t, wallets, 1)

	number := AccountNumber(first.Derivation.Account)
	byNumber := NewAccountSelectorByNumber(waddrmgr.KeyScopeBIP0084, number)
	reused, err := wallets[0].NewAddress(t.Context(), byNumber, false)

	// Assert: the durable unused child is returned without allocation.
	require.NoError(t, err)
	require.Equal(t, first, reused)
	require.Equal(t, uint32(3), receivingKeyCount(t, wallets[0], false))
}

// TestNewAddressSQLiteConcurrentEmptyBranch verifies concurrent callers on an
// empty SQLite branch return the same child and advance derivation once, even
// while the first caller's registration is still pending.
func TestNewAddressSQLiteConcurrentEmptyBranch(t *testing.T) {
	t.Parallel()

	const callers = 8

	// Arrange: hold the first registration until every later caller has
	// returned; later registrations succeed immediately.
	chainMock := createTestChain(t)
	chainMock.On("WatchAddrsFromTip", mock.Anything, mock.Anything).Unset()

	path := filepath.Join(t.TempDir(), "concurrent.sqlite")
	_, w := newReceivingSQLiteWallet(t, path, chainMock)
	selector := NewAccountSelectorByName(waddrmgr.KeyScopeBIP0084, "recv")

	enteredChan := make(chan struct{})
	releaseChan := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseChan) })
	t.Cleanup(release)

	chainMock.On("WatchAddrsFromTip", w.lifetimeCtx, mock.Anything).
		Run(func(mock.Arguments) {
			close(enteredChan)

			<-releaseChan
		}).Return(nil).Once()
	chainMock.On("WatchAddrsFromTip", w.lifetimeCtx, mock.Anything).
		Return(nil).Times(callers)

	firstChan := make(chan addressInfoResp, 1)
	go func() {
		info, err := w.NewAddress(t.Context(), selector, false)
		firstChan <- addressInfoResp{info: info, err: err}
	}()

	<-enteredChan

	// Act: race the remaining callers while the first watch is pending.
	results := make(chan addressInfoResp, callers)

	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			info, err := w.NewAddress(t.Context(), selector, false)
			results <- addressInfoResp{info: info, err: err}
		}()
	}

	wg.Wait()
	close(results)

	release()

	first := <-firstChan

	// Assert: every caller received the single allocated child.
	require.NoError(t, first.err)

	for result := range results {
		require.NoError(t, result.err)
		require.Equal(t, first.info, result.info)
	}

	require.Equal(t, uint32(1), receivingKeyCount(t, w, false))
}

// TestNewAddressKVDBAllocatesSuccessive verifies modern kvdb keeps force-next
// behavior: each call, by name or number, returns the next distinct child.
func TestNewAddressKVDBAllocatesSuccessive(t *testing.T) {
	t.Parallel()

	// Arrange: create a kvdb Wallet whose chain accepts each notification.
	m := testKVDBManager(t)
	chainMock, ok := m.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	chainMock.On("NotifyReceived", mock.Anything).Return(nil).Times(3)

	params := sqliteCreateParams(t)
	params.PubPassphrase = []byte("public")
	w, err := m.Create(params)
	require.NoError(t, err)
	require.True(t, w.usesKVDBStore())

	scope := waddrmgr.KeyScopeBIP0084

	// Act: request three external addresses, the last by number.
	first, err := w.NewAddress(
		t.Context(), NewAccountSelectorByName(
			scope, waddrmgr.DefaultAccountName,
		), false,
	)
	require.NoError(t, err)
	second, err := w.NewAddress(
		t.Context(), NewAccountSelectorByName(
			scope, waddrmgr.DefaultAccountName,
		), false,
	)
	require.NoError(t, err)
	third, err := w.NewAddress(
		t.Context(), NewAccountSelectorByNumber(scope, 0), false,
	)
	require.NoError(t, err)

	// Assert: each call allocated the next child on the external branch.
	for i, info := range []AddressInfo{first, second, third} {
		require.NotNil(t, info.Derivation)
		require.Equal(t, uint32(i), info.Derivation.Index)
		require.False(t, info.Internal)
		require.Equal(t, waddrmgr.WitnessPubKey, info.AddrType)
	}

	require.NotEqual(t, first.Addr, second.Addr)
	require.NotEqual(t, second.Addr, third.Addr)
}
