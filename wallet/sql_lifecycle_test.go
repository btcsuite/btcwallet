package wallet

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	storesqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// ambiguousCommitStore commits one selected transaction without publishing its
// manager hooks, then reports that commit as ambiguous.
type ambiguousCommitStore struct {
	// Store delegates transactions not selected for ambiguity injection.
	walletstore.Store

	ambiguousNextUpdate     bool
	ambiguousNextUpdateOnce bool
}

// Update simulates a durable replay-capable transaction whose acknowledgement
// and commit-hook publication were lost.
func (s *ambiguousCommitStore) Update(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	if !s.ambiguousNextUpdate {
		return s.Store.Update(ctx, body, reset)
	}

	s.ambiguousNextUpdate = false

	var hooks []func()

	err := s.Store.Update(ctx, func(tx walletstore.ReadWriteTx) error {
		return body(&capturedCommitHooksTx{
			ReadWriteTx: tx,
			hooks:       &hooks,
		})
	}, func() {
		hooks = nil
		if reset != nil {
			reset()
		}
	})
	if err != nil {
		return err
	}

	return walletstore.NewAmbiguousCommitError(
		errors.New("commit acknowledgement lost"), hooks...,
	)
}

// UpdateOnce simulates a durable transaction whose commit acknowledgement was
// lost before in-memory hooks could be published.
func (s *ambiguousCommitStore) UpdateOnce(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	if !s.ambiguousNextUpdateOnce {
		return s.Store.UpdateOnce(ctx, body, reset)
	}

	s.ambiguousNextUpdateOnce = false

	err := s.Store.UpdateOnce(ctx, func(tx walletstore.ReadWriteTx) error {
		return body(&noCommitHooksTx{ReadWriteTx: tx})
	}, reset)
	if err != nil {
		return err
	}

	return &walletstore.AmbiguousCommitError{
		Err: errors.New("commit acknowledgement lost"),
	}
}

// noCommitHooksTx suppresses manager commit hooks while delegating all durable
// operations to the real transaction.
type noCommitHooksTx struct {
	// ReadWriteTx delegates transaction operations other than Addr.
	walletstore.ReadWriteTx
}

// Addr returns an address store that ignores commit hook registration.
//
//nolint:ireturn // The test wrapper implements the transaction contract.
func (t *noCommitHooksTx) Addr() walletstore.AddrReadWriteStore {
	return &noCommitHooksAddr{
		AddrReadWriteStore: t.ReadWriteTx.Addr(),
	}
}

// noCommitHooksAddr delegates durable address operations and drops cache hooks.
type noCommitHooksAddr struct {
	// AddrReadWriteStore delegates address operations other than OnCommit.
	walletstore.AddrReadWriteStore
}

// OnCommit intentionally suppresses publication to simulate an ambiguous SQL
// commit result.
func (*noCommitHooksAddr) OnCommit(func()) {}

// capturedCommitHooksTx diverts manager hooks from a durable transaction so an
// ambiguous result can return them to the reconciliation path.
type capturedCommitHooksTx struct {
	// ReadWriteTx delegates transaction operations other than Addr.
	walletstore.ReadWriteTx

	hooks *[]func()
}

// Addr returns an address store that captures commit hooks for later repair.
//
//nolint:ireturn // The test wrapper implements the transaction contract.
func (t *capturedCommitHooksTx) Addr() walletstore.AddrReadWriteStore {
	return &capturedCommitHooksAddr{
		AddrReadWriteStore: t.ReadWriteTx.Addr(),
		hooks:              t.hooks,
	}
}

// capturedCommitHooksAddr diverts hook registration into a test-owned slice.
type capturedCommitHooksAddr struct {
	// AddrReadWriteStore delegates address operations other than OnCommit.
	walletstore.AddrReadWriteStore

	hooks *[]func()
}

// OnCommit records a hook without publishing it after the underlying commit.
func (a *capturedCommitHooksAddr) OnCommit(callback func()) {
	*a.hooks = append(*a.hooks, callback)
}

// rejectingChainClient returns a configured broadcast failure while delegating
// the remaining chain interface to the standard wallet test client.
type rejectingChainClient struct {
	*mockChainClient

	err error
}

// SendRawTransaction returns the configured broadcast failure.
func (c *rejectingChainClient) SendRawTransaction(*wire.MsgTx, bool) (
	*chainhash.Hash, error) {

	return nil, c.err
}

// TestSQLWalletCreateAccountAddressRestart verifies SQL-native creation and the
// account and derived-address lifecycle through the existing Loader and Wallet.
func TestSQLWalletCreateAccountAddressRestart(t *testing.T) {
	t.Parallel()

	params := &chaincfg.TestNet3Params
	pubPass := []byte("public-pass")
	privPass := []byte("private-pass")
	seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
	require.NoError(t, err)

	dbPath := filepath.Join(t.TempDir(), "wallet.sqlite")
	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	require.NoError(t, storesqlite.ApplyMigrations(conn))

	store := dbsqlite.NewNamedStore(conn, "lifecycle")
	loader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	exists, err := loader.WalletExists()
	require.NoError(t, err)
	require.False(t, exists)

	wallet, err := loader.CreateNewWallet(
		pubPass, privPass, seed, time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}
	require.NoError(t, wallet.Unlock(privPass, nil))

	scopedManager, err := wallet.Manager.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	rollbackErr := errors.New("account rollback")
	err = store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			_, _, err := scopedManager.NewAccountFromStore(
				tx.Addr(), "rolled back",
			)
			if err != nil {
				return err
			}

			return rollbackErr
		}, nil,
	)
	require.ErrorIs(t, err, rollbackErr)
	_, err = wallet.AccountNumber(
		waddrmgr.KeyScopeBIP0084, "rolled back",
	)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound))

	account, err := wallet.NextAccount(
		waddrmgr.KeyScopeBIP0084, "secondary",
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, account)
	require.NoError(t, wallet.RenameAccount(
		waddrmgr.KeyScopeBIP0084, account, "renamed",
	))
	accountNumber, err := wallet.AccountNumber(
		waddrmgr.KeyScopeBIP0084, "renamed",
	)
	require.NoError(t, err)
	require.Equal(t, account, accountNumber)

	customScope := waddrmgr.KeyScope{Purpose: 1017, Coin: 1}
	customSchema := waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.WitnessPubKey,
		InternalAddrType: waddrmgr.TaprootPubKey,
	}
	_, err = wallet.AddScopeManager(customScope, customSchema)
	require.NoError(t, err)

	addresses := make([]string, 0, len(waddrmgr.DefaultKeyScopes)*2)
	for _, scope := range waddrmgr.DefaultKeyScopes {
		scopeAccount := uint32(waddrmgr.DefaultAccountNum)
		if scope == waddrmgr.KeyScopeBIP0084 {
			scopeAccount = account
		}

		external, err := wallet.NewAddress(scopeAccount, scope)
		require.NoError(t, err)
		addresses = append(addresses, external.String())

		managed, err := wallet.AddressInfo(external)
		require.NoError(t, err)
		require.Equal(t, waddrmgr.ScopeAddrMap[scope].ExternalAddrType,
			managed.AddrType())

		internal, err := wallet.NewChangeAddress(scopeAccount, scope)
		require.NoError(t, err)
		addresses = append(addresses, internal.String())

		managed, err = wallet.AddressInfo(internal)
		require.NoError(t, err)
		require.Equal(t, waddrmgr.ScopeAddrMap[scope].InternalAddrType,
			managed.AddrType())
	}
	customExternal, err := wallet.NewAddress(
		waddrmgr.DefaultAccountNum, customScope,
	)
	require.NoError(t, err)
	addresses = append(addresses, customExternal.String())
	customInternal, err := wallet.NewChangeAddress(
		waddrmgr.DefaultAccountNum, customScope,
	)
	require.NoError(t, err)
	addresses = append(addresses, customInternal.String())

	result, err := wallet.Accounts(waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)
	require.Len(t, result.Accounts, 3)
	balances, err := wallet.AccountBalances(waddrmgr.KeyScopeBIP0084, 0)
	require.NoError(t, err)
	require.Len(t, balances, 3)

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())

	conn, err = storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	store = dbsqlite.NewNamedStore(conn, "lifecycle")
	loader, err = NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err = loader.OpenExistingWallet(pubPass, false)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}
	_, err = wallet.Manager.FetchScopedKeyManager(customScope)
	require.NoError(t, err)

	require.NoError(t, wallet.Unlock(privPass, nil))
	for _, addressString := range addresses {
		managedAddresses, err := wallet.SortedActivePaymentAddresses()
		require.NoError(t, err)
		require.Contains(t, managedAddresses, addressString)
	}

	props, err := wallet.AccountProperties(
		waddrmgr.KeyScopeBIP0084, account,
	)
	require.NoError(t, err)
	require.Equal(t, "renamed", props.AccountName)
	require.EqualValues(t, 1, props.ExternalKeyCount)
	require.EqualValues(t, 1, props.InternalKeyCount)

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())
}

// TestSQLWalletPassphraseLifecycle verifies private, public, and atomic dual
// passphrase changes remain usable across lock and restart.
func TestSQLWalletPassphraseLifecycle(t *testing.T) {
	t.Parallel()

	params := &chaincfg.TestNet3Params
	pubPass := []byte("public-pass")
	privPass := []byte("private-pass")
	newPubPass := []byte("new-public-pass")
	newPrivPass := []byte("new-private-pass")
	finalPubPass := []byte("final-public-pass")
	finalPrivPass := []byte("final-private-pass")

	conn, err := storesqlite.Open(
		context.Background(), storesqlite.Config{
			DBPath: filepath.Join(t.TempDir(), "wallet.sqlite"),
		},
	)
	require.NoError(t, err)
	require.NoError(t, storesqlite.ApplyMigrations(conn))

	store := dbsqlite.NewNamedStore(conn, "passphrases")
	loader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err := loader.CreateNewWallet(
		pubPass, privPass, nil, time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}
	require.NoError(t, wallet.Unlock(privPass, nil))

	require.NoError(t, wallet.ChangePrivatePassphrase(
		privPass, newPrivPass,
	))
	wallet.Lock()
	require.Eventually(t, wallet.Locked, time.Second, 10*time.Millisecond)
	err = wallet.Unlock(privPass, nil)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase))
	require.NoError(t, wallet.Unlock(newPrivPass, nil))

	require.NoError(t, wallet.ChangePublicPassphrase(pubPass, newPubPass))
	require.NoError(t, wallet.ChangePassphrases(
		newPubPass, finalPubPass, newPrivPass, finalPrivPass,
	))
	require.NoError(t, loader.UnloadWallet())

	wrongLoader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	_, err = wrongLoader.OpenExistingWallet(newPubPass, false)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase))

	loader, err = NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err = loader.OpenExistingWallet(finalPubPass, false)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}
	err = wallet.Unlock(newPrivPass, nil)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase))
	require.NoError(t, wallet.Unlock(finalPrivPass, nil))

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())
}

// TestSQLWalletImportWatchOnlyRestart verifies imported key and script
// reconstruction, lock behavior, and permanent watch-only conversion.
func TestSQLWalletImportWatchOnlyRestart(t *testing.T) {
	t.Parallel()

	params := &chaincfg.TestNet3Params
	pubPass := []byte("public-pass")
	privPass := []byte("private-pass")
	dbPath := filepath.Join(t.TempDir(), "wallet.sqlite")
	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	require.NoError(t, storesqlite.ApplyMigrations(conn))

	store := dbsqlite.NewNamedStore(conn, "imports")
	loader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err := loader.CreateNewWallet(
		pubPass, privPass, nil, time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}
	require.NoError(t, wallet.Unlock(privPass, nil))

	privateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	wif, err := btcutil.NewWIF(privateKey, params, true)
	require.NoError(t, err)
	privateAddress, err := wallet.ImportPrivateKey(
		waddrmgr.KeyScopeBIP0084, wif, nil, false,
	)
	require.NoError(t, err)

	publicKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	require.NoError(t, wallet.ImportPublicKey(
		publicKey.PubKey(), waddrmgr.TaprootPubKey,
	))

	legacyScript := []byte{txscript.OP_TRUE}
	legacyAddress, err := wallet.ImportP2SHRedeemScript(legacyScript)
	require.NoError(t, err)

	block := &waddrmgr.BlockStamp{
		Hash:      *params.GenesisHash,
		Height:    0,
		Timestamp: params.GenesisBlock.Header.Timestamp,
	}
	scopedManager, err := wallet.Manager.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	witnessScript := []byte{txscript.OP_TRUE, txscript.OP_DROP}
	var witnessAddress waddrmgr.ManagedScriptAddress
	err = store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			var err error
			witnessAddress, err =
				scopedManager.ImportWitnessScriptFromStore(
					tx.Addr(), witnessScript, block, 0, true,
				)
			return err
		}, func() {
			witnessAddress = nil
		},
	)
	require.NoError(t, err)

	taprootPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	tapscript := &waddrmgr.Tapscript{
		Type:          waddrmgr.TaprootFullKeyOnly,
		FullOutputKey: taprootPrivateKey.PubKey(),
	}
	taprootAddress, err := wallet.ImportTaprootScript(
		waddrmgr.KeyScopeBIP0086, tapscript, block, 1, true,
	)
	require.NoError(t, err)

	wallet.Lock()
	require.Eventually(t, wallet.Locked, time.Second, 10*time.Millisecond)
	_, err = witnessAddress.Script()
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrLocked))
	_, err = taprootAddress.(waddrmgr.ManagedScriptAddress).Script()
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrLocked))
	require.NoError(t, wallet.Unlock(privPass, nil))

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())

	conn, err = storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	store = dbsqlite.NewNamedStore(conn, "imports")
	loader, err = NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err = loader.OpenExistingWallet(pubPass, false)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}
	require.NoError(t, wallet.Unlock(privPass, nil))

	privateManaged, err := wallet.AddressInfo(wifAddress(t, privateAddress,
		params))
	require.NoError(t, err)
	_, err = privateManaged.(waddrmgr.ManagedPubKeyAddress).PrivKey()
	require.NoError(t, err)

	legacyManaged, err := wallet.AddressInfo(legacyAddress)
	require.NoError(t, err)
	require.Equal(t, legacyScript,
		requireScript(t, legacyManaged.(waddrmgr.ManagedScriptAddress)))
	witnessManaged, err := wallet.AddressInfo(witnessAddress.Address())
	require.NoError(t, err)
	require.Equal(t, witnessScript,
		requireScript(t, witnessManaged.(waddrmgr.ManagedScriptAddress)))
	taprootManaged, err := wallet.AddressInfo(taprootAddress.Address())
	require.NoError(t, err)
	_, err = taprootManaged.(waddrmgr.ManagedTaprootScriptAddress).
		TaprootScript()
	require.NoError(t, err)

	scopedManager, err = wallet.Manager.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	stopReads := make(chan struct{})
	readErr := make(chan error, 1)
	var readWorkers sync.WaitGroup
	readWorkers.Add(1)
	go func() {
		defer readWorkers.Done()
		for {
			select {
			case <-stopReads:
				return

			default:
				_, err := wallet.AccountProperties(
					waddrmgr.KeyScopeBIP0084,
					waddrmgr.DefaultAccountNum,
				)
				if err != nil {
					select {
					case readErr <- err:
					default:
					}
					return
				}
			}
		}
	}()
	require.NoError(t, wallet.InitAccounts(scopedManager, true, 0))
	close(stopReads)
	readWorkers.Wait()
	select {
	case err := <-readErr:
		require.NoError(t, err)

	default:
	}
	require.True(t, wallet.Manager.WatchOnly())
	_, err = privateManaged.(waddrmgr.ManagedPubKeyAddress).PrivKey()
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWatchingOnly))

	var privateRows int
	require.NoError(t, conn.QueryRowContext(t.Context(), `
		SELECT
			(SELECT COUNT(*) FROM wallets
			 WHERE master_priv_params IS NOT NULL
				OR encrypted_crypto_priv_key IS NOT NULL
				OR encrypted_crypto_script_key IS NOT NULL
				OR encrypted_master_hd_priv_key IS NOT NULL) +
			(SELECT COUNT(*) FROM key_scopes
			 WHERE encrypted_coin_priv_key IS NOT NULL) +
			(SELECT COUNT(*) FROM accounts
			 WHERE encrypted_priv_key IS NOT NULL) +
			(SELECT COUNT(*) FROM addresses
			 WHERE encrypted_priv_key IS NOT NULL
				OR (is_secret_script = TRUE
					AND encrypted_script IS NOT NULL))
	`).Scan(&privateRows))
	require.Zero(t, privateRows)

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())
}

// TestSQLWatchingOnlyWalletLifecycle verifies native watch-only creation,
// account import, derivation, private-key downgrading, and restart.
func TestSQLWatchingOnlyWalletLifecycle(t *testing.T) {
	t.Parallel()

	params := &chaincfg.TestNet3Params
	pubPass := []byte("public-pass")
	dbPath := filepath.Join(t.TempDir(), "wallet.sqlite")
	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	require.NoError(t, storesqlite.ApplyMigrations(conn))

	store := dbsqlite.NewNamedStore(conn, "watch-only")
	loader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err := loader.CreateNewWatchingOnlyWallet(
		pubPass, time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}
	require.True(t, wallet.Manager.WatchOnly())
	require.Empty(t, wallet.Manager.ActiveScopedKeyManagers())
	err = wallet.Unlock([]byte("unused"), nil)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWatchingOnly))

	seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
	require.NoError(t, err)
	rootKey, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)
	defer rootKey.Zero()
	purposeKey, err := rootKey.DeriveNonStandard(
		waddrmgr.KeyScopeBIP0084.Purpose + hdkeychain.HardenedKeyStart,
	)
	require.NoError(t, err)
	defer purposeKey.Zero()
	coinKey, err := purposeKey.DeriveNonStandard(
		waddrmgr.KeyScopeBIP0084.Coin + hdkeychain.HardenedKeyStart,
	)
	require.NoError(t, err)
	defer coinKey.Zero()
	accountKey, err := coinKey.DeriveNonStandard(
		hdkeychain.HardenedKeyStart,
	)
	require.NoError(t, err)
	defer accountKey.Zero()
	accountPubKey, err := accountKey.Neuter()
	require.NoError(t, err)
	defer accountPubKey.Zero()

	addrType := waddrmgr.WitnessPubKey
	dryProps, external, internal, err := wallet.ImportAccountDryRun(
		"watch account", accountPubKey, 0, &addrType, 2,
	)
	require.NoError(t, err)
	require.EqualValues(t, 2, dryProps.ExternalKeyCount)
	require.EqualValues(t, 2, dryProps.InternalKeyCount)
	require.Len(t, external, 2)
	require.Len(t, internal, 2)
	_, err = wallet.AccountNumber(
		waddrmgr.KeyScopeBIP0084, "watch account",
	)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound))

	props, err := wallet.ImportAccount(
		"watch account", accountPubKey, 0, &addrType,
	)
	require.NoError(t, err)
	require.True(t, props.IsWatchOnly)
	require.Equal(t, uint32(0), props.AccountNumber)
	watchAddress, err := wallet.NewAddress(
		props.AccountNumber, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)

	scopedManager, err := wallet.Manager.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	block := &waddrmgr.BlockStamp{
		Hash:      *params.GenesisHash,
		Height:    0,
		Timestamp: params.GenesisBlock.Header.Timestamp,
	}
	publicScript := []byte{txscript.OP_TRUE, txscript.OP_TRUE}
	var publicScriptAddress waddrmgr.ManagedScriptAddress
	err = store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			var err error
			publicScriptAddress, err =
				scopedManager.ImportWitnessScriptFromStore(
					tx.Addr(), publicScript, block, 0, false,
				)
			return err
		}, func() {
			publicScriptAddress = nil
		},
	)
	require.NoError(t, err)
	require.Equal(t, publicScript, requireScript(t, publicScriptAddress))

	taprootPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	publicTapscript := &waddrmgr.Tapscript{
		Type:          waddrmgr.TaprootFullKeyOnly,
		FullOutputKey: taprootPrivateKey.PubKey(),
	}
	publicTaprootAddress, err := wallet.ImportTaprootScript(
		waddrmgr.KeyScopeBIP0084, publicTapscript, block, 1, false,
	)
	require.NoError(t, err)

	privateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	wif, err := btcutil.NewWIF(privateKey, params, true)
	require.NoError(t, err)
	importedAddress, err := wallet.ImportPrivateKey(
		waddrmgr.KeyScopeBIP0084, wif, nil, false,
	)
	require.NoError(t, err)
	managed, err := wallet.AddressInfo(wifAddress(t, importedAddress, params))
	require.NoError(t, err)
	_, err = managed.(waddrmgr.ManagedPubKeyAddress).PrivKey()
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWatchingOnly))

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())

	conn, err = storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	store = dbsqlite.NewNamedStore(conn, "watch-only")
	loader, err = NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err = loader.OpenExistingWallet(pubPass, false)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}
	require.True(t, wallet.Manager.WatchOnly())

	have, err := wallet.HaveAddress(watchAddress)
	require.NoError(t, err)
	require.True(t, have)
	have, err = wallet.HaveAddress(wifAddress(t, importedAddress, params))
	require.NoError(t, err)
	require.True(t, have)
	publicManaged, err := wallet.AddressInfo(publicScriptAddress.Address())
	require.NoError(t, err)
	require.Equal(t, publicScript,
		requireScript(t, publicManaged.(waddrmgr.ManagedScriptAddress)))
	publicTaprootManaged, err := wallet.AddressInfo(
		publicTaprootAddress.Address(),
	)
	require.NoError(t, err)
	_, err = publicTaprootManaged.(waddrmgr.ManagedTaprootScriptAddress).
		TaprootScript()
	require.NoError(t, err)

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())
}

// TestSQLLifecycleCommitSafety verifies allocation rollback, ambiguous import
// refresh, durable start-block monotonicity, and ambiguous scope attachment.
func TestSQLLifecycleCommitSafety(t *testing.T) {
	t.Parallel()

	params := &chaincfg.TestNet3Params
	pubPass := []byte("public-pass")
	privPass := []byte("private-pass")
	dbPath := filepath.Join(t.TempDir(), "wallet.sqlite")
	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	require.NoError(t, storesqlite.ApplyMigrations(conn))

	store := dbsqlite.NewNamedStore(conn, "commit-safety")
	loader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err := loader.CreateNewWallet(
		pubPass, privPass, nil, time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}
	require.NoError(t, wallet.Unlock(privPass, nil))

	scopedManager, err := wallet.Manager.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	rollbackErr := errors.New("rollback two allocations")
	var attempted []address.Address
	err = store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			for range 2 {
				managed, _, err :=
					scopedManager.NextExternalAddressFromStore(
						tx.Addr(), waddrmgr.DefaultAccountNum,
					)
				if err != nil {
					return err
				}
				attempted = append(attempted, managed.Address())
			}

			return rollbackErr
		}, func() {
			attempted = nil
		},
	)
	require.ErrorIs(t, err, rollbackErr)
	require.Len(t, attempted, 2)
	props, err := wallet.AccountProperties(
		waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
	)
	require.NoError(t, err)
	require.Zero(t, props.ExternalKeyCount)
	first, err := wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	second, err := wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	require.Equal(t, attempted[0].String(), first.String())
	require.Equal(t, attempted[1].String(), second.String())

	seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
	require.NoError(t, err)
	rootKey, err := hdkeychain.NewMaster(seed, params)
	require.NoError(t, err)
	defer rootKey.Zero()
	accountKey := rootKey
	for _, child := range []uint32{
		waddrmgr.KeyScopeBIP0084.Purpose + hdkeychain.HardenedKeyStart,
		waddrmgr.KeyScopeBIP0084.Coin + hdkeychain.HardenedKeyStart,
		hdkeychain.HardenedKeyStart,
	} {
		accountKey, err = accountKey.DeriveNonStandard(child)
		require.NoError(t, err)
	}
	defer accountKey.Zero()
	privateScope := waddrmgr.KeyScope{Purpose: 1_019, Coin: 1}
	_, err = wallet.ImportAccountWithScope(
		"private", accountKey, 0, privateScope,
		waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084],
	)
	require.ErrorContains(t, err, "private keys cannot be imported")
	_, err = wallet.Manager.FetchScopedKeyManager(privateScope)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound))

	taprootKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	tapscript := &waddrmgr.Tapscript{
		Type:          waddrmgr.TaprootFullKeyOnly,
		FullOutputKey: taprootKey.PubKey(),
	}
	for _, version := range []byte{0, 2} {
		_, err := wallet.ImportTaprootScript(
			waddrmgr.KeyScopeBIP0086, tapscript, nil, version, true,
		)
		require.ErrorContains(t, err, "invalid witness version")
	}

	highStart := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{10},
		Height:    10,
		Timestamp: time.Unix(10, 0),
	}
	err = store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			state, err := tx.Addr().SyncState()
			if err != nil {
				return err
			}
			state.StartBlock = highStart
			return tx.Addr().PutSyncState(state)
		}, nil,
	)
	require.NoError(t, err)
	require.NoError(t, loader.UnloadWallet())

	loader, err = NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err = loader.OpenExistingWallet(pubPass, false)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}
	require.NoError(t, wallet.Unlock(privPass, nil))

	ambiguousStore := &ambiguousCommitStore{
		Store:                   store,
		ambiguousNextUpdateOnce: true,
	}
	wallet.store = ambiguousStore
	privateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	wif, err := btcutil.NewWIF(privateKey, params, true)
	require.NoError(t, err)
	lowerStart := &waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{5},
		Height:    5,
		Timestamp: time.Unix(5, 0),
	}
	_, err = wallet.ImportPrivateKey(
		waddrmgr.KeyScopeBIP0084, wif, lowerStart, false,
	)
	var ambiguous *walletstore.AmbiguousCommitError
	require.ErrorAs(t, err, &ambiguous)

	err = store.View(t.Context(), func(tx walletstore.ReadTx) error {
		state, err := tx.Addr().SyncState()
		require.NoError(t, err)
		require.Equal(t, lowerStart.Height, state.StartBlock.Height)
		return nil
	}, nil)
	require.NoError(t, err)

	durableStart := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{3},
		Height:    3,
		Timestamp: time.Unix(3, 0),
	}
	err = store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			state, err := tx.Addr().SyncState()
			if err != nil {
				return err
			}
			state.StartBlock = durableStart
			return tx.Addr().PutSyncState(state)
		}, nil,
	)
	require.NoError(t, err)

	secondPrivateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	secondWIF, err := btcutil.NewWIF(secondPrivateKey, params, true)
	require.NoError(t, err)
	staleCacheStart := &waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{4},
		Height:    4,
		Timestamp: time.Unix(4, 0),
	}
	_, err = wallet.ImportPrivateKey(
		waddrmgr.KeyScopeBIP0084, secondWIF, staleCacheStart, false,
	)
	require.NoError(t, err)
	err = store.View(t.Context(), func(tx walletstore.ReadTx) error {
		state, err := tx.Addr().SyncState()
		require.NoError(t, err)
		require.Equal(t, durableStart.Height, state.StartBlock.Height)
		return nil
	}, nil)
	require.NoError(t, err)

	customScope := waddrmgr.KeyScope{Purpose: 1_020, Coin: 1}
	customSchema := waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.WitnessPubKey,
		InternalAddrType: waddrmgr.TaprootPubKey,
	}
	ambiguousStore.ambiguousNextUpdateOnce = true
	attached, err := wallet.AddScopeManager(customScope, customSchema)
	require.NoError(t, err)
	require.Equal(t, customScope, attached.Scope())
	fetched, err := wallet.Manager.FetchScopedKeyManager(customScope)
	require.NoError(t, err)
	require.Same(t, attached, fetched)

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())
}

// TestSQLChainLifecycleEntryPoints verifies Store-backed connected, relevant,
// and disconnected notifications mutate both manager domains without walletdb.
func TestSQLChainLifecycleEntryPoints(t *testing.T) {
	t.Parallel()

	params := &chaincfg.TestNet3Params
	conn, err := storesqlite.Open(
		context.Background(), storesqlite.Config{
			DBPath: filepath.Join(t.TempDir(), "wallet.sqlite"),
		},
	)
	require.NoError(t, err)
	require.NoError(t, storesqlite.ApplyMigrations(conn))

	store := dbsqlite.NewNamedStore(conn, "chain-lifecycle")
	loader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err := loader.CreateNewWallet(
		[]byte("public-pass"), []byte("private-pass"), nil,
		time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	client := &mockChainClient{
		getBlockHeader: &params.GenesisBlock.Header,
	}
	wallet.chainClient = client

	receiveAddress, err := wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(receiveAddress)
	require.NoError(t, err)

	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   chainhash.Hash{1},
			Height: 1,
		},
		Time: time.Unix(1, 0),
	}
	ambiguousStore := &ambiguousCommitStore{
		Store:               store,
		ambiguousNextUpdate: true,
	}
	wallet.store = ambiguousStore
	err = wallet.updateChainStore(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			return wallet.connectBlockFromStore(tx, block)
		}, func(tx walletstore.ReadTx) (bool, error) {
			return syncBlockCommitted(tx, block)
		},
	)
	require.NoError(t, err)
	require.Equal(t, block.Height, wallet.Manager.SyncedTo().Height)

	msgTx := wire.NewMsgTx(2)
	msgTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  chainhash.Hash{9},
		Index: 0,
	}})
	msgTx.AddTxOut(&wire.TxOut{Value: 50_000, PkScript: pkScript})
	record, err := wtxmgr.NewTxRecordFromMsgTx(msgTx, time.Unix(1, 0))
	require.NoError(t, err)
	err = store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			return wallet.addRelevantTxFromStore(tx, record, &block)
		}, nil,
	)
	require.NoError(t, err)

	managed, err := wallet.AddressInfo(receiveAddress)
	require.NoError(t, err)
	require.True(t, managed.Used(nil))
	wallet.SetChainSynced(true)
	rewound, err := wallet.disconnectBlockFromStore(client, block)
	require.NoError(t, err)
	require.True(t, rewound)
	require.Zero(t, wallet.Manager.SyncedTo().Height)

	err = store.View(t.Context(), func(tx walletstore.ReadTx) error {
		details, err := tx.Tx().TxDetails(&record.Hash)
		require.NoError(t, err)
		require.Equal(t, int32(-1), details.Block.Height)
		return nil
	}, nil)
	require.NoError(t, err)

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())
}

// TestSQLWalletTransactionLifecycle verifies the public transaction, balance,
// UTXO, label, lease, and descendant-removal APIs across a SQLite restart.
//
//nolint:cyclop,maintidx,noinlineerr // One lifecycle covers one wallet.
func TestSQLWalletTransactionLifecycle(t *testing.T) {
	t.Parallel()

	params := &chaincfg.TestNet3Params
	dbPath := filepath.Join(t.TempDir(), "wallet.sqlite")
	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	require.NoError(t, storesqlite.ApplyMigrations(conn))

	store := dbsqlite.NewNamedStore(conn, "transactions")
	loader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err := loader.CreateNewWallet(
		[]byte("public-pass"), []byte("private-pass"), nil,
		time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{getBestBlockHeight: 1}

	receiveAddress, err := wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0044,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(receiveAddress)
	require.NoError(t, err)

	rollbackAddress, err := wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0044,
	)
	require.NoError(t, err)
	rollbackScript, err := txscript.PayToAddrScript(rollbackAddress)
	require.NoError(t, err)
	rollbackTx := wire.NewMsgTx(2)
	rollbackTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{7},
	}})
	rollbackTx.AddTxOut(&wire.TxOut{
		Value: 25_000, PkScript: rollbackScript,
	})
	rollbackRecord, err := wtxmgr.NewTxRecordFromMsgTx(
		rollbackTx, time.Unix(10, 0),
	)
	require.NoError(t, err)
	rollbackErr := errors.New("rollback relevant transaction")
	err = store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			if err := wallet.addRelevantTxFromStore(
				tx, rollbackRecord, nil,
			); err != nil {

				return err
			}

			return rollbackErr
		}, nil,
	)
	require.ErrorIs(t, err, rollbackErr)
	rollbackManaged, err := wallet.AddressInfo(rollbackAddress)
	require.NoError(t, err)
	require.False(t, rollbackManaged.Used(nil))
	err = store.View(t.Context(), func(tx walletstore.ReadTx) error {
		state, err := tx.Addr().Address(
			waddrmgr.KeyScopeBIP0044, rollbackAddress.ScriptAddress(),
		)
		require.NoError(t, err)
		require.False(t, state.Used)

		return nil
	}, nil)
	require.NoError(t, err)
	_, err = wallet.GetTransaction(rollbackRecord.Hash)
	require.ErrorIs(t, err, ErrNoTx)

	fundingTx := wire.NewMsgTx(2)
	fundingTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  chainhash.Hash{8},
		Index: 1,
	}})
	fundingTx.AddTxOut(&wire.TxOut{Value: 50_000, PkScript: pkScript})
	funding, err := wtxmgr.NewTxRecordFromMsgTx(
		fundingTx, time.Unix(11, 0),
	)
	require.NoError(t, err)

	spentness := wallet.NtfnServer.AccountSpentnessNotifications(0)
	transactions := wallet.NtfnServer.TransactionNotifications()
	updateErr := make(chan error, 1)
	go func() {
		updateErr <- store.UpdateOnce(
			t.Context(), func(tx walletstore.ReadWriteTx) error {
				return wallet.addRelevantTxFromStore(tx, funding, nil)
			}, nil,
		)
	}()
	select {
	case notification := <-spentness.C:
		require.Equal(t, funding.Hash, *notification.Hash())
		require.Equal(t, uint32(0), notification.Index())

	case <-time.After(time.Second):
		t.Fatal("unspent notification not published after commit")
	}
	select {
	case notification := <-transactions.C:
		require.Len(t, notification.UnminedTransactions, 1)
		require.Equal(
			t, funding.Hash,
			*notification.UnminedTransactions[0].Hash,
		)

	case <-time.After(time.Second):
		t.Fatal("transaction notification not published after commit")
	}
	require.NoError(t, <-updateErr)
	spentness.Done()
	transactions.Done()

	balance, err := wallet.CalculateBalance(0)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(50_000), balance)
	accountBalances, err := wallet.CalculateAccountBalances(
		waddrmgr.DefaultAccountNum, 0,
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(50_000), accountBalances.Total)
	require.Equal(t, btcutil.Amount(50_000), accountBalances.Spendable)

	balances, err := wallet.AccountBalances(waddrmgr.KeyScopeBIP0044, 0)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(50_000), balances[0].AccountBalance)
	accounts, err := wallet.Accounts(waddrmgr.KeyScopeBIP0044)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(50_000), accounts.Accounts[0].TotalBalance)

	unspent, err := wallet.ListUnspent(0, 1, "")
	require.NoError(t, err)
	require.Len(t, unspent, 1)
	outputs, err := wallet.UnspentOutputs(OutputSelectionPolicy{
		Account: waddrmgr.DefaultAccountNum,
	})
	require.NoError(t, err)
	require.Len(t, outputs, 1)

	outpoint := wire.OutPoint{Hash: funding.Hash, Index: 0}
	knownTx, knownOutput, confirmations, err := wallet.FetchOutpointInfo(
		&outpoint,
	)
	require.NoError(t, err)
	require.Equal(t, funding.Hash, knownTx.TxHash())
	require.Equal(t, int64(50_000), knownOutput.Value)
	require.Zero(t, confirmations)

	result, err := wallet.GetTransaction(funding.Hash)
	require.NoError(t, err)
	require.Equal(t, int32(-1), result.Height)
	require.Len(t, result.Summary.MyOutputs, 1)
	allTransactions, err := wallet.ListAllTransactions()
	require.NoError(t, err)
	require.Len(t, allTransactions, 1)
	recentTransactions, err := wallet.ListTransactions(0, 10)
	require.NoError(t, err)
	require.Len(t, recentTransactions, 1)
	sinceBlock, err := wallet.ListSinceBlock(0, -1, 0)
	require.NoError(t, err)
	require.Len(t, sinceBlock, 1)
	rangeResult, err := wallet.GetTransactions(nil, nil, "", nil)
	require.NoError(t, err)
	require.Len(t, rangeResult.UnminedTransactions, 1)
	pubKeyHash, ok := receiveAddress.(*address.AddressPubKeyHash)
	require.True(t, ok)
	addressTransactions, err := wallet.ListAddressTransactions(
		map[string]struct{}{string(pubKeyHash.ScriptAddress()): {}},
	)
	require.NoError(t, err)
	require.Len(t, addressTransactions, 1)

	totals, err := wallet.TotalReceivedForAccounts(
		waddrmgr.KeyScopeBIP0044, 0,
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(50_000), totals[0].TotalReceived)

	total, err := wallet.TotalReceivedForAddr(receiveAddress, 0)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(50_000), total)

	details, err := UnstableAPI(wallet).TxDetails(&funding.Hash)
	require.NoError(t, err)
	require.Equal(t, funding.Hash, details.Hash)

	var ranged []chainhash.Hash

	err = UnstableAPI(wallet).RangeTransactions(
		0, -1, func(details []wtxmgr.TxDetails) (bool, error) {
			for _, detail := range details {
				ranged = append(ranged, detail.Hash)
			}

			return false, nil
		},
	)
	require.NoError(t, err)
	require.Equal(t, []chainhash.Hash{funding.Hash}, ranged)

	require.NoError(t, wallet.LabelTransaction(
		funding.Hash, "funding", false,
	))
	err = wallet.LabelTransaction(funding.Hash, "duplicate", false)
	require.ErrorIs(t, err, ErrTxLabelExists)
	require.NoError(t, wallet.LabelTransaction(
		funding.Hash, "funding updated", true,
	))
	result, err = wallet.GetTransaction(funding.Hash)
	require.NoError(t, err)
	require.Equal(t, "funding updated", result.Summary.Label)

	lockID := wtxmgr.LockID{1}
	expiry, err := wallet.LeaseOutput(lockID, outpoint, time.Hour)
	require.NoError(t, err)
	require.True(t, expiry.After(time.Now()))
	_, err = wallet.LeaseOutput(wtxmgr.LockID{2}, outpoint, time.Hour)
	require.ErrorIs(t, err, wtxmgr.ErrOutputAlreadyLocked)
	leased, err := wallet.ListLeasedOutputs()
	require.NoError(t, err)
	require.Len(t, leased, 1)
	balance, err = wallet.CalculateBalance(0)
	require.NoError(t, err)
	require.Zero(t, balance)
	err = wallet.ReleaseOutput(wtxmgr.LockID{2}, outpoint)
	require.ErrorIs(t, err, wtxmgr.ErrOutputUnlockNotAllowed)
	require.NoError(t, wallet.ReleaseOutput(lockID, outpoint))

	_, err = wallet.LeaseOutput(lockID, outpoint, time.Millisecond)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		leased, err := wallet.ListLeasedOutputs()
		return err == nil && len(leased) == 0
	}, time.Second, 10*time.Millisecond)

	spenderTx := wire.NewMsgTx(2)
	spenderTx.AddTxIn(&wire.TxIn{PreviousOutPoint: outpoint})
	spenderTx.AddTxOut(&wire.TxOut{Value: 49_000, PkScript: []byte{0x51}})
	spender, err := wtxmgr.NewTxRecordFromMsgTx(
		spenderTx, time.Unix(12, 0),
	)
	require.NoError(t, err)
	rejectedTx := spenderTx.Copy()
	rejectedTx.TxOut[0].Value = 48_500
	rejectedRecord, err := wtxmgr.NewTxRecordFromMsgTx(
		rejectedTx, time.Unix(12, 0),
	)
	require.NoError(t, err)
	broadcastErr := errors.New("transaction rejected")
	wallet.chainClient = &rejectingChainClient{
		mockChainClient: &mockChainClient{getBestBlockHeight: 1},
		err:             broadcastErr,
	}
	err = wallet.PublishTransaction(rejectedTx, "")
	require.ErrorIs(t, err, broadcastErr)
	_, err = wallet.GetTransaction(rejectedRecord.Hash)
	require.ErrorIs(t, err, ErrNoTx)
	balance, err = wallet.CalculateBalance(0)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(50_000), balance)
	wallet.chainClient = &mockChainClient{getBestBlockHeight: 1}

	err = store.UpdateOnce(t.Context(), func(tx walletstore.ReadWriteTx) error {
		return wallet.addRelevantTxFromStore(tx, spender, nil)
	}, nil)
	require.NoError(t, err)
	spenderResult, err := wallet.GetTransaction(spender.Hash)
	require.NoError(t, err)
	require.Len(t, spenderResult.Summary.MyInputs, 1)
	balance, err = wallet.CalculateBalance(0)
	require.NoError(t, err)
	require.Zero(t, balance)

	childTx := wire.NewMsgTx(2)
	childTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: spender.Hash,
	}})
	childTx.AddTxOut(&wire.TxOut{Value: 48_000, PkScript: []byte{0x51}})
	child, err := wtxmgr.NewTxRecordFromMsgTx(childTx, time.Unix(13, 0))
	require.NoError(t, err)
	err = store.UpdateOnce(t.Context(), func(tx walletstore.ReadWriteTx) error {
		return wallet.addRelevantTxFromStore(tx, child, nil)
	}, nil)
	require.NoError(t, err)
	require.NoError(t, wallet.RemoveDescendants(spenderTx))
	_, err = wallet.GetTransaction(spender.Hash)
	require.ErrorIs(t, err, ErrNoTx)
	_, err = wallet.GetTransaction(child.Hash)
	require.ErrorIs(t, err, ErrNoTx)
	balance, err = wallet.CalculateBalance(0)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(50_000), balance)

	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: chainhash.Hash{1}, Height: 1},
		Time:  time.Unix(14, 0),
	}
	blockNotifications := wallet.NtfnServer.TransactionNotifications()
	blockErr := make(chan error, 1)
	go func() {
		blockErr <- store.UpdateOnce(
			t.Context(), func(tx walletstore.ReadWriteTx) error {
				if err := wallet.addRelevantTxFromStore(
					tx, funding, &block,
				); err != nil {

					return err
				}

				return wallet.connectBlockFromStore(tx, block)
			}, nil,
		)
	}()
	select {
	case notification := <-blockNotifications.C:
		require.Len(t, notification.AttachedBlocks, 1)
		require.Len(t, notification.AttachedBlocks[0].Transactions, 1)
		require.Equal(
			t, funding.Hash,
			*notification.AttachedBlocks[0].Transactions[0].Hash,
		)

	case <-time.After(time.Second):
		t.Fatal("block notification not published after commit")
	}
	require.NoError(t, <-blockErr)
	blockNotifications.Done()
	result, err = wallet.GetTransaction(funding.Hash)
	require.NoError(t, err)
	require.Equal(t, int32(1), result.Height)
	require.Equal(t, int32(1), result.Confirmations)

	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())
	conn, err = storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	require.NoError(t, err)
	store = dbsqlite.NewNamedStore(conn, "transactions")
	loader, err = NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err = loader.OpenExistingWallet([]byte("public-pass"), false)
	require.NoError(t, err)
	result, err = wallet.GetTransaction(funding.Hash)
	require.NoError(t, err)
	require.Equal(t, "funding updated", result.Summary.Label)
	require.Equal(t, int32(1), result.Height)
	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())
}

// TestSQLAccountScopesAndNotifications verifies sparse account aggregation,
// scope isolation, and spentness notification routing for a non-default
// account.
func TestSQLAccountScopesAndNotifications(t *testing.T) {
	t.Parallel()

	params := &chaincfg.TestNet3Params
	conn, err := storesqlite.Open(
		context.Background(), storesqlite.Config{
			DBPath: filepath.Join(t.TempDir(), "wallet.sqlite"),
		},
	)
	require.NoError(t, err)
	require.NoError(t, storesqlite.ApplyMigrations(conn))
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})

	store := dbsqlite.NewNamedStore(conn, "account-scopes")
	loader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	wallet, err := loader.CreateNewWallet(
		[]byte("public-pass"), []byte("private-pass"), nil,
		time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)

	wallet.chainClient = &mockChainClient{}
	require.NoError(t, wallet.Unlock([]byte("private-pass"), nil))
	t.Cleanup(func() {
		require.NoError(t, loader.UnloadWallet())
	})

	const sparseAccount = uint32(7)

	manager, err := wallet.Manager.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0044,
	)
	require.NoError(t, err)
	require.NoError(t, store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			return manager.NewRawAccountFromStore(tx.Addr(), sparseAccount)
		}, nil,
	))

	sparseAddress, err := wallet.NewAddress(
		sparseAccount, waddrmgr.KeyScopeBIP0044,
	)
	require.NoError(t, err)
	otherScopeAddress, err := wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)

	newFunding := func(marker byte, value int64,
		addr address.Address) *wtxmgr.TxRecord {

		t.Helper()

		pkScript, err := txscript.PayToAddrScript(addr)
		require.NoError(t, err)

		msgTx := wire.NewMsgTx(2)
		msgTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{marker},
			Index: 1,
		}})
		msgTx.AddTxOut(&wire.TxOut{Value: value, PkScript: pkScript})
		record, err := wtxmgr.NewTxRecordFromMsgTx(
			msgTx, time.Unix(100+int64(marker), 0),
		)
		require.NoError(t, err)

		return record
	}
	sparseFunding := newFunding(1, 70_000, sparseAddress)
	otherFunding := newFunding(2, 80_000, otherScopeAddress)

	spentness := wallet.NtfnServer.AccountSpentnessNotifications(
		sparseAccount,
	)
	updateErr := make(chan error, 1)

	go func() {
		updateErr <- store.UpdateOnce(
			t.Context(), func(tx walletstore.ReadWriteTx) error {
				return wallet.addRelevantTxFromStore(
					tx, sparseFunding, nil,
				)
			}, nil,
		)
	}()

	select {
	case notification := <-spentness.C:
		require.Equal(t, sparseFunding.Hash, *notification.Hash())
		require.Equal(t, uint32(0), notification.Index())

	case <-time.After(time.Second):
		t.Fatal("non-default account did not receive unspent notification")
	}

	require.NoError(t, <-updateErr)
	spentness.Done()

	require.NoError(t, store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			return wallet.addRelevantTxFromStore(tx, otherFunding, nil)
		}, nil,
	))

	accounts, err := wallet.Accounts(waddrmgr.KeyScopeBIP0044)
	require.NoError(t, err)

	accountBalances := make(map[uint32]btcutil.Amount)
	for _, account := range accounts.Accounts {
		accountBalances[account.AccountNumber] = account.TotalBalance
	}

	require.Equal(t, btcutil.Amount(70_000),
		accountBalances[sparseAccount])
	require.Zero(t, accountBalances[waddrmgr.DefaultAccountNum])

	totals, err := wallet.TotalReceivedForAccounts(
		waddrmgr.KeyScopeBIP0044, 0,
	)
	require.NoError(t, err)

	received := make(map[uint32]btcutil.Amount)
	for _, total := range totals {
		received[total.AccountNumber] = total.TotalReceived
	}

	require.Equal(t, btcutil.Amount(70_000), received[sparseAccount])
	require.Zero(t, received[waddrmgr.DefaultAccountNum])

	otherTotals, err := wallet.TotalReceivedForAccounts(
		waddrmgr.KeyScopeBIP0084, 0,
	)
	require.NoError(t, err)

	otherReceived := make(map[uint32]btcutil.Amount)
	for _, total := range otherTotals {
		otherReceived[total.AccountNumber] = total.TotalReceived
	}

	require.Equal(t, btcutil.Amount(80_000),
		otherReceived[waddrmgr.DefaultAccountNum])

}

// wifAddress decodes an address returned by ImportPrivateKey for a test.
//
//nolint:ireturn // The helper returns the decoded address interface.
func wifAddress(t *testing.T, encoded string,
	params *chaincfg.Params) address.Address {

	t.Helper()

	addr, err := address.DecodeAddress(encoded, params)
	require.NoError(t, err)

	return addr
}

// requireScript returns a managed script's clear text for a test.
func requireScript(t *testing.T,
	managed waddrmgr.ManagedScriptAddress) []byte {

	t.Helper()

	script, err := managed.Script()
	require.NoError(t, err)

	return script
}
