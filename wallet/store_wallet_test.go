package wallet

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	walletkvdb "github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	storesqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	sqlitedb "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// managerFixture contains the durable address-manager state copied from a
// normal KV wallet before the SQLite-only runtime starts.
type managerFixture struct {
	manager   waddrmgr.ManagerState
	sync      waddrmgr.SyncState
	scopes    []waddrmgr.KeyScopeState
	accounts  []waddrmgr.AccountState
	addresses []managerAddressFixture
}

// managerAddressFixture couples backend-neutral address state with the legacy
// identifier whose digest is stored by SQL.
type managerAddressFixture struct {
	id    []byte
	state waddrmgr.AddressState
}

// readManagerFixture copies manager state through the KV Store adapter and
// resolves each address's legacy identifier through the real manager.
func readManagerFixture(t *testing.T, store walletstore.Store,
	database walletdb.DB, manager *waddrmgr.Manager) managerFixture {

	t.Helper()

	var fixture managerFixture
	addressStates := make(map[string]waddrmgr.AddressState)
	err := store.View(t.Context(), func(tx walletstore.ReadTx) error {
		var err error
		fixture.manager, err = tx.Addr().ManagerState()
		if err != nil {
			return err
		}

		fixture.sync, err = tx.Addr().SyncState()
		if err != nil {
			return err
		}

		fixture.scopes, err = tx.Addr().KeyScopes()
		if err != nil {
			return err
		}

		for _, scope := range fixture.scopes {
			accounts, err := tx.Addr().Accounts(scope.Scope)
			if err != nil {
				return err
			}

			for _, account := range accounts {
				// SQL represents the imported account's absent HD key as an
				// empty, non-null blob.
				if account.Account == waddrmgr.ImportedAddrAccount {
					account.EncryptedPubKey = []byte{}
				}

				fixture.accounts = append(fixture.accounts, account)
			}

			addresses, err := tx.Addr().ActiveAddresses(scope.Scope)
			if err != nil {
				return err
			}
			for _, state := range addresses {
				addressStates[string(state.Hash)] = state
			}
		}

		return nil
	}, func() {})
	require.NoError(t, err)

	err = walletdb.View(database, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		for _, scope := range fixture.scopes {
			scoped, err := manager.FetchScopedKeyManager(scope.Scope)
			if err != nil {
				return err
			}

			err = scoped.ForEachActiveAddress(
				ns, func(addr address.Address) error {
					id := addr.ScriptAddress()
					hash := sha256.Sum256(id)
					state, ok := addressStates[string(hash[:])]
					if !ok {
						return errors.New("address state not found")
					}

					fixture.addresses = append(
						fixture.addresses, managerAddressFixture{
							id:    append([]byte(nil), id...),
							state: state,
						},
					)
					delete(addressStates, string(hash[:]))

					return nil
				},
			)
			if err != nil {
				return err
			}
		}

		return nil
	})
	require.NoError(t, err)
	require.Empty(t, addressStates)

	return fixture
}

// putFixtureBlock inserts one block required by the SQLite wallet lifecycle
// foreign keys.
func putFixtureBlock(t *testing.T, queries *sqlitedb.Queries, walletID int64,
	block waddrmgr.BlockStamp) {

	t.Helper()
	require.NoError(t, queries.EnsureBlockHeight(
		t.Context(), sqlitedb.EnsureBlockHeightParams{
			BlockHeight:    int64(block.Height),
			HeaderHash:     block.Hash[:],
			BlockTimestamp: block.Timestamp.Unix(),
		},
	))
	require.NoError(t, queries.InsertBlock(t.Context(),
		sqlitedb.InsertBlockParams{
			WalletID:       walletID,
			BlockHeight:    int64(block.Height),
			HeaderHash:     block.Hash[:],
			BlockTimestamp: block.Timestamp.Unix(),
		}))
}

// writeManagerFixture materializes the pre-migrated fixture through SQLite
// lifecycle queries and the backend-neutral Store.
func writeManagerFixture(t *testing.T, conn *sql.DB,
	fixture managerFixture) (int64, walletstore.Store) {

	t.Helper()
	queries := sqlitedb.New(conn)

	birthdayHeight := sql.NullInt64{}
	if fixture.sync.BirthdayBlock != nil {
		birthdayHeight = sql.NullInt64{
			Int64: int64(fixture.sync.BirthdayBlock.Height),
			Valid: true,
		}
	}

	walletID, err := queries.CreateWallet(
		t.Context(), sqlitedb.CreateWalletParams{
			WalletName:               "store-wallet",
			ManagerVersion:           int64(fixture.manager.Version),
			ManagerCreatedAt:         fixture.manager.CreatedAt.Unix(),
			IsWatchOnly:              fixture.manager.WatchOnly,
			MasterPubParams:          fixture.manager.MasterPubParams,
			MasterPrivParams:         fixture.manager.MasterPrivParams,
			EncryptedCryptoPubKey:    fixture.manager.EncryptedCryptoPubKey,
			EncryptedCryptoPrivKey:   fixture.manager.EncryptedCryptoPrivKey,
			EncryptedCryptoScriptKey: fixture.manager.EncryptedCryptoScriptKey,
			EncryptedMasterHdPubKey:  fixture.manager.EncryptedMasterHDPubKey,
			EncryptedMasterHdPrivKey: fixture.manager.EncryptedMasterHDPrivKey,
		},
	)
	require.NoError(t, err)
	putFixtureBlock(t, queries, walletID, fixture.sync.StartBlock)
	putFixtureBlock(t, queries, walletID, fixture.sync.SyncedTo)

	if fixture.sync.BirthdayBlock != nil {
		putFixtureBlock(t, queries, walletID, *fixture.sync.BirthdayBlock)
	}

	require.NoError(t, queries.PutWalletSyncState(
		t.Context(), sqlitedb.PutWalletSyncStateParams{
			WalletID:              walletID,
			StartBlockHeight:      int64(fixture.sync.StartBlock.Height),
			SyncedBlockHeight:     int64(fixture.sync.SyncedTo.Height),
			BirthdayTimestamp:     fixture.sync.Birthday.Unix(),
			BirthdayBlockHeight:   birthdayHeight,
			BirthdayBlockVerified: fixture.sync.BirthdayBlockVerified,
		},
	))

	store := dbsqlite.NewStore(conn, walletID)
	err = store.Update(t.Context(), func(tx walletstore.ReadWriteTx) error {
		for _, scope := range fixture.scopes {
			if err := tx.Addr().PutKeyScope(scope); err != nil {
				return err
			}
		}

		for _, account := range fixture.accounts {
			if err := tx.Addr().PutAccount(account); err != nil {
				return err
			}
		}

		for _, address := range fixture.addresses {
			if err := tx.Addr().PutAddress(
				address.id, address.state,
			); err != nil {
				return err
			}
		}

		return nil
	}, func() {})
	require.NoError(t, err)

	return walletID, store
}

// openStoreWallet opens and starts the existing Wallet through the Store-only
// Loader mode.
func openStoreWallet(t *testing.T, params *chaincfg.Params,
	store walletstore.Store, pubPass []byte) (*Loader, *Wallet) {

	t.Helper()
	loader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)

	wallet, err := loader.OpenExistingWallet(pubPass, false)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}

	return loader, wallet
}

// requireManagedPrivateKey verifies that an address reconstructed or allocated
// by the store-backed manager exposes its private key while unlocked.
func requireManagedPrivateKey(t *testing.T, managed waddrmgr.ManagedAddress) {
	t.Helper()

	pubKeyAddr, ok := managed.(waddrmgr.ManagedPubKeyAddress)
	require.True(t, ok)
	privKey, err := pubKeyAddr.PrivKey()
	require.NoError(t, err)
	privKey.Zero()
}

// TestStoreBackedWalletAddressRestart verifies KV fixture migration, real
// manager open, rollback-safe allocation, and durable SQLite restart without a
// walletdb sidecar.
func TestStoreBackedWalletAddressRestart(t *testing.T) {
	t.Parallel()

	params := &chaincfg.TestNet3Params
	pubPass := []byte("public-pass")
	privPass := []byte("private-pass")
	seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
	require.NoError(t, err)

	kvDir := filepath.Join(t.TempDir(), "kv")
	kvLoader := NewLoader(
		params, kvDir, true, DefaultDBTimeout, 0,
	)
	kvWallet, err := kvLoader.CreateNewWallet(
		pubPass, privPass, seed, time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)

	kvStore := walletkvdb.NewStore(
		kvWallet.Database(), kvWallet.Manager, kvWallet.TxStore,
	)
	kvScoped, err := kvWallet.Manager.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	require.NoError(t, kvWallet.Unlock(privPass, nil))

	var (
		secondaryAccount uint32
		kvExternal       waddrmgr.ManagedAddress
		kvInternal       waddrmgr.ManagedAddress
	)
	require.NoError(t, walletdb.Update(
		kvWallet.Database(), func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			secondaryAccount, err = kvScoped.NewAccount(ns, "secondary")
			if err != nil {
				return err
			}

			external, err := kvScoped.NextExternalAddresses(
				ns, waddrmgr.DefaultAccountNum, 1,
			)
			if err != nil {
				return err
			}
			kvExternal = external[0]

			internal, err := kvScoped.NextInternalAddresses(
				ns, waddrmgr.DefaultAccountNum, 1,
			)
			if err != nil {
				return err
			}
			kvInternal = internal[0]

			return nil
		},
	))
	require.Equal(t, uint32(1), secondaryAccount)

	fixture := readManagerFixture(
		t, kvStore, kvWallet.Database(), kvWallet.Manager,
	)
	watchOnly := kvWallet.Manager.WatchOnly()

	var kvProps *waddrmgr.AccountProperties
	require.NoError(t, walletdb.View(
		kvWallet.Database(), func(tx walletdb.ReadTx) error {
			var err error
			kvProps, err = kvScoped.AccountProperties(
				tx.ReadBucket(waddrmgrNamespaceKey),
				waddrmgr.DefaultAccountNum,
			)
			return err
		},
	))
	require.NoError(t, kvLoader.UnloadWallet())
	require.NoError(t, os.RemoveAll(kvDir))

	sqlDir := filepath.Join(t.TempDir(), "sqlite")
	require.NoError(t, os.MkdirAll(sqlDir, 0o700))
	sqlPath := filepath.Join(sqlDir, "wallet.sqlite")
	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: sqlPath,
	})
	require.NoError(t, err)
	require.NoError(t, storesqlite.ApplyMigrations(conn))

	walletID, store := writeManagerFixture(t, conn, fixture)
	createLoader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	_, err = createLoader.CreateNewWallet(
		pubPass, privPass, seed, fixture.sync.Birthday,
	)
	require.ErrorIs(t, err, ErrExists)

	wrongLoader, err := NewLoaderWithStore(params, 0, store)
	require.NoError(t, err)
	_, err = wrongLoader.OpenExistingWallet([]byte("wrong"), false)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase))

	loader, sqlWallet := openStoreWallet(t, params, store, pubPass)
	require.Equal(
		t, watchOnly, sqlWallet.Manager.WatchOnly(),
	)
	require.Equal(t, fixture.sync.Birthday, sqlWallet.Manager.Birthday())
	require.Equal(t, fixture.sync.SyncedTo, sqlWallet.Manager.SyncedTo())
	require.Len(t, sqlWallet.Manager.ActiveScopedKeyManagers(),
		len(fixture.scopes))

	sqlScoped, err := sqlWallet.Manager.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	var sqlProps *waddrmgr.AccountProperties
	require.NoError(t, store.View(
		t.Context(), func(tx walletstore.ReadTx) error {
			var err error
			sqlProps, err = sqlScoped.AccountPropertiesFromStore(
				tx.Addr(), waddrmgr.DefaultAccountNum,
			)
			return err
		}, func() {},
	))
	require.Equal(t, kvProps.ExternalKeyCount, sqlProps.ExternalKeyCount)
	require.Equal(t, kvProps.InternalKeyCount, sqlProps.InternalKeyCount)
	require.Equal(t, kvProps.AccountPubKey.String(),
		sqlProps.AccountPubKey.String())

	lastExternal, err := sqlScoped.LastExternalAddress(
		nil, waddrmgr.DefaultAccountNum,
	)
	require.NoError(t, err)
	require.Equal(t, kvExternal.Address().String(),
		lastExternal.Address().String())
	lastInternal, err := sqlScoped.LastInternalAddress(
		nil, waddrmgr.DefaultAccountNum,
	)
	require.NoError(t, err)
	require.Equal(t, kvInternal.Address().String(),
		lastInternal.Address().String())

	// Wallet.Unlock must use the store-backed path and derive private keys
	// for chain addresses reconstructed during open.
	require.NoError(t, sqlWallet.Unlock(privPass, nil))
	requireManagedPrivateKey(t, lastExternal)
	requireManagedPrivateKey(t, lastInternal)

	secondaryAddr, err := sqlWallet.NewAddress(
		secondaryAccount, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	secondaryManaged, err := sqlScoped.Address(nil, secondaryAddr)
	require.NoError(t, err)
	requireManagedPrivateKey(t, secondaryManaged)

	secondaryAddrTwo, err := sqlWallet.NewAddress(
		secondaryAccount, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	require.NotEqual(t, secondaryAddr.String(), secondaryAddrTwo.String())
	requireManagedPrivateKey(t, secondaryManaged)

	secondaryPub, ok := secondaryManaged.(waddrmgr.ManagedPubKeyAddress)
	require.True(t, ok)
	_, secondaryPath, ok := secondaryPub.DerivationInfo()
	require.True(t, ok)
	derivedSecondary, err := sqlScoped.DeriveFromKeyPath(
		nil, secondaryPath,
	)
	require.NoError(t, err)
	requireManagedPrivateKey(t, derivedSecondary)

	// An ambiguous result refreshes durable indexes into the existing
	// account object rather than evicting its decrypted private key.
	sqlWallet.Manager.MarkAccountCacheStale(
		waddrmgr.KeyScopeBIP0084, secondaryAccount,
	)
	require.NoError(t, store.View(
		t.Context(), func(tx walletstore.ReadTx) error {
			props, err := sqlScoped.AccountPropertiesFromStore(
				tx.Addr(), secondaryAccount,
			)
			if err == nil {
				require.EqualValues(t, 2, props.ExternalKeyCount)
			}
			return err
		}, nil,
	))
	derivedSecondary, err = sqlScoped.DeriveFromKeyPath(nil, secondaryPath)
	require.NoError(t, err)
	requireManagedPrivateKey(t, derivedSecondary)

	rollbackErr := errors.New("force address rollback")
	var attempted address.Address
	err = store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			managed, _, err := sqlScoped.NextExternalAddressFromStore(
				tx.Addr(), waddrmgr.DefaultAccountNum,
			)
			if err != nil {
				return err
			}
			attempted = managed.Address()

			return rollbackErr
		}, func() {
			attempted = nil
		},
	)
	require.ErrorIs(t, err, rollbackErr)

	var addressCount, nextExternal int64
	require.NoError(t, conn.QueryRowContext(t.Context(), `
		SELECT COUNT(*) FROM addresses WHERE wallet_id = ?
	`, walletID).Scan(&addressCount))
	require.EqualValues(t, len(fixture.addresses)+2, addressCount)
	require.NoError(t, conn.QueryRowContext(t.Context(), `
		SELECT a.next_external_index
		FROM accounts AS a
		JOIN key_scopes AS s ON s.id = a.scope_id
		WHERE a.wallet_id = ? AND s.purpose = 84
			AND a.account_number = 0
	`, walletID).Scan(&nextExternal))
	require.EqualValues(t, 1, nextExternal)
	require.NoError(t, store.View(
		t.Context(), func(tx walletstore.ReadTx) error {
			props, err := sqlScoped.AccountPropertiesFromStore(
				tx.Addr(), waddrmgr.DefaultAccountNum,
			)
			if err == nil {
				require.EqualValues(t, 1, props.ExternalKeyCount)
			}
			return err
		}, func() {},
	))

	addrOne, err := sqlWallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	require.Equal(t, attempted.String(), addrOne.String())
	require.NoError(t, loader.UnloadWallet())
	require.NoError(t, conn.Close())

	conn, err = storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: sqlPath,
	})
	require.NoError(t, err)
	store = dbsqlite.NewStore(conn, walletID)
	loader, sqlWallet = openStoreWallet(t, params, store, pubPass)
	sqlScoped, err = sqlWallet.Manager.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)

	lastExternal, err = sqlScoped.LastExternalAddress(
		nil, waddrmgr.DefaultAccountNum,
	)
	require.NoError(t, err)
	require.Equal(t, addrOne.String(), lastExternal.Address().String())
	lastInternal, err = sqlScoped.LastInternalAddress(
		nil, waddrmgr.DefaultAccountNum,
	)
	require.NoError(t, err)
	require.Equal(t, kvInternal.Address().String(),
		lastInternal.Address().String())
	lastSecondary, err := sqlScoped.LastExternalAddress(
		nil, secondaryAccount,
	)
	require.NoError(t, err)
	require.Equal(t, secondaryAddrTwo.String(),
		lastSecondary.Address().String())

	require.NoError(t, sqlWallet.Unlock(privPass, nil))
	requireManagedPrivateKey(t, lastExternal)
	requireManagedPrivateKey(t, lastSecondary)

	addrTwo, err := sqlWallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	require.NotEqual(t, addrOne.String(), addrTwo.String())
	require.NoError(t, loader.UnloadWallet())

	rows, err := conn.QueryContext(t.Context(), `
		SELECT address_index
		FROM addresses
		WHERE wallet_id = ? AND account_number = 0 AND branch = 0
		ORDER BY address_index
	`, walletID)
	require.NoError(t, err)
	defer rows.Close()
	var indexes []int64
	for rows.Next() {
		var index int64
		require.NoError(t, rows.Scan(&index))
		indexes = append(indexes, index)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.Equal(t, []int64{0, 1, 2}, indexes)
	require.NoError(t, conn.QueryRowContext(t.Context(), `
		SELECT a.next_external_index
		FROM accounts AS a
		JOIN key_scopes AS s ON s.id = a.scope_id
		WHERE a.wallet_id = ? AND s.purpose = 84
			AND a.account_number = 0
	`, walletID).Scan(&nextExternal))
	require.EqualValues(t, 3, nextExternal)
	require.NoError(t, conn.Close())

	_, err = os.Stat(filepath.Join(sqlDir, WalletDBName))
	require.True(t, os.IsNotExist(err))
}
