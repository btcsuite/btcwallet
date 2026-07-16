package waddrmgr

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// noAccountSentinel is the value the KV layer records for a key scope that has
// no accounts. It mirrors the (1<<32)-1 marker returned by fetchLastAccount and
// must stay distinct from a real account 0.
const noAccountSentinel = ^uint32(0)

// init primes the lazily memoized public key on the shared test rootKey. Each
// setupManager call runs Create, which neuters rootKey and, on first use,
// writes its public-key cache. Priming that cache once here, before any
// parallel test runs, keeps concurrent setupManager calls race-free under
// -race.
func init() {
	_, _ = rootKey.Neuter()
}

// mainKeyPresent reports whether the given main-bucket key currently exists.
func mainKeyPresent(t *testing.T, db walletdb.DB, key []byte) bool {
	t.Helper()

	var present bool
	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		present = ns.NestedReadBucket(mainBucketName).Get(key) != nil

		return nil
	})
	require.NoError(t, err)

	return present
}

// scopeKeyPresent reports whether the given scoped-bucket key currently exists
// for the passed key scope.
func scopeKeyPresent(t *testing.T, db walletdb.DB, scope KeyScope,
	key []byte) bool {

	t.Helper()

	var present bool
	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		scoped, err := fetchReadScopeBucket(ns, &scope)
		if err != nil {
			return err
		}
		present = scoped.Get(key) != nil

		return nil
	})
	require.NoError(t, err)

	return present
}

// updateStore runs fn against a bucket-bound writable manager store.
func updateStore(t *testing.T, db walletdb.DB,
	fn func(ManagerReadWriteStore) error) error {

	t.Helper()

	return walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		store := BindManagerReadWriteStore(
			tx.ReadWriteBucket(waddrmgrNamespaceKey),
		)

		return fn(store)
	})
}

// viewStore runs fn against a bucket-bound read-only manager store.
func viewStore(t *testing.T, db walletdb.DB,
	fn func(ManagerReadStore) error) error {

	t.Helper()

	return walletdb.View(db, func(tx walletdb.ReadTx) error {
		return fn(BindManagerReadStore(
			tx.ReadBucket(waddrmgrNamespaceKey),
		))
	})
}

// TestKVPutManagerStateReplacement verifies that PutManagerState honors full
// replacement semantics: optional key material omitted from the request is
// deleted rather than retained, while present material is kept.
func TestKVPutManagerStateReplacement(t *testing.T) {
	t.Parallel()

	// The private main-bucket keys that a watch-only replacement must clear.
	privateKeys := [][]byte{
		masterPrivKeyName, cryptoPrivKeyName, cryptoScriptKeyName,
		masterHDPrivName,
	}

	// The public main-bucket keys that must always survive a replacement.
	publicKeys := [][]byte{masterPubKeyName, cryptoPubKeyName}

	tests := []struct {
		name string

		// build derives the replacement state from the initial full
		// state seeded by setupManager.
		build func(full ManagerState) ManagerState

		// wantPrivate reports whether the private key material should
		// still exist after the replacement.
		wantPrivate bool
	}{
		{
			name: "full state retains private material",
			build: func(full ManagerState) ManagerState {
				return full
			},
			wantPrivate: true,
		},
		{
			name: "watch-only replacement clears private material",
			build: func(full ManagerState) ManagerState {
				full.WatchOnly = true
				full.MasterPrivParams = nil
				full.EncryptedCryptoPrivKey = nil
				full.EncryptedCryptoScriptKey = nil
				full.EncryptedMasterHDPrivKey = nil

				return full
			},
			wantPrivate: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			teardown, db, _ := setupManager(t)
			t.Cleanup(teardown)

			// A freshly created manager owns all private material.
			for _, key := range privateKeys {
				require.True(
					t, mainKeyPresent(t, db, key),
					"missing seed key %s", key,
				)
			}

			// Read the initial full state, then write the derived
			// replacement state.
			var full ManagerState
			err := viewStore(t, db, func(s ManagerReadStore) error {
				var err error
				full, err = s.ManagerState()

				return err
			})
			require.NoError(t, err)

			want := tc.build(full)
			err = updateStore(t, db, func(s ManagerReadWriteStore) error {
				return s.PutManagerState(want)
			})
			require.NoError(t, err)

			// Public material always survives.
			for _, key := range publicKeys {
				require.True(
					t, mainKeyPresent(t, db, key),
					"public key %s removed", key,
				)
			}

			// Private material presence depends on the replacement.
			for _, key := range privateKeys {
				require.Equal(
					t, tc.wantPrivate,
					mainKeyPresent(t, db, key),
					"private key %s presence", key,
				)
			}

			// The decoded state must match what was written.
			var got ManagerState
			err = viewStore(t, db, func(s ManagerReadStore) error {
				var err error
				got, err = s.ManagerState()

				return err
			})
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

// TestKVSetCoinTypeKeysReplacement verifies that SetCoinTypeKeys deletes a
// stale encrypted private coin-type key when the replacement omits it, while
// retaining a supplied private key.
func TestKVSetCoinTypeKeysReplacement(t *testing.T) {
	t.Parallel()

	scope := KeyScopeBIP0084

	tests := []struct {
		name         string
		encryptedPub []byte
		encPriv      []byte
		wantPriv     bool
	}{
		{
			name:         "present private key retained",
			encryptedPub: []byte("coin-pub"),
			encPriv:      []byte("coin-priv"),
			wantPriv:     true,
		},
		{
			name:         "nil private key deleted",
			encryptedPub: []byte("coin-pub"),
			encPriv:      nil,
			wantPriv:     false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			teardown, db, _ := setupManager(t)
			t.Cleanup(teardown)

			// The default scope starts with a private coin-type key.
			require.True(
				t, scopeKeyPresent(t, db, scope, coinTypePrivKeyName),
			)

			err := updateStore(t, db, func(s ManagerReadWriteStore) error {
				return s.SetCoinTypeKeys(
					scope, tc.encryptedPub, tc.encPriv,
				)
			})
			require.NoError(t, err)

			// The public coin-type key always survives.
			require.True(
				t, scopeKeyPresent(t, db, scope, coinTypePubKeyName),
			)
			require.Equal(
				t, tc.wantPriv,
				scopeKeyPresent(t, db, scope, coinTypePrivKeyName),
			)
		})
	}
}

// TestKVDeletePrivateKeysScripts verifies that watch-only conversion clears
// every secret script, including taproot scripts which share the witness-script
// row encoding, while leaving public scripts intact.
func TestKVDeletePrivateKeysScripts(t *testing.T) {
	t.Parallel()

	v0, v1 := uint8(0), uint8(1)
	secret, public := true, false

	tests := []struct {
		name        string
		addressID   []byte
		addrType    StoreAddressType
		version     *uint8
		isSecret    *bool
		wantCleared bool
	}{
		{
			name:        "secret witness v0 script cleared",
			addressID:   []byte("witness-secret"),
			addrType:    AddressWitnessScript,
			version:     &v0,
			isSecret:    &secret,
			wantCleared: true,
		},
		{
			name:        "secret taproot script cleared",
			addressID:   []byte("taproot-secret"),
			addrType:    AddressTaprootScript,
			version:     &v1,
			isSecret:    &secret,
			wantCleared: true,
		},
		{
			name:        "public taproot script retained",
			addressID:   []byte("taproot-public"),
			addrType:    AddressTaprootScript,
			version:     &v1,
			isSecret:    &public,
			wantCleared: false,
		},
	}

	teardown, db, _ := setupManager(t)
	t.Cleanup(teardown)

	scriptFor := func(id []byte) []byte {
		return append([]byte("script-"), id...)
	}

	// Store every script address, then convert the wallet to watch-only.
	err := updateStore(t, db, func(s ManagerReadWriteStore) error {
		for _, tc := range tests {
			state := AddressState{
				Scope:           KeyScopeBIP0084,
				Account:         ImportedAddrAccount,
				Type:            tc.addrType,
				AddedAt:         time.Unix(200, 0),
				WitnessVersion:  tc.version,
				IsSecretScript:  tc.isSecret,
				EncryptedHash:   append([]byte("hash-"), tc.addressID...),
				EncryptedScript: scriptFor(tc.addressID),
			}
			if err := s.PutAddress(tc.addressID, state); err != nil {
				return err
			}
		}

		return nil
	})
	require.NoError(t, err)

	err = updateStore(t, db, func(s ManagerReadWriteStore) error {
		return s.DeletePrivateKeys()
	})
	require.NoError(t, err)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var got AddressState
			err := viewStore(t, db, func(s ManagerReadStore) error {
				var err error
				got, err = s.Address(
					KeyScopeBIP0084, tc.addressID,
				)

				return err
			})
			require.NoError(t, err)

			if tc.wantCleared {
				require.Empty(t, got.EncryptedScript)
			} else {
				require.Equal(
					t, scriptFor(tc.addressID),
					got.EncryptedScript,
				)
			}
		})
	}
}

// TestKVPutAccountRemovesStaleNameIndex verifies that replacing an account with
// a different name removes the old name index, while re-writing the same name
// leaves the account resolvable.
func TestKVPutAccountRemovesStaleNameIndex(t *testing.T) {
	t.Parallel()

	scope := KeyScopeBIP0084

	tests := []struct {
		name        string
		firstName   string
		secondName  string
		wantOldGone bool
	}{
		{
			name:        "rename drops old name index",
			firstName:   "alpha",
			secondName:  "beta",
			wantOldGone: true,
		},
		{
			name:        "same name stays resolvable",
			firstName:   "alpha",
			secondName:  "alpha",
			wantOldGone: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			teardown, db, _ := setupManager(t)
			t.Cleanup(teardown)

			const account = uint32(1)

			err := updateStore(t, db, func(s ManagerReadWriteStore) error {
				err := s.PutAccount(defaultAccountState(
					scope, account, tc.firstName,
				))
				if err != nil {
					return err
				}

				return s.PutAccount(defaultAccountState(
					scope, account, tc.secondName,
				))
			})
			require.NoError(t, err)

			err = viewStore(t, db, func(s ManagerReadStore) error {
				// The current name always resolves to the account.
				got, err := s.AccountByName(scope, tc.secondName)
				require.NoError(t, err)
				require.Equal(t, account, got.Account)

				// The old name resolves only when it was reused.
				_, err = s.AccountByName(scope, tc.firstName)
				if tc.wantOldGone {
					require.True(
						t, IsError(err, ErrAccountNotFound),
					)
				} else {
					require.NoError(t, err)
				}

				return nil
			})
			require.NoError(t, err)
		})
	}
}

// TestKVRenameAccountRejectsCollision verifies that RenameAccount rejects a
// name already owned by a different account, but permits renaming to a free
// name or to the account's own current name.
func TestKVRenameAccountRejectsCollision(t *testing.T) {
	t.Parallel()

	scope := KeyScopeBIP0084

	teardown, db, _ := setupManager(t)
	t.Cleanup(teardown)

	const (
		accountA = uint32(1)
		accountB = uint32(2)
	)

	err := updateStore(t, db, func(s ManagerReadWriteStore) error {
		err := s.PutAccount(defaultAccountState(scope, accountA, "alpha"))
		if err != nil {
			return err
		}

		return s.PutAccount(defaultAccountState(scope, accountB, "beta"))
	})
	require.NoError(t, err)

	// Renaming account A onto account B's name must be rejected and must not
	// clobber account B's name index.
	err = updateStore(t, db, func(s ManagerReadWriteStore) error {
		return s.RenameAccount(scope, accountA, "beta")
	})
	require.True(t, IsError(err, ErrDuplicateAccount))

	err = viewStore(t, db, func(s ManagerReadStore) error {
		got, err := s.AccountByName(scope, "beta")
		require.NoError(t, err)
		require.Equal(t, accountB, got.Account)

		got, err = s.AccountByName(scope, "alpha")
		require.NoError(t, err)
		require.Equal(t, accountA, got.Account)

		return nil
	})
	require.NoError(t, err)

	// Renaming to a free name succeeds and drops the old name.
	err = updateStore(t, db, func(s ManagerReadWriteStore) error {
		return s.RenameAccount(scope, accountA, "gamma")
	})
	require.NoError(t, err)

	// Renaming to the account's own current name is a permitted no-op.
	err = updateStore(t, db, func(s ManagerReadWriteStore) error {
		return s.RenameAccount(scope, accountA, "gamma")
	})
	require.NoError(t, err)

	err = viewStore(t, db, func(s ManagerReadStore) error {
		got, err := s.AccountByName(scope, "gamma")
		require.NoError(t, err)
		require.Equal(t, accountA, got.Account)

		_, err = s.AccountByName(scope, "alpha")
		require.True(t, IsError(err, ErrAccountNotFound))

		return nil
	})
	require.NoError(t, err)
}

// TestKVPutAddressRehomeRemovesStaleIndex verifies that re-homing an address to
// a different account removes the previous account-address index so the address
// is not listed under both accounts.
func TestKVPutAddressRehomeRemovesStaleIndex(t *testing.T) {
	t.Parallel()

	scope := KeyScopeBIP0084

	teardown, db, _ := setupManager(t)
	t.Cleanup(teardown)

	const (
		accountA = uint32(1)
		accountB = uint32(2)
	)

	addressID := []byte("rehomed-address")
	branch, index := uint32(0), uint32(9)

	addrState := func(account uint32) AddressState {
		return AddressState{
			Scope:      scope,
			Account:    account,
			Type:       AddressChain,
			AddedAt:    time.Unix(300, 0),
			SyncStatus: AddressSyncNone,
			Branch:     &branch,
			Index:      &index,
		}
	}

	// Store the address under account A, then re-home it to account B.
	err := updateStore(t, db, func(s ManagerReadWriteStore) error {
		return s.PutAddress(addressID, addrState(accountA))
	})
	require.NoError(t, err)

	err = viewStore(t, db, func(s ManagerReadStore) error {
		addrs, err := s.AccountAddresses(scope, accountA)
		require.NoError(t, err)
		require.Len(t, addrs, 1)

		return nil
	})
	require.NoError(t, err)

	err = updateStore(t, db, func(s ManagerReadWriteStore) error {
		return s.PutAddress(addressID, addrState(accountB))
	})
	require.NoError(t, err)

	err = viewStore(t, db, func(s ManagerReadStore) error {
		// The stale account no longer lists the address.
		oldAddrs, err := s.AccountAddresses(scope, accountA)
		require.NoError(t, err)
		require.Empty(t, oldAddrs)

		// The new account owns the address exactly once.
		newAddrs, err := s.AccountAddresses(scope, accountB)
		require.NoError(t, err)
		require.Len(t, newAddrs, 1)
		require.Equal(t, accountB, newAddrs[0].Account)

		return nil
	})
	require.NoError(t, err)
}

// TestKVStartBlockTimestampNarrowed documents the narrowed StartBlock contract:
// the legacy KV encoding persists only the start block height and hash, so its
// timestamp does not round-trip, whereas SyncedTo retains its timestamp.
func TestKVStartBlockTimestampNarrowed(t *testing.T) {
	t.Parallel()

	teardown, db, _ := setupManager(t)
	t.Cleanup(teardown)

	start := BlockStamp{
		Height:    800,
		Hash:      chainhash.Hash{80},
		Timestamp: time.Unix(8_000, 0),
	}
	synced := BlockStamp{
		Height:    801,
		Hash:      chainhash.Hash{81},
		Timestamp: time.Unix(8_001, 0),
	}
	want := SyncState{
		StartBlock: start,
		SyncedTo:   synced,
		Birthday:   time.Unix(7_999, 0),
	}

	err := updateStore(t, db, func(s ManagerReadWriteStore) error {
		return s.PutSyncState(want)
	})
	require.NoError(t, err)

	var got SyncState
	err = viewStore(t, db, func(s ManagerReadStore) error {
		var err error
		got, err = s.SyncState()

		return err
	})
	require.NoError(t, err)

	// Height and hash round-trip, but the start block timestamp is dropped.
	require.Equal(t, start.Height, got.StartBlock.Height)
	require.Equal(t, start.Hash, got.StartBlock.Hash)
	require.True(t, got.StartBlock.Timestamp.IsZero())

	// SyncedTo retains its full block stamp, including the timestamp.
	require.Equal(t, synced, got.SyncedTo)
}

// TestKVLastAccountNoAccountSentinel verifies that the KV layer preserves the
// no-account sentinel distinctly from a real account 0, both at the decode
// layer and through a Store round-trip.
func TestKVLastAccountNoAccountSentinel(t *testing.T) {
	t.Parallel()

	t.Run("decode", func(t *testing.T) {
		t.Parallel()

		scope := KeyScope{Purpose: 8888, Coin: 8888}

		tests := []struct {
			name  string
			write *uint32
			want  uint32
		}{
			{
				name:  "missing key returns sentinel",
				write: nil,
				want:  noAccountSentinel,
			},
			{
				name:  "account zero preserved",
				write: pointerTo(uint32(0)),
				want:  0,
			},
			{
				name:  "sentinel preserved",
				write: pointerTo(noAccountSentinel),
				want:  noAccountSentinel,
			},
		}

		for _, tc := range tests {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				teardown, db := emptyDB(t)
				t.Cleanup(teardown)

				// Build a bare scope namespace, optionally writing
				// a last-account value.
				err := walletdb.Update(
					db, func(tx walletdb.ReadWriteTx) error {
						ns, err := tx.CreateTopLevelBucket(
							waddrmgrNamespaceKey,
						)
						if err != nil {
							return err
						}

						err = createManagerNS(
							ns, ScopeAddrMap,
						)
						if err != nil {
							return err
						}

						root := ns.NestedReadWriteBucket(
							scopeBucketName,
						)
						err = createScopedManagerNS(
							root, &scope,
						)
						if err != nil {
							return err
						}

						if tc.write == nil {
							return nil
						}

						return putLastAccount(
							ns, &scope, *tc.write,
						)
					},
				)
				require.NoError(t, err)

				err = walletdb.View(
					db, func(tx walletdb.ReadTx) error {
						ns := tx.ReadBucket(
							waddrmgrNamespaceKey,
						)
						got, err := fetchLastAccount(
							ns, &scope,
						)
						require.NoError(t, err)
						require.Equal(t, tc.want, got)

						return nil
					},
				)
				require.NoError(t, err)
			})
		}
	})

	t.Run("store round-trip", func(t *testing.T) {
		t.Parallel()

		teardown, db, _ := setupManager(t)
		t.Cleanup(teardown)

		scope := KeyScopeBIP0084

		// setupManager seeds the default scope with account 0, which
		// must decode as 0 rather than the no-account sentinel.
		err := viewStore(t, db, func(s ManagerReadStore) error {
			got, err := s.KeyScope(scope)
			require.NoError(t, err)
			require.Equal(
				t, uint32(DefaultAccountNum), got.LastAccount,
			)

			return nil
		})
		require.NoError(t, err)

		// The sentinel round-trips distinctly from account 0.
		values := []uint32{noAccountSentinel, 0, noAccountSentinel}
		for _, want := range values {
			err := updateStore(t, db, func(s ManagerReadWriteStore) error {
				return s.SetLastAccount(scope, want)
			})
			require.NoError(t, err)

			err = viewStore(t, db, func(s ManagerReadStore) error {
				got, err := s.KeyScope(scope)
				require.NoError(t, err)
				require.Equal(t, want, got.LastAccount)

				return nil
			})
			require.NoError(t, err)
		}
	})
}

// defaultAccountState builds a minimal default AccountState for KV store tests.
func defaultAccountState(scope KeyScope, account uint32,
	name string) AccountState {

	return AccountState{
		Scope:            scope,
		Account:          account,
		Type:             AccountDefault,
		Name:             name,
		EncryptedPubKey:  append([]byte("pub-"), name...),
		EncryptedPrivKey: append([]byte("priv-"), name...),
	}
}

// pointerTo returns a pointer to the passed value.
func pointerTo[T any](value T) *T {
	return &value
}
