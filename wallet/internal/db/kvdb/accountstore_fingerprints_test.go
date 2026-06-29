package kvdb

import (
	"bytes"
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// fingerprintDeriveFnFixture returns an AccountDerivationFunc local to the
// fingerprint-test file. It derives a real account-level extended key
// from a deterministic seed so PutDerivedAccountWithKeys' public-key
// decryption succeeds, and stamps a fixed MasterKeyFingerprint so the
// round-trip assertions are observable.
//
// This file keeps its derivation fixture local so these fingerprint tests
// do not depend on broader account-store test helpers.
func fingerprintDeriveFnFixture(t *testing.T,
	mgr *waddrmgr.Manager) db.AccountDerivationFunc {

	t.Helper()

	seed := bytes.Repeat([]byte{0xFA}, hdkeychain.RecommendedSeedLen)
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)

	return func(_ context.Context, scope db.KeyScope, accountNumber uint32,
		_ bool) (*db.DerivedAccountData, error) {

		purposeKey, err := masterKey.DeriveNonStandard(
			scope.Purpose + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return nil, err
		}

		coinKey, err := purposeKey.DeriveNonStandard(
			scope.Coin + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return nil, err
		}

		acctPriv, err := coinKey.DeriveNonStandard(
			accountNumber + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return nil, err
		}

		acctPub, err := acctPriv.Neuter()
		if err != nil {
			return nil, err
		}

		encPriv, err := mgr.Encrypt(
			waddrmgr.CKTPrivate, []byte(acctPriv.String()),
		)
		if err != nil {
			return nil, err
		}

		return &db.DerivedAccountData{
			PublicKey:            []byte(acctPub.String()),
			EncryptedPrivateKey:  encPriv,
			MasterKeyFingerprint: testFingerprintValue,
		}, nil
	}
}

// testFingerprintValue is the deterministic MasterKeyFingerprint that
// fingerprintDeriveFnFixture stamps on every derived account.
const testFingerprintValue uint32 = 0xC0DEC0DE

// TestCreateDerivedAccountPersistsMasterKeyFingerprint verifies a
// derived account's master fingerprint round-trips through the
// kvdb side bucket independently of waddrmgr's default-account row
// (which has no fingerprint column).
func TestCreateDerivedAccountPersistsMasterKeyFingerprint(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}

	deriveFn := fingerprintDeriveFnFixture(t, mgr)
	info, err := store.CreateDerivedAccount(t.Context(),
		db.CreateDerivedAccountParams{
			Scope: scope,
			Name:  "fp-derived",
		},
		deriveFn,
	)
	require.NoError(t, err)
	require.NotNil(t, info.AccountNumber)
	require.Equal(t, testFingerprintValue, info.MasterKeyFingerprint)

	// Round-trip via Store.GetAccount — the value must come back
	// from the side bucket, not from waddrmgr's row.
	name := "fp-derived"
	got, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: scope,
		Name:  &name,
	})
	require.NoError(t, err)
	require.Equal(t, testFingerprintValue, got.MasterKeyFingerprint)
}

// TestLoadAccountInfoFallsBackOnMissingFingerprintRow verifies the
// legacy-compatibility path: a derived account whose side-bucket entry
// is missing reads back props.MasterKeyFingerprint (which is 0 for
// waddrmgr default-account rows). The wallet-layer override is the
// canonical compatibility fallback at the public boundary; this test
// pins the store-layer behavior (returns 0 honestly).
func TestLoadAccountInfoFallsBackOnMissingFingerprintRow(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}
	mgrScope := waddrmgr.KeyScope{
		Purpose: scope.Purpose, Coin: scope.Coin,
	}

	deriveFn := fingerprintDeriveFnFixture(t, mgr)
	info, err := store.CreateDerivedAccount(
		t.Context(),
		db.CreateDerivedAccountParams{
			Scope: scope,
			Name:  "fp-derived-fallback",
		},
		deriveFn,
	)
	require.NoError(t, err)
	require.Equal(t, testFingerprintValue, info.MasterKeyFingerprint)

	// Manually delete the side-bucket entry to simulate a legacy
	// derived account that pre-dates the side bucket.
	err = walletdb.Update(store.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		bucket := ns.NestedReadWriteBucket(
			accountMasterFingerprintBucketKey,
		)
		require.NotNil(t, bucket)

		key := newAccountCreatedAtKey(
			mgrScope, *info.AccountNumber,
		)

		return bucket.Delete(key[:])
	})
	require.NoError(t, err)

	// Read back — store now returns 0 (waddrmgr's default-account
	// row has no fingerprint). The wallet-layer override outside
	// of kvdb backfills the cached master fingerprint at the
	// public boundary.
	name := "fp-derived-fallback"
	got, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: scope,
		Name:  &name,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(0), got.MasterKeyFingerprint,
		"missing side-bucket entry must fall back to waddrmgr's 0",
	)
}
