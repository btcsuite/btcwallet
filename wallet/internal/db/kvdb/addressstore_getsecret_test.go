package kvdb

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// TestGetAddressSecretImportedPrivateKey verifies that an imported private-key
// address returns its encrypted private key and no script.
func TestGetAddressSecretImportedPrivateKey(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	unlockAddrStore(t, dbConn, addrStore)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	wif, err := btcutil.NewWIF(privKey, addrStore.ChainParams(), false)
	require.NoError(t, err)

	manager, err := addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)

	var pkScript []byte

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		managedAddr, err := manager.ImportPrivateKey(ns, wif, nil)
		if err != nil {
			return err
		}

		pkScript, err = txscript.PayToAddrScript(managedAddr.Address())

		return err
	})
	require.NoError(t, err)

	secret, err := store.GetAddressSecret(t.Context(),
		db.GetAddressSecretQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, secret)
	require.NotEmpty(t, secret.EncryptedPrivKey,
		"imported private-key address must expose encrypted priv key")
	require.Empty(t, secret.EncryptedScript)
	require.Equal(t, uint32(0), secret.AddressID)
}

// TestGetAddressSecretCanceledCtx verifies that a canceled context aborts the
// read: a signing request that is canceled before it reaches walletdb must not
// enter the store and return secret key material.
func TestGetAddressSecretCanceledCtx(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	unlockAddrStore(t, dbConn, addrStore)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	wif, err := btcutil.NewWIF(privKey, addrStore.ChainParams(), false)
	require.NoError(t, err)

	manager, err := addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)

	var pkScript []byte

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		managedAddr, err := manager.ImportPrivateKey(ns, wif, nil)
		if err != nil {
			return err
		}

		pkScript, err = txscript.PayToAddrScript(managedAddr.Address())

		return err
	})
	require.NoError(t, err)

	// The address exists and carries a private key, so an uncanceled read
	// would succeed. A canceled context must abort before the walletdb
	// lookup and surface context.Canceled instead of the secret.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	secret, err := store.GetAddressSecret(ctx,
		db.GetAddressSecretQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, secret)
}

// TestGetAddressSecretRejectsEmptySelector verifies that kvdb rejects an
// address-secret query with no script pubkey rather than mapping the malformed
// selector onto ErrSecretNotFound. The failure must read the same on every
// backend.
func TestGetAddressSecretRejectsEmptySelector(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	store := NewStore(dbConn, nil, newSpendableAddrMgr(t, dbConn))

	for _, script := range [][]byte{nil, {}} {
		secret, err := store.GetAddressSecret(t.Context(),
			db.GetAddressSecretQuery{
				WalletID:     0,
				ScriptPubKey: script,
			},
		)
		require.ErrorIs(t, err, db.ErrInvalidAddressQuery)
		require.Nil(t, secret)
	}
}

// TestGetAddressSecretP2SHScriptIsSecret verifies that a legacy P2SH redeem
// script is always reported secret. waddrmgr stores no per-row flag for P2SH:
// it only ever encrypts those under the script crypto key, so the store must
// report ScriptIsSecret=true and the ciphertext must decrypt under that key.
func TestGetAddressSecretP2SHScriptIsSecret(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	// A P2SH import is always secret in waddrmgr, so the manager must be
	// unlocked to hold the script key.
	unlockAddrStore(t, dbConn, addrStore)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	redeemScript, err := txscript.NewScriptBuilder().
		AddData(privKey.PubKey().SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	addr, err := address.NewAddressScriptHash(
		redeemScript, addrStore.ChainParams(),
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	scope, err := legacyImportScope(db.ScriptHash)
	require.NoError(t, err)
	manager, err := addrStore.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		bs := addrStore.SyncedTo()

		_, err := manager.ImportScript(ns, redeemScript, &bs)

		return err
	})
	require.NoError(t, err)

	secret, err := store.GetAddressSecret(t.Context(),
		db.GetAddressSecretQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, secret)
	require.True(t, secret.ScriptIsSecret)

	got, err := addrStore.Decrypt(
		waddrmgr.CKTScript, secret.EncryptedScript,
	)
	require.NoError(t, err)
	require.Equal(t, redeemScript, got)
}

// TestGetAddressSecretUnknownScript verifies that a script the wallet does not
// own maps to ErrSecretNotFound.
func TestGetAddressSecretUnknownScript(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	// Build a standard P2WPKH script for a key the wallet has never seen.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pkScript := p2wpkhScript(t, privKey, addrStore.ChainParams())

	_, err = store.GetAddressSecret(t.Context(),
		db.GetAddressSecretQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.ErrorIs(t, err, db.ErrSecretNotFound)
}

// p2wpkhScript builds a P2WPKH output script for the given key on chainParams.
func p2wpkhScript(t *testing.T, privKey *btcec.PrivateKey,
	chainParams *chaincfg.Params) []byte {

	t.Helper()

	pubKeyHash := address.Hash160(privKey.PubKey().SerializeCompressed())
	addr, err := address.NewAddressWitnessPubKeyHash(
		pubKeyHash, chainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return pkScript
}
