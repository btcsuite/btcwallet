package kvdb

import (
	"context"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// bip84Scope is the db.KeyScope used by the account-secret tests.
var bip84Scope = db.KeyScope{
	Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
	Coin:    waddrmgr.KeyScopeBIP0084.Coin,
}

// TestGetAccountSecretDerived verifies that a derived account returns its
// encrypted private key when selected by BIP44 account number.
func TestGetAccountSecretDerived(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	deriveFn := fingerprintDeriveFnFixture(t, mgr)
	info, err := store.CreateDerivedAccount(t.Context(),
		db.CreateDerivedAccountParams{
			Scope: bip84Scope,
			Name:  fpDerivedAccountName,
		},
		deriveFn,
	)
	require.NoError(t, err)
	require.NotNil(t, info.AccountNumber)

	secret, err := store.GetAccountSecret(t.Context(),
		db.GetAccountSecretQuery{
			Scope:         bip84Scope,
			AccountNumber: *info.AccountNumber,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, secret)
	require.NotNil(t, secret.EncryptedPrivateKey,
		"derived account must expose encrypted private key")
}

// TestGetAccountSecretNotFound verifies that querying an absent account number
// returns ErrAccountNotFound.
func TestGetAccountSecretNotFound(t *testing.T) {
	t.Parallel()

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	_, err := store.GetAccountSecret(t.Context(),
		db.GetAccountSecretQuery{
			Scope:         bip84Scope,
			AccountNumber: 99,
		},
	)
	require.ErrorIs(t, err, db.ErrAccountNotFound)
}

// TestGetAccountSecretCanceledCtx verifies that a canceled context aborts the
// read: a signing request that is canceled before it reaches walletdb must not
// enter the store and return secret account material.
func TestGetAccountSecretCanceledCtx(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	deriveFn := fingerprintDeriveFnFixture(t, mgr)
	info, err := store.CreateDerivedAccount(t.Context(),
		db.CreateDerivedAccountParams{
			Scope: bip84Scope,
			Name:  "cancel-derived",
		},
		deriveFn,
	)
	require.NoError(t, err)
	require.NotNil(t, info.AccountNumber)

	// The account exists, so an uncanceled read would succeed. A canceled
	// context must abort before the walletdb lookup and surface
	// context.Canceled instead of the secret.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	secret, err := store.GetAccountSecret(ctx,
		db.GetAccountSecretQuery{
			Scope:         bip84Scope,
			AccountNumber: *info.AccountNumber,
		},
	)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, secret)
}
