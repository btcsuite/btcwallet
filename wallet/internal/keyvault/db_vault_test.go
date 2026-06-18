package keyvault

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/stretchr/testify/require"
)

// errStoreUnavailable is a sentinel error for simulating store failures in
// tests.
var errStoreUnavailable = errors.New("store unavailable")

var (
	// correctPassphrase is used to assert correct passphrase usage.
	correctPassphrase = []byte("correct-passphrase")

	// wrongPassphrase is used to assert wrong passphrase usage.
	wrongPassphrase = []byte("wrong-passphrase")
)

// TestUnlockedStateZero verifies that zero clears runtime secret material.
func TestUnlockedStateZero(t *testing.T) {
	t.Parallel()

	cryptoKeyPrivate := snacl.CryptoKey{1, 2}
	cryptoKeyScript := snacl.CryptoKey{3, 4}
	seed := []byte("0123456789abcdef0123456789abcdef")
	hdRootKey, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	state := &unlockedState{
		cryptoKeyPrivate: cryptoKeyPrivate,
		cryptoKeyScript:  cryptoKeyScript,
		hdRootKey:        hdRootKey,
	}

	state.zero()

	require.Equal(t, snacl.CryptoKey{}, state.cryptoKeyPrivate)
	require.Equal(t, snacl.CryptoKey{}, state.cryptoKeyScript)
	require.Nil(t, state.hdRootKey)
}
