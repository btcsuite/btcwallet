package keyvault

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/stretchr/testify/require"
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
