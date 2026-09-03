package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

func TestLoaderSetCreateScryptOptions(t *testing.T) {
	loader := NewLoader(
		&chaincfg.MainNetParams, t.TempDir(), true, 0, 0,
	)
	publicConfig := &waddrmgr.ScryptOptions{N: 16, R: 8, P: 1}
	privateConfig := &waddrmgr.ScryptOptions{N: 64, R: 8, P: 1}

	err := loader.SetCreateScryptOptions(publicConfig, privateConfig)
	require.NoError(t, err)

	publicConfig.N = 32
	privateConfig.N = 128
	require.Equal(t, 16, loader.cfg.createPublicScrypt.N)
	require.Equal(t, 64, loader.cfg.createPrivateScrypt.N)

	loader.wallet = &Wallet{}
	err = loader.SetCreateScryptOptions(publicConfig, privateConfig)
	require.ErrorIs(t, err, ErrLoaded)
}
