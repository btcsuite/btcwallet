package wallet

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestStorage(t *testing.T) {
	storage, err := NewAddressMapStorage("")
	require.NoError(t, err)

	err = storage.SetEthAddress("btcAddress", "ethAddress")
	require.NoError(t, err)

	storage.store.Close()

	storage2, err := NewAddressMapStorage("")
	require.NoError(t, err)

	ethAddress, err := storage2.GetEthAddress("btcAddress")
	require.NoError(t, err)

	require.Equal(t, "ethAddress", ethAddress)

	t.Cleanup(func() {
		storage2.store.Close()
		_ = os.Remove(DefaultStorageFileName)
	})
}
