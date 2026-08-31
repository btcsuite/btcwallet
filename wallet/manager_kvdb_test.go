package wallet

//nolint:staticcheck // Test the temporary kvdb compatibility path.
import (
	"testing"

	kvdb "github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/stretchr/testify/require"
)

// TestKVDBManagerBackendRetainedData verifies that only Load may reuse the
// Manager-owned data for the one opened legacy wallet.
func TestKVDBManagerBackendRetainedData(t *testing.T) {
	t.Parallel()

	// Arrange: Retain one Manager-owned walletData value for the current
	// wallet name.
	retained := &walletData{id: 42}
	backend := &kvdbManagerBackend{
		store:      &kvdb.Store{}, //nolint:staticcheck
		walletName: "managed",
		walletData: retained,
	}

	// Act: Load the current wallet and attempt to create it again through the
	// backend paths that deliberately differ on retained data reuse.
	loaded, loadErr := backend.load(t.Context(), Config{Name: "managed"})
	created, createErr := backend.create(
		t.Context(), Config{Name: "managed"}, CreateWalletParams{}, nil,
	)

	// Assert: Reload reuses Manager-owned data, while duplicate creation
	// remains an error.
	require.NoError(t, loadErr)
	require.Same(t, retained, loaded)
	require.ErrorIs(t, createErr, ErrInvalidParam)
	require.Nil(t, created)
}
