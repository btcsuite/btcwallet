package db

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/stretchr/testify/require"
)

// TestNilIfEmptyBytes verifies that nil and empty slices normalize to nil while
// non-empty slices are preserved.
func TestNilIfEmptyBytes(t *testing.T) {
	t.Parallel()

	t.Run("nil input", func(t *testing.T) {
		t.Parallel()

		result := NilIfEmptyBytes(nil)

		require.Nil(t, result)
	})

	t.Run("empty non-nil input", func(t *testing.T) {
		t.Parallel()

		result := NilIfEmptyBytes([]byte{})

		require.Nil(t, result)
	})

	t.Run("non-empty input", func(t *testing.T) {
		t.Parallel()

		input := []byte{1, 2, 3}
		result := NilIfEmptyBytes(input)

		require.NotNil(t, result)
		require.Equal(t, input, result)
	})
}

// TestDatabaseIdentityValidation covers ordinary and renamed-signet invariants.
func TestDatabaseIdentityValidation(t *testing.T) {
	t.Parallel()

	// Arrange: Derive signet inputs and isolate the variants used by the table.
	c := chaincfg.DefaultSignetChallenge
	d := chainhash.DoubleHashB(append([]byte{byte(len(c))}, c...))
	sig := chaincfg.SigNetParams
	sig.Name = "private-signet"
	wrong := sig
	wrong.Net++
	tests := []struct {
		name   string
		params *chaincfg.Params
		digest []byte
		want   error
	}{
		{
			name:   "ordinary",
			params: &chaincfg.RegressionNetParams,
		},
		{
			name:   "ordinary digest",
			params: &chaincfg.RegressionNetParams,
			digest: d,
			want:   ErrInvalidDatabaseIdentity,
		},
		{
			name:   "renamed signet",
			params: &sig,
			digest: d,
		},
		{
			name:   "missing digest",
			params: &sig,
			want:   ErrInvalidDatabaseIdentity,
		},
		{
			name:   "wrong magic",
			params: &wrong,
			digest: d,
			want:   ErrInvalidDatabaseIdentity,
		},
		{
			name:   "short",
			params: &sig,
			digest: d[:len(d)-1],
			want:   ErrInvalidDatabaseIdentity,
		},
		{
			name: "missing parameters",
			want: ErrInvalidDatabaseIdentity,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: Build the tuple checked before SQL connection setup.
			_, err := NewDatabaseIdentity(tc.params, tc.digest)

			// Assert: The sentinel appears exactly for invalid input rows.
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// TestDatabaseIdentityCopiesValues proves caller and SQL slices never alias.
func TestDatabaseIdentityCopiesValues(t *testing.T) {
	t.Parallel()

	// Arrange: Detach caller-owned signet parameters and challenge digest.
	challenge := chaincfg.DefaultSignetChallenge
	prefixedChallenge := append([]byte{byte(len(challenge))}, challenge...)
	digest := chainhash.DoubleHashB(prefixedChallenge)
	params := chaincfg.SigNetParams
	sourceGenesis := *params.GenesisHash
	params.GenesisHash = &sourceGenesis
	identity, err := NewDatabaseIdentity(&params, digest)
	require.NoError(t, err)

	// Act: Mutate caller inputs and one returned SQL digest.
	sourceGenesis[0]++
	digest[0]++
	_, _, storedDigest := identity.Values()
	storedDigest[0]++
	gotGenesis, _, gotDigest := identity.Values()

	// Assert: Validation and outputs retain the original canonical tuple.
	require.NoError(t, identity.Validate())
	require.Equal(t, chaincfg.SigNetParams.GenesisHash[:], gotGenesis)
	require.Equal(t, chainhash.DoubleHashB(prefixedChallenge), gotDigest)
}

// TestVerifyStoredDatabaseIdentityPreservesOperationalError proves count and
// read failures remain distinguishable from a persisted identity mismatch.
func TestVerifyStoredDatabaseIdentityPreservesOperationalError(t *testing.T) {
	t.Parallel()

	// Arrange: Make the count and row-read callbacks fail independently with
	// the same observable operational cause.
	identity, err := NewDatabaseIdentity(&chaincfg.RegressionNetParams, nil)
	require.NoError(t, err)

	operationErr := errors.New("query interrupted")
	count := func(context.Context) (int64, error) { return 1, nil }
	badCount := func(context.Context) (int64, error) { return 0, operationErr }
	read := func(context.Context) ([]byte, int64, []byte, error) {
		return nil, 0, nil, operationErr
	}

	// Act: Verify each failing query through the shared callback boundary.
	countErr := VerifyStoredDatabaseIdentity(
		t.Context(), identity, badCount, read,
	)
	readErr := VerifyStoredDatabaseIdentity(t.Context(), identity, count, read)

	// Assert: Both causes survive without the persisted mismatch sentinel.
	require.ErrorIs(t, countErr, operationErr)
	require.NotErrorIs(t, countErr, ErrDatabaseIdentityMismatch)
	require.ErrorIs(t, readErr, operationErr)
	require.NotErrorIs(t, readErr, ErrDatabaseIdentityMismatch)
}
