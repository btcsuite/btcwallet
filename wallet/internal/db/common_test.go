package db

import (
	"testing"

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
