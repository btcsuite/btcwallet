package runtime

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test errors used by the runtime helper tests.
var errRuntimeOther = errors.New("other")

// TestAmbiguousTxCommitError verifies the sentinel-matching and unwrap
// behavior of AmbiguousTxCommitError.
func TestAmbiguousTxCommitError(t *testing.T) {
	t.Parallel()

	err := &AmbiguousTxCommitError{Err: io.EOF}
	wrappedSentinel := fmt.Errorf("wrap: %w", ErrAmbiguousTxCommit)

	require.ErrorIs(t, err, ErrAmbiguousTxCommit)
	require.False(t, err.Is(wrappedSentinel))
	require.Equal(t, io.EOF.Error(), err.Error())
	require.ErrorIs(t, err, io.EOF)
	require.Equal(
		t, ErrAmbiguousTxCommit.Error(), (&AmbiguousTxCommitError{}).Error(),
	)
	require.NoError(t, (*AmbiguousTxCommitError)(nil).Unwrap())
}

// TestCommitTransportError verifies that transport-shaped commit failures are
// detected as ambiguous-outcome candidates.
func TestCommitTransportError(t *testing.T) {
	t.Parallel()

	require.True(t, isCommitTransportError(io.EOF))
	require.True(t, isCommitTransportError(driver.ErrBadConn))
	require.True(t, isCommitTransportError(sql.ErrConnDone))
	require.True(t, isCommitTransportError(netTimeoutError{}))
	require.False(t, isCommitTransportError(errRuntimeOther))
	require.NotNil(t, extractNetError(netTimeoutError{}))
	require.Nil(t, extractNetError(errRuntimeOther))
}

// netTimeoutError is a test helper that reports a transport timeout.
type netTimeoutError struct{}

// Error returns the static timeout error string.
func (e netTimeoutError) Error() string {
	return "timeout"
}

// Timeout reports that the test error is a timeout.
func (e netTimeoutError) Timeout() bool {
	return true
}
