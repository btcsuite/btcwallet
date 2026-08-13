package pg

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockMigrationSession records migration session setting changes.
type mockMigrationSession struct {
	mock.Mock
}

var _ migrationSession = (*mockMigrationSession)(nil)

// ExecContext forwards a session setting change to the configured mock.
func (m *mockMigrationSession) ExecContext(ctx context.Context, query string,
	queryArgs ...any) (sql.Result, error) {

	callArgs := []any{ctx, query}
	callArgs = append(callArgs, queryArgs...)
	args := m.Called(callArgs...)

	sqlResult, _ := args.Get(0).(sql.Result)

	return sqlResult, args.Error(1)
}

// TestWithMigrationLockTimeout verifies lock timeout setup and cleanup.
func TestWithMigrationLockTimeout(t *testing.T) {
	t.Parallel()

	operationErr := errors.New("operation failed")
	resetErr := errors.New("reset failed")
	setErr := errors.New("set failed")

	testCases := []struct {
		name            string
		setErr          error
		operationErr    error
		resetErr        error
		expectOperation bool
		expectedErrors  []error
	}{
		{
			name:            "runs operation",
			expectOperation: true,
		},
		{
			name:            "preserves operation and reset failures",
			operationErr:    operationErr,
			resetErr:        resetErr,
			expectOperation: true,
			expectedErrors:  []error{operationErr, resetErr},
		},
		{
			name:           "stops after setup failure",
			setErr:         setErr,
			expectedErrors: []error{setErr},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			session := &mockMigrationSession{}
			setCall := session.On(
				"ExecContext", mock.Anything,
				setStatementTimeout, migrationLockTimeout.String(),
			).Return(nil, testCase.setErr).Once()

			if testCase.setErr == nil {
				resetCall := session.On(
					"ExecContext", mock.Anything,
					resetStatementTimeout,
				).Return(nil, testCase.resetErr).Once()
				mock.InOrder(setCall, resetCall)
			}

			operationCalled := false
			err := withMigrationLockTimeout(
				t.Context(), session, func() error {
					operationCalled = true

					return testCase.operationErr
				},
			)

			require.Equal(
				t, testCase.expectOperation, operationCalled,
			)

			if len(testCase.expectedErrors) == 0 {
				require.NoError(t, err)
			} else {
				for _, expectedErr := range testCase.expectedErrors {
					require.ErrorIs(t, err, expectedErr)
				}
			}

			session.AssertExpectations(t)
		})
	}
}
