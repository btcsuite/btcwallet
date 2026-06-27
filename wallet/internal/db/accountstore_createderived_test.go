package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	// Test errors for CreateDerivedAccount ops testing.
	errTestWallet = errors.New("wallet")
	errTestScope  = errors.New("scope")
	errTestBoom   = errors.New("boom")
)

// TestCreateDerivedAccountParamsValidate verifies derived account creation
// validation rejects missing and reserved names.
func TestCreateDerivedAccountParamsValidate(t *testing.T) {
	t.Parallel()

	err := (&CreateDerivedAccountParams{Name: "default"}).Validate()
	require.NoError(t, err)

	err = (&CreateDerivedAccountParams{}).Validate()
	require.ErrorIs(t, err, ErrMissingAccountName)

	err = (&CreateDerivedAccountParams{
		Name: DefaultImportedAccountName,
	}).Validate()
	require.ErrorIs(t, err, ErrReservedAccountName)
}

// TestCreateDerivedAccountWithOps verifies that the shared helper owns the
// common derived-account workflow and returns the normalized AccountInfo.
func TestCreateDerivedAccountWithOps(t *testing.T) {
	t.Parallel()

	params := CreateDerivedAccountParams{
		WalletID: 7,
		Scope: KeyScope{
			Purpose: 49,
			Coin:    0,
		},
		Name: "savings",
	}
	createdAt := time.Unix(123, 0)
	expectedRow := CreateDerivedAccountRow{
		AccountNumber: sql.NullInt64{Int64: 12, Valid: true},
		CreatedAt:     createdAt,
	}

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// Verify call order: WalletWatchOnly -> EnsureScope ->
	// AllocateAccountNumber -> CreateDerivedAccount.
	walletCall := ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		true, nil,
	).Once()
	ensureScopeCall := ops.On(
		"EnsureScope", mock.Anything, uint32(7), params.Scope,
	).Return(int64(11), ScopeAddrMap[KeyScopeBIP0049Plus], nil).Once()
	allocateCall := ops.On(
		"AllocateAccountNumber", mock.Anything, int64(11),
	).Return(int64(12), nil).Once()
	createCall := ops.On(
		"CreateDerivedAccount", mock.Anything, int64(11), int64(12),
		"savings", mock.Anything,
	).Return(expectedRow, nil).Once()

	mock.InOrder(walletCall, ensureScopeCall, allocateCall, createCall)

	ctx := t.Context()
	info, err := CreateDerivedAccountWithOps(
		ctx, params, ops, testValidWatchOnlyDeriveFn(),
	)

	require.NoError(t, err)
	require.NotNil(t, info.AccountNumber)
	require.Equal(t, uint32(12), *info.AccountNumber)
	require.Equal(t, params.Name, info.AccountName)
	require.False(t, info.IsImported)
	require.True(t, info.IsWatchOnly)
	require.Equal(t, createdAt, info.CreatedAt)
	require.Equal(t, params.Scope, info.KeyScope)
	require.Equal(t, ScopeAddrMap[params.Scope], info.AddrSchema)
}

// TestCreateDerivedAccountWithOpsRejectsInvalidParams verifies that the shared
// helper validates the public request before any backend step runs.
func TestCreateDerivedAccountWithOpsRejectsInvalidParams(t *testing.T) {
	t.Parallel()

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// Pass empty params (missing Name). No backend methods should be called.
	info, err := CreateDerivedAccountWithOps(
		t.Context(), CreateDerivedAccountParams{}, ops, testValidDeriveFn(),
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrMissingAccountName)

	// Explicitly assert zero calls for each backend method.
	ops.AssertNotCalled(t, "WalletWatchOnly")
	ops.AssertNotCalled(t, "EnsureScope")
	ops.AssertNotCalled(t, "AllocateAccountNumber")
	ops.AssertNotCalled(t, "CreateDerivedAccount")
}

// TestCreateDerivedAccountWithOpsNilAccountNumber verifies that the shared
// helper rejects a nil account number returned from the backend.
func TestCreateDerivedAccountWithOpsNilAccountNumber(t *testing.T) {
	t.Parallel()

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		false, nil,
	).Once()
	ops.On(
		"EnsureScope", mock.Anything, uint32(7), KeyScope{
			Purpose: 49,
			Coin:    0,
		},
	).Return(int64(8), ScopeAddrMap[KeyScopeBIP0049Plus], nil).Once()
	ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
		int64(9), nil,
	).Once()
	ops.On(
		"CreateDerivedAccount", mock.Anything, int64(8), int64(9), "savings",
		mock.Anything,
	).Return(
		CreateDerivedAccountRow{
			CreatedAt: time.Unix(456, 0),
		}, nil,
	).Once()

	info, err := CreateDerivedAccountWithOps(
		t.Context(), testCreateDerivedAccountParams(), ops,
		testValidDeriveFn(),
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrNilDBAccountNumber)
}

// TestCreateDerivedAccountWithOpsMaxAccountNumber verifies that the shared
// helper preserves the existing max-account-number error mapping.
func TestCreateDerivedAccountWithOpsMaxAccountNumber(t *testing.T) {
	t.Parallel()

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		false, nil,
	).Once()
	ops.On(
		"EnsureScope", mock.Anything, uint32(7), KeyScope{
			Purpose: 49,
			Coin:    0,
		},
	).Return(int64(8), ScopeAddrMap[KeyScopeBIP0049Plus], nil).Once()
	ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
		int64(^uint32(0))+1, nil,
	).Once()

	info, err := CreateDerivedAccountWithOps(
		t.Context(), testCreateDerivedAccountParams(), ops,
		testValidDeriveFn(),
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrMaxAccountNumberReached)
	require.ErrorContains(t, err, "exceeds max")
	ops.AssertNotCalled(t, "CreateDerivedAccount")
}

// TestCreateDerivedAccountWithOpsWrapsStageErrors verifies that the shared
// helper keeps stage-specific error context around backend failures and
// short-circuits on early errors.
func TestCreateDerivedAccountWithOpsWrapsStageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setupOps        func() *mockCreateDerivedAccountOps
		wantErr         error
		wantWrappedText string
	}{
		{
			name: "wallet watch only",
			setupOps: func() *mockCreateDerivedAccountOps {
				ops := &mockCreateDerivedAccountOps{}
				ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
					false, errTestWallet,
				).Once()

				return ops
			},
			wantErr: errTestWallet,
		},
		{
			name: "ensure scope",
			setupOps: func() *mockCreateDerivedAccountOps {
				ops := &mockCreateDerivedAccountOps{}
				ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
					false, nil,
				).Once()
				ops.On(
					"EnsureScope", mock.Anything, uint32(7), KeyScope{
						Purpose: 49,
						Coin:    0,
					},
				).Return(int64(0), ScopeAddrSchema{}, errTestScope).Once()

				return ops
			},
			wantErr: errTestScope,
		},
		{
			name: "allocate account number",
			setupOps: func() *mockCreateDerivedAccountOps {
				ops := &mockCreateDerivedAccountOps{}
				ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
					false, nil,
				).Once()
				ops.On(
					"EnsureScope", mock.Anything, uint32(7), KeyScope{
						Purpose: 49,
						Coin:    0,
					},
				).Return(
					int64(8), ScopeAddrMap[KeyScopeBIP0049Plus], nil,
				).Once()
				ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
					int64(0), errTestBoom,
				).Once()

				return ops
			},
			wantErr:         errTestBoom,
			wantWrappedText: "allocate account number: boom",
		},
		{
			name: "create account",
			setupOps: func() *mockCreateDerivedAccountOps {
				ops := &mockCreateDerivedAccountOps{}
				ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
					false, nil,
				).Once()
				ops.On("EnsureScope", mock.Anything, uint32(7), KeyScope{
					Purpose: 49,
					Coin:    0,
				}).Return(
					int64(8), ScopeAddrMap[KeyScopeBIP0049Plus], nil,
				).Once()
				ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
					int64(9), nil,
				).Once()
				ops.On("CreateDerivedAccount", mock.Anything, int64(8),
					int64(9), "savings", mock.Anything,
				).Return(
					CreateDerivedAccountRow{}, errTestBoom,
				).Once()

				return ops
			},
			wantErr:         errTestBoom,
			wantWrappedText: "create account: boom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ops := tc.setupOps()
			t.Cleanup(func() {
				ops.AssertExpectations(t)
			})

			info, err := CreateDerivedAccountWithOps(
				t.Context(), testCreateDerivedAccountParams(), ops,
				testValidDeriveFn(),
			)

			require.Nil(t, info)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.wantErr)

			if tc.wantWrappedText != "" {
				require.EqualError(t, err, tc.wantWrappedText)
			}
		})
	}
}

// TestCreateDerivedAccountWithOpsDeriveFnInvokedOnce verifies that the shared
// helper invokes the derivation callback exactly once after allocating the
// account number, with the wallet's watch-only mode and the allocated account
// number, and forwards the returned material to CreateDerivedAccount.
func TestCreateDerivedAccountWithOpsDeriveFnInvokedOnce(t *testing.T) {
	t.Parallel()

	derived := newSpendableDerivedAccountData()
	rec := &deriveFnRecorder{returnData: derived}

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		false, nil,
	).Once()
	ops.On(
		"EnsureScope", mock.Anything, uint32(7), KeyScope{
			Purpose: 49,
			Coin:    0,
		},
	).Return(int64(8), ScopeAddrMap[KeyScopeBIP0049Plus], nil).Once()
	ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
		int64(9), nil,
	).Once()
	ops.On(
		"CreateDerivedAccount", mock.Anything, int64(8), int64(9), "savings",
		derived,
	).Return(
		CreateDerivedAccountRow{
			AccountNumber: sql.NullInt64{Int64: 9, Valid: true},
			CreatedAt:     time.Unix(101, 0),
		}, nil,
	).Once()

	info, err := CreateDerivedAccountWithOps(
		t.Context(), testCreateDerivedAccountParams(), ops, rec.fn(),
	)

	require.NoError(t, err)
	require.NotNil(t, info)
	require.Len(t, rec.calls, 1)
	require.Equal(t, uint32(9), rec.calls[0].accountNumber)
	require.False(t, rec.calls[0].walletIsWatchOnly)
}

// TestCreateDerivedAccountWithOpsRollsBackOnDeriveFnError verifies that the
// allocation is unwound when the derivation callback returns an error: the
// backend's CreateDerivedAccount step must NOT run, so the caller's outer
// transaction can roll back the allocation by aborting the surrounding tx.
func TestCreateDerivedAccountWithOpsRollsBackOnDeriveFnError(t *testing.T) {
	t.Parallel()

	rec := &deriveFnRecorder{returnErr: errTestBoom}

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		false, nil,
	).Once()
	ops.On(
		"EnsureScope", mock.Anything, uint32(7), KeyScope{
			Purpose: 49,
			Coin:    0,
		},
	).Return(int64(8), ScopeAddrMap[KeyScopeBIP0049Plus], nil).Once()
	ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
		int64(9), nil,
	).Once()

	info, err := CreateDerivedAccountWithOps(
		t.Context(), testCreateDerivedAccountParams(), ops, rec.fn(),
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, errTestBoom)
	require.EqualError(t, err, "derive account: boom")
	require.Len(t, rec.calls, 1)
	ops.AssertNotCalled(t, "CreateDerivedAccount")
}

// TestCreateDerivedAccountWithOpsNilDeriveFn verifies the contract rejects a
// nil derivation callback up front before any backend stage runs.
func TestCreateDerivedAccountWithOpsNilDeriveFn(t *testing.T) {
	t.Parallel()

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	info, err := CreateDerivedAccountWithOps(
		t.Context(), testCreateDerivedAccountParams(), ops, nil,
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, errNilAccountDerivationFunc)
	ops.AssertNotCalled(t, "WalletWatchOnly")
	ops.AssertNotCalled(t, "EnsureScope")
	ops.AssertNotCalled(t, "AllocateAccountNumber")
	ops.AssertNotCalled(t, "CreateDerivedAccount")
}

// TestCreateDerivedAccountWithOpsRejectsInvalidDerivedDataNil verifies that nil
// callback data is rejected before the backend CreateDerivedAccount step runs.
func TestCreateDerivedAccountWithOpsRejectsInvalidDerivedDataNil(t *testing.T) {
	t.Parallel()

	rec := &deriveFnRecorder{returnData: nil}

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		false, nil,
	).Once()
	ops.On(
		"EnsureScope", mock.Anything, uint32(7), KeyScope{
			Purpose: 49,
			Coin:    0,
		},
	).Return(int64(8), ScopeAddrMap[KeyScopeBIP0049Plus], nil).Once()
	ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
		int64(9), nil,
	).Once()

	info, err := CreateDerivedAccountWithOps(
		t.Context(), testCreateDerivedAccountParams(), ops, rec.fn(),
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrNilDerivedAccountData)
	ops.AssertNotCalled(t, "CreateDerivedAccount")
}

// TestCreateDerivedAccountWithOpsRejectsInvalidDerivedDataMissingPublicKey
// verifies that derived data without a public key is rejected before the
// backend's CreateDerivedAccount step runs.
func TestCreateDerivedAccountWithOpsRejectsInvalidDerivedDataMissingPublicKey(
	t *testing.T) {

	t.Parallel()

	rec := &deriveFnRecorder{returnData: &DerivedAccountData{
		EncryptedPrivateKey: []byte{0x1},
	}}

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		false, nil,
	).Once()
	ops.On(
		"EnsureScope", mock.Anything, uint32(7), KeyScope{
			Purpose: 49,
			Coin:    0,
		},
	).Return(int64(8), ScopeAddrMap[KeyScopeBIP0049Plus], nil).Once()
	ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
		int64(9), nil,
	).Once()

	info, err := CreateDerivedAccountWithOps(
		t.Context(), testCreateDerivedAccountParams(), ops, rec.fn(),
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, errMissingDerivedPublicKey)
	ops.AssertNotCalled(t, "CreateDerivedAccount")
}

// TestCreateDerivedAccountWithOpsRejectsInvalidDerivedDataMissingPrivateKey
// verifies that spendable-wallet derivations missing a private key are
// rejected.
func TestCreateDerivedAccountWithOpsRejectsInvalidDerivedDataMissingPrivateKey(
	t *testing.T) {

	t.Parallel()

	rec := &deriveFnRecorder{returnData: &DerivedAccountData{
		PublicKey: []byte{0x02, 0xab},
	}}

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		false, nil,
	).Once()
	ops.On(
		"EnsureScope", mock.Anything, uint32(7), KeyScope{
			Purpose: 49,
			Coin:    0,
		},
	).Return(int64(8), ScopeAddrMap[KeyScopeBIP0049Plus], nil).Once()
	ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
		int64(9), nil,
	).Once()

	info, err := CreateDerivedAccountWithOps(
		t.Context(), testCreateDerivedAccountParams(), ops, rec.fn(),
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, errMissingDerivedPrivateKey)
	ops.AssertNotCalled(t, "CreateDerivedAccount")
}

// TestCreateDerivedAccountWithOpsRejectsInvalidDerivedDataWatchOnlyHasPriv
// verifies that watch-only wallets cannot persist an encrypted private key.
func TestCreateDerivedAccountWithOpsRejectsInvalidDerivedDataWatchOnlyHasPriv(
	t *testing.T) {

	t.Parallel()

	rec := &deriveFnRecorder{returnData: &DerivedAccountData{
		PublicKey:           []byte{0x02, 0xab},
		EncryptedPrivateKey: []byte{0x1},
	}}

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		true, nil,
	).Once()
	ops.On(
		"EnsureScope", mock.Anything, uint32(7), KeyScope{
			Purpose: 49,
			Coin:    0,
		},
	).Return(int64(8), ScopeAddrMap[KeyScopeBIP0049Plus], nil).Once()
	ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
		int64(9), nil,
	).Once()

	info, err := CreateDerivedAccountWithOps(
		t.Context(), testCreateDerivedAccountParams(), ops, rec.fn(),
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, errWatchOnlyDerivedPrivateKey)
	ops.AssertNotCalled(t, "CreateDerivedAccount")
}

// testCreateDerivedAccountParams returns one valid derived-account request for
// shared helper tests.
func testCreateDerivedAccountParams() CreateDerivedAccountParams {
	return CreateDerivedAccountParams{
		WalletID: 7,
		Scope: KeyScope{
			Purpose: 49,
			Coin:    0,
		},
		Name: "savings",
	}
}

// mockCreateDerivedAccountOps is a mock implementation of
// CreateDerivedAccountOps.
type mockCreateDerivedAccountOps struct {
	mock.Mock
}

var _ CreateDerivedAccountOps = (*mockCreateDerivedAccountOps)(nil)

// WalletWatchOnly implements CreateDerivedAccountOps.
func (m *mockCreateDerivedAccountOps) WalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	args := m.Called(ctx, walletID)

	isWatchOnly, ok := args.Get(0).(bool)
	if !ok {
		return false, mockTypeError("WalletWatchOnly result")
	}

	return isWatchOnly, args.Error(1)
}

// EnsureScope implements CreateDerivedAccountOps.
func (m *mockCreateDerivedAccountOps) EnsureScope(ctx context.Context,
	walletID uint32,
	scope KeyScope) (int64, ScopeAddrSchema, error) {

	args := m.Called(ctx, walletID, scope)

	scopeID, ok := args.Get(0).(int64)
	if !ok {
		return 0, ScopeAddrSchema{}, mockTypeError("EnsureScope result")
	}

	schema, ok := args.Get(1).(ScopeAddrSchema)
	if !ok {
		return 0, ScopeAddrSchema{}, mockTypeError(
			"EnsureScope schema result",
		)
	}

	return scopeID, schema, args.Error(2)
}

// AllocateAccountNumber implements CreateDerivedAccountOps.
func (m *mockCreateDerivedAccountOps) AllocateAccountNumber(ctx context.Context,
	scopeID int64) (int64, error) {

	args := m.Called(ctx, scopeID)

	accountNum, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("AllocateAccountNumber result")
	}

	return accountNum, args.Error(1)
}

// CreateDerivedAccount implements CreateDerivedAccountOps.
func (m *mockCreateDerivedAccountOps) CreateDerivedAccount(ctx context.Context,
	scopeID int64, accountNumber int64, name string,
	derived *DerivedAccountData) (CreateDerivedAccountRow, error) {

	args := m.Called(ctx, scopeID, accountNumber, name, derived)

	row, ok := args.Get(0).(CreateDerivedAccountRow)
	if !ok {
		return CreateDerivedAccountRow{}, mockTypeError(
			"CreateDerivedAccount result",
		)
	}

	return row, args.Error(1)
}

// deriveFnRecorder captures the AccountDerivationFunc invocations performed by
// CreateDerivedAccountWithOps so tests can assert call ordering and arguments.
type deriveFnRecorder struct {
	calls      []deriveFnCall
	returnData *DerivedAccountData
	returnErr  error
}

// deriveFnCall records one AccountDerivationFunc invocation.
type deriveFnCall struct {
	scope             KeyScope
	accountNumber     uint32
	walletIsWatchOnly bool
}

// fn returns the AccountDerivationFunc closure that records each invocation.
func (r *deriveFnRecorder) fn() AccountDerivationFunc {
	return func(_ context.Context, scope KeyScope, accountNumber uint32,
		walletIsWatchOnly bool) (*DerivedAccountData, error) {

		r.calls = append(r.calls, deriveFnCall{
			scope:             scope,
			accountNumber:     accountNumber,
			walletIsWatchOnly: walletIsWatchOnly,
		})

		if r.returnErr != nil {
			return nil, r.returnErr
		}

		return r.returnData, nil
	}
}

// newSpendableDerivedAccountData returns a minimal valid DerivedAccountData
// for spendable-wallet tests.
func newSpendableDerivedAccountData() *DerivedAccountData {
	return &DerivedAccountData{
		PublicKey:            []byte{0x02, 0xab},
		EncryptedPrivateKey:  []byte{0xde, 0xad},
		MasterKeyFingerprint: 0x1234,
	}
}

// newWatchOnlyDerivedAccountData returns a minimal valid DerivedAccountData
// for watch-only-wallet tests.
func newWatchOnlyDerivedAccountData() *DerivedAccountData {
	return &DerivedAccountData{
		PublicKey:            []byte{0x02, 0xab},
		MasterKeyFingerprint: 0x1234,
	}
}

// testValidDeriveFn returns an AccountDerivationFunc that succeeds with valid
// spendable data — used by tests that exercise non-derivation failure paths.
func testValidDeriveFn() AccountDerivationFunc {
	return (&deriveFnRecorder{
		returnData: newSpendableDerivedAccountData(),
	}).fn()
}

// testValidWatchOnlyDeriveFn returns an AccountDerivationFunc that succeeds
// with valid watch-only data — used by watch-only wallet tests.
func testValidWatchOnlyDeriveFn() AccountDerivationFunc {
	return (&deriveFnRecorder{
		returnData: newWatchOnlyDerivedAccountData(),
	}).fn()
}
