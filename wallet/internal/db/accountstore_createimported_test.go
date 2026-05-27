package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	// Test errors for CreateImportedAccount ops testing.
	errTestImportedWallet  = errors.New("wallet")
	errTestImportedScope   = errors.New("scope")
	errTestImportedAccount = errors.New("account")
	errTestImportedSecret  = errors.New("secret")
	errTestImportedReload  = errors.New("reload")
)

// TestCreateImportedAccountParamsValidateBasic verifies imported account
// creation validation rejects missing account names and public keys.
func TestCreateImportedAccountParamsValidateBasic(t *testing.T) {
	t.Parallel()

	err := (&CreateImportedAccountParams{
		Name:      "imported",
		PublicKey: []byte{1},
	}).ValidateBasic()
	require.NoError(t, err)

	err = (&CreateImportedAccountParams{}).ValidateBasic()
	require.ErrorIs(t, err, ErrMissingAccountName)

	err = (&CreateImportedAccountParams{Name: "imported"}).ValidateBasic()
	require.ErrorIs(t, err, ErrMissingAccountPublicKey)
}

// TestCreateImportedAccountWithOps verifies that the shared helper owns the
// imported-account workflow sequencing and returns the final AccountInfo.
func TestCreateImportedAccountWithOps(t *testing.T) {
	t.Parallel()

	params := testCreateImportedAccountParams()
	createdAt := time.Unix(123, 0)
	expectedInfo := &AccountInfo{
		AccountNumber:        0,
		AccountName:          params.Name,
		Origin:               ImportedAccount,
		IsWatchOnly:          false,
		CreatedAt:            createdAt,
		KeyScope:             params.Scope,
		AddrSchema:           ScopeAddrMap[params.Scope],
		PublicKey:            params.PublicKey,
		MasterKeyFingerprint: params.MasterFingerprint,
	}

	ops := &mockCreateImportedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	walletCall := ops.On(
		"IsWalletWatchOnly", mock.Anything, params.WalletID,
	).Return(false, nil).Once()
	ensureScopeCall := ops.On(
		"EnsureKeyScope", mock.Anything, params.WalletID, params.Scope,
		params.AddrSchema,
	).Return(int64(11), nil).Once()
	createCall := ops.On(
		"CreateImportedAccount", mock.Anything,
		CreateImportedAccountInsertRequest{
			ScopeID:           11,
			Name:              params.Name,
			PublicKey:         params.PublicKey,
			MasterFingerprint: params.MasterFingerprint,
		},
	).Return(int64(22), nil).Once()
	secretCall := ops.On(
		"CreateAccountSecret", mock.Anything, int64(22),
		params.EncryptedPrivateKey,
	).Return(nil).Once()
	reloadCall := ops.On(
		"GetAccountInfoByID", mock.Anything, int64(22),
	).Return(expectedInfo, nil).Once()

	mock.InOrder(
		walletCall, ensureScopeCall, createCall, secretCall, reloadCall,
	)

	info, err := CreateImportedAccountWithOps(t.Context(), params, ops)

	require.NoError(t, err)
	require.Same(t, expectedInfo, info)
	require.Equal(t, createdAt, info.CreatedAt)
	require.Equal(t, ScopeAddrMap[params.Scope], info.AddrSchema)
	require.Equal(t, params.PublicKey, info.PublicKey)
	require.Equal(t, params.MasterFingerprint, info.MasterKeyFingerprint)
}

// TestCreateImportedAccountWithOpsRejectsInvalidParams verifies the shared
// helper validates the request before any backend step runs.
func TestCreateImportedAccountWithOpsRejectsInvalidParams(t *testing.T) {
	t.Parallel()

	ops := &mockCreateImportedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	info, err := CreateImportedAccountWithOps(t.Context(),
		CreateImportedAccountParams{}, ops)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrMissingAccountName)
	ops.AssertNotCalled(t, "IsWalletWatchOnly")
	ops.AssertNotCalled(t, "EnsureKeyScope")
	ops.AssertNotCalled(t, "CreateImportedAccount")
	ops.AssertNotCalled(t, "CreateAccountSecret")
	ops.AssertNotCalled(t, "GetAccountInfoByID")
}

// TestCreateImportedAccountWithOpsRejectsWatchOnlyViolation verifies that the
// shared helper blocks spendable imports on watch-only wallets before writes.
func TestCreateImportedAccountWithOpsRejectsWatchOnlyViolation(t *testing.T) {
	t.Parallel()

	params := testCreateImportedAccountParams()

	ops := &mockCreateImportedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("IsWalletWatchOnly", mock.Anything, params.WalletID).Return(
		true, nil,
	).Once()

	info, err := CreateImportedAccountWithOps(t.Context(), params, ops)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrWatchOnlyViolation)
	require.EqualError(
		t, err, "wallet 7 cannot create account \"imported\": watch-only "+
			"invariant violation",
	)
	ops.AssertNotCalled(t, "EnsureKeyScope")
	ops.AssertNotCalled(t, "CreateImportedAccount")
	ops.AssertNotCalled(t, "CreateAccountSecret")
	ops.AssertNotCalled(t, "GetAccountInfoByID")
}

// TestCreateImportedAccountWithOpsSkipsSecretInsertion verifies that the
// shared helper omits the secret write when no encrypted private key exists.
func TestCreateImportedAccountWithOpsSkipsSecretInsertion(t *testing.T) {
	t.Parallel()

	params := testCreateImportedAccountParams()
	params.EncryptedPrivateKey = nil
	expectedInfo := &AccountInfo{
		AccountNumber:        0,
		AccountName:          params.Name,
		Origin:               ImportedAccount,
		IsWatchOnly:          true,
		KeyScope:             params.Scope,
		AddrSchema:           ScopeAddrMap[params.Scope],
		PublicKey:            params.PublicKey,
		MasterKeyFingerprint: params.MasterFingerprint,
	}

	ops := &mockCreateImportedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	walletCall := ops.On("IsWalletWatchOnly", mock.Anything,
		params.WalletID,
	).Return(false, nil).Once()
	ensureScopeCall := ops.On("EnsureKeyScope", mock.Anything,
		params.WalletID, params.Scope, params.AddrSchema,
	).Return(int64(11), nil).Once()
	createCall := ops.On("CreateImportedAccount", mock.Anything,
		CreateImportedAccountInsertRequest{
			ScopeID:           11,
			Name:              params.Name,
			PublicKey:         params.PublicKey,
			MasterFingerprint: params.MasterFingerprint,
		},
	).Return(int64(22), nil).Once()
	reloadCall := ops.On("GetAccountInfoByID", mock.Anything,
		int64(22),
	).Return(expectedInfo, nil).Once()

	mock.InOrder(walletCall, ensureScopeCall, createCall, reloadCall)

	info, err := CreateImportedAccountWithOps(t.Context(), params, ops)

	require.NoError(t, err)
	require.Same(t, expectedInfo, info)
	ops.AssertNotCalled(t, "CreateAccountSecret")
}

// TestCreateImportedAccountWithOpsWrapsStageErrors verifies that the shared
// helper keeps stage-specific error context around backend failures.
func TestCreateImportedAccountWithOpsWrapsStageErrors(t *testing.T) {
	t.Parallel()

	t.Run("wallet watch only", func(t *testing.T) {
		t.Parallel()

		opOps := &mockCreateImportedAccountOps{}
		t.Cleanup(func() {
			opOps.AssertExpectations(t)
		})

		opOps.On("IsWalletWatchOnly", mock.Anything, uint32(7)).Return(
			false, errTestImportedWallet,
		).Once()

		info, err := CreateImportedAccountWithOps(t.Context(),
			testCreateImportedAccountParams(), opOps)

		require.Nil(t, info)
		require.ErrorIs(t, err, errTestImportedWallet)
		require.EqualError(t, err, "wallet watch only: wallet")
		opOps.AssertNotCalled(t, "EnsureKeyScope")
		opOps.AssertNotCalled(t, "CreateImportedAccount")
		opOps.AssertNotCalled(t, "CreateAccountSecret")
		opOps.AssertNotCalled(t, "GetAccountInfoByID")
	})

	t.Run("ensure scope", func(t *testing.T) {
		t.Parallel()

		params := testCreateImportedAccountParams()
		opOps := &mockCreateImportedAccountOps{}
		t.Cleanup(func() {
			opOps.AssertExpectations(t)
		})

		opOps.On("IsWalletWatchOnly", mock.Anything, params.WalletID).Return(
			false, nil,
		).Once()
		opOps.On("EnsureKeyScope", mock.Anything, params.WalletID,
			params.Scope, params.AddrSchema,
		).Return(int64(0), errTestImportedScope).Once()

		info, err := CreateImportedAccountWithOps(t.Context(), params, opOps)

		require.Nil(t, info)
		require.ErrorIs(t, err, errTestImportedScope)
		require.EqualError(t, err, "ensure scope: scope")
		opOps.AssertNotCalled(t, "CreateImportedAccount")
		opOps.AssertNotCalled(t, "CreateAccountSecret")
		opOps.AssertNotCalled(t, "GetAccountInfoByID")
	})

	t.Run("create account", func(t *testing.T) {
		t.Parallel()

		params := testCreateImportedAccountParams()
		opOps := &mockCreateImportedAccountOps{}
		t.Cleanup(func() {
			opOps.AssertExpectations(t)
		})

		opOps.On("IsWalletWatchOnly", mock.Anything, params.WalletID).Return(
			false, nil,
		).Once()
		opOps.On("EnsureKeyScope", mock.Anything, params.WalletID,
			params.Scope, params.AddrSchema,
		).Return(int64(11), nil).Once()
		opOps.On("CreateImportedAccount", mock.Anything,
			CreateImportedAccountInsertRequest{
				ScopeID:           11,
				Name:              params.Name,
				PublicKey:         params.PublicKey,
				MasterFingerprint: params.MasterFingerprint,
			},
		).Return(int64(0), errTestImportedAccount).Once()

		info, err := CreateImportedAccountWithOps(t.Context(), params, opOps)

		require.Nil(t, info)
		require.ErrorIs(t, err, errTestImportedAccount)
		require.EqualError(t, err, "create account: account")
		opOps.AssertNotCalled(t, "CreateAccountSecret")
		opOps.AssertNotCalled(t, "GetAccountInfoByID")
	})

	t.Run("insert account secret", func(t *testing.T) {
		t.Parallel()

		params := testCreateImportedAccountParams()
		opOps := &mockCreateImportedAccountOps{}
		t.Cleanup(func() {
			opOps.AssertExpectations(t)
		})

		opOps.On("IsWalletWatchOnly", mock.Anything, params.WalletID).Return(
			false, nil,
		).Once()
		opOps.On("EnsureKeyScope", mock.Anything, params.WalletID,
			params.Scope, params.AddrSchema,
		).Return(int64(11), nil).Once()
		opOps.On("CreateImportedAccount", mock.Anything,
			CreateImportedAccountInsertRequest{
				ScopeID:           11,
				Name:              params.Name,
				PublicKey:         params.PublicKey,
				MasterFingerprint: params.MasterFingerprint,
			},
		).Return(int64(22), nil).Once()
		opOps.On("CreateAccountSecret", mock.Anything, int64(22),
			params.EncryptedPrivateKey,
		).Return(errTestImportedSecret).Once()

		info, err := CreateImportedAccountWithOps(t.Context(), params, opOps)

		require.Nil(t, info)
		require.ErrorIs(t, err, errTestImportedSecret)
		require.EqualError(t, err, "insert account secrets: secret")
		opOps.AssertNotCalled(t, "GetAccountInfoByID")
	})

	t.Run("reload final account info", func(t *testing.T) {
		t.Parallel()

		params := testCreateImportedAccountParams()
		opOps := &mockCreateImportedAccountOps{}
		t.Cleanup(func() {
			opOps.AssertExpectations(t)
		})

		opOps.On("IsWalletWatchOnly", mock.Anything, params.WalletID).Return(
			false, nil,
		).Once()
		opOps.On("EnsureKeyScope", mock.Anything, params.WalletID,
			params.Scope, params.AddrSchema,
		).Return(int64(11), nil).Once()
		opOps.On("CreateImportedAccount", mock.Anything,
			CreateImportedAccountInsertRequest{
				ScopeID:           11,
				Name:              params.Name,
				PublicKey:         params.PublicKey,
				MasterFingerprint: params.MasterFingerprint,
			},
		).Return(int64(22), nil).Once()
		opOps.On("CreateAccountSecret", mock.Anything, int64(22),
			params.EncryptedPrivateKey,
		).Return(nil).Once()
		opOps.On("GetAccountInfoByID", mock.Anything, int64(22)).Return(
			nil, errTestImportedReload,
		).Once()

		info, err := CreateImportedAccountWithOps(t.Context(), params, opOps)

		require.Nil(t, info)
		require.ErrorIs(t, err, errTestImportedReload)
		require.EqualError(t, err, "get account info: reload")
	})
}

// testCreateImportedAccountParams returns one valid imported-account request
// for shared helper tests.
func testCreateImportedAccountParams() CreateImportedAccountParams {
	return CreateImportedAccountParams{
		WalletID: 7,
		Name:     "imported",
		Scope: KeyScope{
			Purpose: 84,
			Coin:    0,
		},
		MasterFingerprint:   0x1234,
		PublicKey:           []byte{0x02, 0xab},
		EncryptedPrivateKey: []byte{0xde, 0xad},
	}
}

// mockCreateImportedAccountOps is a mock implementation of
// CreateImportedAccountOps.
type mockCreateImportedAccountOps struct {
	mock.Mock
}

var _ CreateImportedAccountOps = (*mockCreateImportedAccountOps)(nil)

// IsWalletWatchOnly implements CreateImportedAccountOps.
func (m *mockCreateImportedAccountOps) IsWalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	args := m.Called(ctx, walletID)

	isWatchOnly, ok := args.Get(0).(bool)
	if !ok {
		return false, mockTypeError("IsWalletWatchOnly result")
	}

	return isWatchOnly, args.Error(1)
}

// EnsureKeyScope implements CreateImportedAccountOps.
func (m *mockCreateImportedAccountOps) EnsureKeyScope(ctx context.Context,
	walletID uint32, scope KeyScope, addrSchema *ScopeAddrSchema) (int64,
	error) {

	args := m.Called(ctx, walletID, scope, addrSchema)

	scopeID, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("EnsureKeyScope result")
	}

	return scopeID, args.Error(1)
}

// CreateImportedAccount implements CreateImportedAccountOps.
func (m *mockCreateImportedAccountOps) CreateImportedAccount(
	ctx context.Context, req CreateImportedAccountInsertRequest,
) (int64, error) {

	args := m.Called(ctx, req)

	accountID, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("CreateImportedAccount result")
	}

	return accountID, args.Error(1)
}

// CreateAccountSecret implements CreateImportedAccountOps.
func (m *mockCreateImportedAccountOps) CreateAccountSecret(ctx context.Context,
	accountID int64, encryptedPrivateKey []byte) error {

	args := m.Called(ctx, accountID, encryptedPrivateKey)

	return args.Error(0)
}

// GetAccountInfoByID implements CreateImportedAccountOps.
func (m *mockCreateImportedAccountOps) GetAccountInfoByID(ctx context.Context,
	accountID int64) (*AccountInfo, error) {

	args := m.Called(ctx, accountID)

	info, ok := args.Get(0).(*AccountInfo)
	if !ok && args.Get(0) != nil {
		return nil, mockTypeError("GetAccountInfoByID result")
	}

	return info, args.Error(1)
}

// TestCreateImportedAccountParamsValidateWatchOnly verifies the symmetric
// watch-only invariant rejects mismatched mode imports in both directions.
func TestCreateImportedAccountParamsValidateWatchOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		encryptedPrivKey []byte
		walletWatchOnly  bool
		wantErr          error
	}{
		{
			name:             "watch-only wallet rejects priv key",
			encryptedPrivKey: []byte{1},
			walletWatchOnly:  true,
			wantErr:          ErrWatchOnlyViolation,
		},
		{
			name:            "watch-only wallet accepts no priv key",
			walletWatchOnly: true,
		},
		{
			name:             "spendable wallet accepts priv key",
			encryptedPrivKey: []byte{1},
			walletWatchOnly:  false,
		},
		{
			name:            "spendable wallet accepts no priv key (kvdb path)",
			walletWatchOnly: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			params := &CreateImportedAccountParams{
				WalletID:            7,
				Name:                "imported",
				EncryptedPrivateKey: tc.encryptedPrivKey,
			}
			err := params.ValidateWatchOnly(tc.walletWatchOnly)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

// TestRequireAccountPrivKeyOnSpendable verifies the SQL-only symmetric
// rejection: a spendable wallet must not create an imported account without
// encrypted private-key material under ADR 0012.
func TestRequireAccountPrivKeyOnSpendable(t *testing.T) {
	t.Parallel()

	err := requireAccountPrivKeyOnSpendable(7, "imported", false, nil)
	require.ErrorIs(t, err, ErrSpendableWalletNeedsAccountPrivKey)

	err = requireAccountPrivKeyOnSpendable(7, "imported", false, []byte{1})
	require.NoError(t, err)

	// Watch-only wallets bypass this check; the watch-only-direction
	// rejection happens in ValidateWatchOnly above.
	err = requireAccountPrivKeyOnSpendable(7, "imported", true, nil)
	require.NoError(t, err)
}
