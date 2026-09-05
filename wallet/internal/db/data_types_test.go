package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTxStatusString verifies the public string form for every persisted tx
// status value.
func TestTxStatusString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status TxStatus
		want   string
	}{
		{name: "pending", status: TxStatusPending, want: "pending"},
		{name: "published", status: TxStatusPublished, want: "published"},
		{name: "replaced", status: TxStatusReplaced, want: "replaced"},
		{name: "failed", status: TxStatusFailed, want: "failed"},
		{name: "orphaned", status: TxStatusOrphaned, want: "orphaned"},
		{name: "unknown", status: TxStatus(99), want: "unknown"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, test.want, test.status.String())
		})
	}
}

// TestBalanceParamsValidate verifies that BalanceParams.Validate rejects
// the Account-without-Scope combination with
// ErrBalanceParamsAccountWithoutScope and accepts every other reasonable
// param shape.
func TestBalanceParamsValidate(t *testing.T) {
	t.Parallel()

	var (
		zeroAccount uint32
		zeroConfs   int32
		name        = "default"
	)

	scope := KeyScopeBIP0084

	tests := []struct {
		name    string
		params  BalanceParams
		wantErr error
	}{
		{
			name:   "zero value",
			params: BalanceParams{},
		},
		{
			name: "scope only",
			params: BalanceParams{
				WalletID: 1,
				Scope:    &scope,
			},
		},
		{
			name: "account with scope",
			params: BalanceParams{
				WalletID: 1,
				Scope:    &scope,
				Account:  &zeroAccount,
			},
		},
		{
			name: "name with scope",
			params: BalanceParams{
				WalletID: 1,
				Scope:    &scope,
				Name:     &name,
			},
		},
		{
			name: "account without scope",
			params: BalanceParams{
				WalletID: 1,
				Account:  &zeroAccount,
			},
			wantErr: ErrBalanceParamsAccountWithoutScope,
		},
		{
			name: "account without scope but with confs",
			params: BalanceParams{
				WalletID: 1,
				Account:  &zeroAccount,
				MinConfs: &zeroConfs,
			},
			wantErr: ErrBalanceParamsAccountWithoutScope,
		},
		{
			name: "name without scope",
			params: BalanceParams{
				WalletID: 1,
				Name:     &name,
			},
			wantErr: ErrBalanceParamsNameWithoutScope,
		},
		{
			name: "account and name",
			params: BalanceParams{
				WalletID: 1,
				Scope:    &scope,
				Account:  &zeroAccount,
				Name:     &name,
			},
			wantErr: ErrBalanceParamsAccountAndName,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.params.Validate()
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}
