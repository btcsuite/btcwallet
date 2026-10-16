package db

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// errBackend is a stand-in for a non-ErrNoRows backend failure.
var errBackend = errors.New("backend failure")

// TestMapGetAccountSecretErr verifies a missing row maps to the typed
// not-found error naming the account, while any other failure is wrapped
// unchanged.
func TestMapGetAccountSecretErr(t *testing.T) {
	t.Parallel()

	query := GetAccountSecretQuery{
		WalletID:      2,
		Scope:         KeyScope{Purpose: 84, Coin: 0},
		AccountNumber: 3,
	}

	tests := []struct {
		name    string
		err     error
		wantIs  error
		wantMsg string
	}{
		{
			name:    "missing account",
			err:     sql.ErrNoRows,
			wantIs:  ErrAccountNotFound,
			wantMsg: "account 3 in scope 84/0",
		},
		{
			// A non-ErrNoRows failure is not a missing account and
			// must stay distinguishable from one.
			name:    "other failure passes through",
			err:     fmt.Errorf("wrapped: %w", errBackend),
			wantIs:  errBackend,
			wantMsg: "get account secret",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := MapGetAccountSecretErr(test.err, query)
			require.ErrorIs(t, err, test.wantIs)
			require.ErrorContains(t, err, test.wantMsg)

			if !errors.Is(test.wantIs, ErrAccountNotFound) {
				require.NotErrorIs(t, err, ErrAccountNotFound)
			}
		})
	}
}
