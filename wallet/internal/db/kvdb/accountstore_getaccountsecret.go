package kvdb

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// GetAccountSecret reports that kvdb account secrets are not exposed through
// the store-side account-secret contract.
func (s *Store) GetAccountSecret(_ context.Context,
	query db.GetAccountSecretQuery) (*db.AccountSecret, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	return nil, db.ErrAccountSecretUnavailable
}
