package kvdb

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// CreateDerivedAccount is not yet implemented for kvdb.
func (s *Store) CreateDerivedAccount(ctx context.Context,
	_ db.CreateDerivedAccountParams,
	_ db.AccountDerivationFunc) (*db.AccountInfo, error) {

	return nil, notImplemented(ctx, "CreateDerivedAccount")
}

// CreateImportedAccount is not yet implemented for kvdb.
func (s *Store) CreateImportedAccount(ctx context.Context,
	_ db.CreateImportedAccountParams) (*db.AccountInfo, error) {

	return nil, notImplemented(ctx, "CreateImportedAccount")
}

// GetAccount is not yet implemented for kvdb.
func (s *Store) GetAccount(ctx context.Context,
	_ db.GetAccountQuery) (*db.AccountInfo, error) {

	return nil, notImplemented(ctx, "GetAccount")
}

// ListAccounts is not yet implemented for kvdb.
func (s *Store) ListAccounts(ctx context.Context,
	_ db.ListAccountsQuery) ([]db.AccountInfo, error) {

	return nil, notImplemented(ctx, "ListAccounts")
}

// RenameAccount is not yet implemented for kvdb.
func (s *Store) RenameAccount(ctx context.Context,
	_ db.RenameAccountParams) error {

	return notImplemented(ctx, "RenameAccount")
}
