package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// CreateDerivedAccount creates a new derived account with the given name and
// scope. After allocating the account number, the wallet-supplied deriveFn
// callback returns the account material (extended public key, encrypted
// private key, master-key fingerprint, optional address schema) which is
// persisted together with the row. If the key scope does not exist, it is
// created with NULL public/private key fields using the address schema
// provided by the caller.
func (s *Store) CreateDerivedAccount(ctx context.Context,
	params db.CreateDerivedAccountParams,
	deriveFn db.AccountDerivationFunc) (*db.AccountInfo, error) {

	var info *db.AccountInfo

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		var err error

		info, err = db.CreateDerivedAccountWithOps(
			ctx, params, createDerivedAccountOps{q: qtx}, deriveFn,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// createDerivedAccountOps adapts PostgreSQL sqlc queries to the shared
// CreateDerivedAccount workflow.
type createDerivedAccountOps struct {
	q *sqlc.Queries
}

// WalletWatchOnly implements db.CreateDerivedAccountOps.
func (o createDerivedAccountOps) WalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	return getWalletWatchOnly(ctx, o.q, walletID)
}

// EnsureScope implements db.CreateDerivedAccountOps.
func (o createDerivedAccountOps) EnsureScope(ctx context.Context,
	walletID uint32,
	scope db.KeyScope) (int64, db.ScopeAddrSchema, error) {

	return ensureKeyScope(ctx, o.q, walletID, scope, nil)
}

// AllocateAccountNumber implements db.CreateDerivedAccountOps.
func (o createDerivedAccountOps) AllocateAccountNumber(ctx context.Context,
	scopeID int64) (int64, error) {

	return o.q.GetAndIncrementNextAccountNumber(ctx, scopeID)
}

// CreateDerivedAccount implements db.CreateDerivedAccountOps. The shared
// CreateDerivedAccountWithOps workflow validates derived before invoking
// this method, so derived must be non-nil; defensively reject anyway in
// case a future caller skips that validation.
func (o createDerivedAccountOps) CreateDerivedAccount(ctx context.Context,
	scopeID int64, accountNumber int64, name string,
	derived *db.DerivedAccountData) (db.CreateDerivedAccountRow, error) {

	if derived == nil {
		return db.CreateDerivedAccountRow{}, db.ErrNilDerivedAccountData
	}

	row, err := o.q.CreateDerivedAccount(
		ctx, sqlc.CreateDerivedAccountParams{
			ScopeID: scopeID,
			AccountNumber: sql.NullInt64{
				Int64: accountNumber,
				Valid: true,
			},
			AccountName: name,
			OriginID:    int16(db.DerivedAccount),
			PublicKey:   derived.PublicKey,
			MasterFingerprint: sql.NullInt64{
				Int64: int64(derived.MasterKeyFingerprint),
				Valid: true,
			},
		},
	)
	if err != nil {
		return db.CreateDerivedAccountRow{}, err
	}

	if len(derived.EncryptedPrivateKey) > 0 {
		err = o.q.CreateAccountSecret(
			ctx, sqlc.CreateAccountSecretParams{
				AccountID:           row.ID,
				EncryptedPrivateKey: derived.EncryptedPrivateKey,
			},
		)
		if err != nil {
			return db.CreateDerivedAccountRow{},
				fmt.Errorf("create account secret: %w", err)
		}
	}

	return db.CreateDerivedAccountRow{
		AccountNumber: row.AccountNumber,
		CreatedAt:     row.CreatedAt,
	}, nil
}
