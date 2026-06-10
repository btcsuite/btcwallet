package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// GetAccountSecret retrieves encrypted account-level signing material for one
// account.
func (s *Store) GetAccountSecret(ctx context.Context,
	query db.GetAccountSecretQuery) (*db.AccountSecret, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	var secret *db.AccountSecret

	err = s.execRead(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetAccountSecret(ctx, sqlc.GetAccountSecretParams{
			WalletID:      int64(query.WalletID),
			Purpose:       int64(query.Scope.Purpose),
			CoinType:      int64(query.Scope.Coin),
			AccountNumber: db.NullableUint32ToSQLInt64(query.AccountNumber),
			AccountName:   db.NullableStringToSQLNullString(query.Name),
		})
		if err != nil {
			return mapGetAccountSecretErr(err, query)
		}

		secret, err = accountSecretRowToInfo(row)

		return err
	})
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// accountSecretRowToInfo converts a SQLite account-secret row to the
// backend-independent AccountSecret shape.
func accountSecretRowToInfo(
	row sqlc.GetAccountSecretRow) (*db.AccountSecret, error) {

	walletID, err := db.Int64ToUint32(row.WalletID)
	if err != nil {
		return nil, fmt.Errorf("wallet ID: %w", err)
	}

	purpose, err := db.Int64ToUint32(row.Purpose)
	if err != nil {
		return nil, fmt.Errorf("scope purpose: %w", err)
	}

	coin, err := db.Int64ToUint32(row.CoinType)
	if err != nil {
		return nil, fmt.Errorf("scope coin type: %w", err)
	}

	var accountNumber uint32
	if row.AccountNumber.Valid {
		accountNumber, err = db.Int64ToUint32(row.AccountNumber.Int64)
		if err != nil {
			return nil, fmt.Errorf("account number: %w", err)
		}
	}

	var masterFingerprint uint32
	if row.MasterFingerprint.Valid {
		masterFingerprint, err = db.Int64ToUint32(
			row.MasterFingerprint.Int64,
		)
		if err != nil {
			return nil, fmt.Errorf("master fingerprint: %w", err)
		}
	}

	return &db.AccountSecret{
		WalletID:             walletID,
		Scope:                db.KeyScope{Purpose: purpose, Coin: coin},
		AccountNumber:        accountNumber,
		AccountName:          row.AccountName,
		PublicKey:            row.PublicKey,
		EncryptedPrivateKey:  row.EncryptedPrivateKey,
		MasterKeyFingerprint: masterFingerprint,
	}, nil
}

// mapGetAccountSecretErr returns the typed ErrAccountNotFound when err is
// sql.ErrNoRows, falling back to a wrapped form otherwise.
func mapGetAccountSecretErr(err error,
	query db.GetAccountSecretQuery) error {

	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("get account secret: %w", err)
	}

	if query.Name != nil {
		return fmt.Errorf("account %q in scope %d/%d: %w", *query.Name,
			query.Scope.Purpose, query.Scope.Coin,
			db.ErrAccountNotFound)
	}

	return fmt.Errorf("account %d in scope %d/%d: %w",
		*query.AccountNumber, query.Scope.Purpose, query.Scope.Coin,
		db.ErrAccountNotFound)
}
