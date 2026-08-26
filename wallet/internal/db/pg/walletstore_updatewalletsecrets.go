package pg

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// walletSecretsCommitVerificationTimeout bounds the independent read used when
// PostgreSQL loses the database connection after sending COMMIT. The server may
// already have made the transaction durable even though the client missed its
// acknowledgement, so a short limit keeps verification through another pooled
// connection from stalling the caller.
const walletSecretsCommitVerificationTimeout = 5 * time.Second

// UpdateWalletSecrets updates the wallet secrets through one PostgreSQL
// transaction. If the database connection is lost while awaiting the COMMIT
// acknowledgement, the Store never retries the mutation; it performs one
// detached, bounded read through another pooled connection and returns success
// only when every attempted field is visible. A failed read or mismatch returns
// an ordinary Store error without exposing the runtime ambiguity marker.
func (s *Store) UpdateWalletSecrets(ctx context.Context,
	params db.UpdateWalletSecretsParams) error {

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		return db.UpdateWalletSecretsWithOps(
			ctx, params, updateWalletSecretsOps{q: qtx},
		)
	})

	return verifyWalletSecretsCommit(
		ctx, params, walletSecretsCommitVerificationTimeout, err,
		s.GetWalletSecrets,
	)
}

// verifyWalletSecretsCommit applies the binary Store contract to a completed
// PostgreSQL write. Definite outcomes pass through unchanged; a lost commit
// reply triggers one bounded read that proves success only from an exact match
// with the attempted persisted tuple.
func verifyWalletSecretsCommit(ctx context.Context,
	params db.UpdateWalletSecretsParams, verificationTimeout time.Duration,
	updateErr error, getWalletSecrets func(context.Context,
		uint32) (*db.WalletSecrets, error)) error {

	if updateErr == nil ||
		!errors.Is(updateErr, dbruntime.ErrAmbiguousTxCommit) {

		return updateErr
	}

	// Detach verification from the failed mutation context because a canceled
	// connection must not prevent another pooled connection from observing the
	// durable row. The explicit timeout keeps that independent read bounded.
	verificationCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), verificationTimeout,
	)
	defer cancel()

	persisted, readErr := getWalletSecrets(
		verificationCtx, params.WalletID,
	)
	if persisted != nil {
		// The Store owns this verification-only read, so destroy every returned
		// credential buffer after comparison rather than leaking a second copy.
		defer clearWalletSecrets(persisted)
	}

	commitErr := walletSecretsCommitError(updateErr)
	if readErr != nil {
		return errors.Join(
			commitErr,
			fmt.Errorf("verify wallet secrets after commit: %w", readErr),
		)
	}

	if walletSecretsMatchUpdate(persisted, params) {
		return nil
	}

	return fmt.Errorf("verify wallet secrets after commit: "+
		"persisted values differ: %w", commitErr)
}

// walletSecretsMatchUpdate requires all verifier and ciphertext fields to
// equal the attempted PostgreSQL update, preventing a partial or unrelated
// row from converting an uncertain commit into success.
func walletSecretsMatchUpdate(secrets *db.WalletSecrets,
	params db.UpdateWalletSecretsParams) bool {

	if secrets == nil {
		return false
	}

	return bytes.Equal(secrets.MasterPrivParams, params.MasterPrivParams) &&
		bytes.Equal(secrets.EncryptedCryptoPrivKey,
			params.EncryptedCryptoPrivKey) &&
		bytes.Equal(secrets.EncryptedCryptoScriptKey,
			params.EncryptedCryptoScriptKey) &&
		bytes.Equal(secrets.EncryptedMasterHdPrivKey,
			params.EncryptedMasterHdPrivKey)
}

// clearWalletSecrets destroys the verification read in place so resolving a
// lost commit reply does not extend the lifetime of encrypted credential data.
func clearWalletSecrets(secrets *db.WalletSecrets) {
	clear(secrets.MasterPrivParams)
	clear(secrets.EncryptedCryptoPrivKey)
	clear(secrets.EncryptedCryptoScriptKey)
	clear(secrets.EncryptedMasterHdPrivKey)
}

// walletSecretsCommitError removes the runtime ambiguity marker before the
// PostgreSQL Store returns an unresolved failure, preserving the classified
// transport cause without exposing transaction policy to db.Store callers.
func walletSecretsCommitError(err error) error {
	var ambiguousErr *dbruntime.AmbiguousTxCommitError
	if errors.As(err, &ambiguousErr) && ambiguousErr.Err != nil {
		return ambiguousErr.Err
	}

	return errors.New("postgres wallet secrets commit failed")
}

// updateWalletSecretsOps adapts PostgreSQL sqlc queries to the shared
// UpdateWalletSecrets workflow.
type updateWalletSecretsOps struct {
	q *sqlc.Queries
}

// Ensure updateWalletSecretsOps implements db.UpdateWalletSecretsOps.
var _ db.UpdateWalletSecretsOps = (*updateWalletSecretsOps)(nil)

// WalletWatchOnly implements db.UpdateWalletSecretsOps.
func (o updateWalletSecretsOps) WalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	walletRow, err := o.q.GetWalletByID(ctx, int64(walletID))
	if err == nil {
		return walletRow.IsWatchOnly, nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("wallet %d: %w", walletID,
			db.ErrWalletNotFound)
	}

	return false, err
}

// UpdateWalletSecrets implements db.UpdateWalletSecretsOps.
func (o updateWalletSecretsOps) UpdateWalletSecrets(ctx context.Context,
	params db.UpdateWalletSecretsParams) error {

	rowsAffected, err := o.q.UpdateWalletSecrets(
		ctx, sqlc.UpdateWalletSecretsParams{
			MasterPrivParams: params.MasterPrivParams,
			EncryptedCryptoPrivKey: db.NilIfEmptyBytes(
				params.EncryptedCryptoPrivKey,
			),
			EncryptedCryptoScriptKey: params.EncryptedCryptoScriptKey,
			EncryptedMasterHdPrivKey: db.NilIfEmptyBytes(
				params.EncryptedMasterHdPrivKey,
			),
			WalletID: int64(params.WalletID),
		},
	)
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("wallet secrets for wallet %d: %w",
			params.WalletID, db.ErrSecretNotFound)
	}

	return nil
}
