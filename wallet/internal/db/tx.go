package db

import (
	"context"
	"database/sql"
	"fmt"
)

// execInTx executes a function within a database transaction. It handles
// the transaction lifecycle: begin, commit, and rollback on error.
//
// This is a helper function used by the public ExecuteTx methods on
// PostgresWalletDB and SQLiteWalletDB. It guarantees that the transaction
// will be either committed (on success) or rolled back (on error or panic).
func execInTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	// Rollback can be called safely even when the transaction is already
	// closed. If the transaction commits, this call does nothing. If the
	// rollback fails because of a connection issue, it is still fine since
	// the transaction was never committed, and the database remains
	// unchanged.
	defer func() {
		_ = tx.Rollback()
	}()

	err = fn(tx)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}
