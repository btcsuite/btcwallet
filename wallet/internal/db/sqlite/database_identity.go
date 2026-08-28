package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	sqliteschema "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// initializeDatabaseIdentity atomically claims or verifies before migrations.
func initializeDatabaseIdentity(ctx context.Context, dbConn *sql.DB,
	identity db.DatabaseIdentity) error {

	tx, err := dbConn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin transaction: %w",
			db.ErrDatabaseIdentityMismatch, err)
	}

	// Default rollback keeps every rejected or failed startup non-mutating.
	defer func() { _ = tx.Rollback() }()

	var identityExists, populated bool

	err = tx.QueryRowContext(ctx, sqliteschema.DatabaseIdentityCatalog).Scan(
		&identityExists, &populated,
	)
	if err != nil {
		return fmt.Errorf("%w: inspect catalog: %w",
			db.ErrDatabaseIdentityMismatch, err)
	}

	queries := sqlc.New(tx)
	if !identityExists {
		// Never claim populated unmarked files as wallet-owned storage.
		if populated {
			return fmt.Errorf("%w: unmarked database is populated",
				db.ErrDatabaseIdentityMismatch)
		}

		// Create the table and singleton together, retaining the first error.
		_, err = tx.ExecContext(ctx, sqliteschema.DatabaseIdentitySchema)
		if err == nil {
			genesisHash, networkMagic, signetDigest := identity.Values()
			err = queries.InsertDatabaseIdentity(
				ctx, sqlc.InsertDatabaseIdentityParams{
					GenesisHash:           genesisHash,
					NetworkMagic:          networkMagic,
					SignetChallengeDigest: signetDigest,
				},
			)
		}
	} else {
		err = verifyDatabaseIdentity(ctx, queries, identity)
	}

	if err != nil {
		return fmt.Errorf("%w: initialize or verify identity: %w",
			db.ErrDatabaseIdentityMismatch, err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("%w: commit transaction: %w",
			db.ErrDatabaseIdentityMismatch, err)
	}

	return nil
}

// verifyDatabaseIdentity requires one stored row, then applies the shared
// NULL-aware comparison so every persisted identity field must match.
func verifyDatabaseIdentity(ctx context.Context, queries *sqlc.Queries,
	identity db.DatabaseIdentity) error {

	rowCount, err := queries.CountDatabaseIdentities(ctx)
	if err == nil && rowCount != 1 {
		err = fmt.Errorf("identity row count is %d", rowCount)
	}

	var row sqlc.GetDatabaseIdentityRow
	if err == nil {
		row, err = queries.GetDatabaseIdentity(ctx)
	}

	if err == nil && !identity.Matches(
		row.GenesisHash, row.NetworkMagic, row.SignetChallengeDigest,
	) {

		err = db.ErrDatabaseIdentityMismatch
	}

	return err
}
