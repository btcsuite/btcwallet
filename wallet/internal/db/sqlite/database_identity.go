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
		return fmt.Errorf("begin identity transaction: %w", err)
	}

	// Default rollback keeps every rejected or failed startup non-mutating.
	defer func() { _ = tx.Rollback() }()

	var identityExists, populated, identityReadable bool

	err = tx.QueryRowContext(ctx, sqliteschema.DatabaseIdentityCatalog).Scan(
		&identityExists, &populated, &identityReadable,
	)
	if err != nil {
		return fmt.Errorf("inspect identity catalog: %w", err)
	}

	queries := sqlc.New(tx)
	switch {
	case !identityExists:
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
	case !identityReadable:
		return fmt.Errorf("%w: malformed identity table",
			db.ErrDatabaseIdentityMismatch)

	default:
		// Normalize the generated row for the shared singleton verifier.
		readIdentity := func(ctx context.Context) (
			[]byte, int64, []byte, error) {

			row, err := queries.GetDatabaseIdentity(ctx)

			return row.GenesisHash, row.NetworkMagic,
				row.SignetChallengeDigest, err
		}
		err = db.VerifyStoredDatabaseIdentity(
			ctx, identity, queries.CountDatabaseIdentities, readIdentity,
		)
	}

	if err != nil {
		return fmt.Errorf("initialize or verify identity: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commit identity transaction: %w", err)
	}

	return nil
}
