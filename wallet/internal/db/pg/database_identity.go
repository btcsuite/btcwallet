package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	pgschema "github.com/btcsuite/btcwallet/wallet/internal/sql/pg"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
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

	namespace, err := sqlc.New(tx).InspectDatabaseIdentityNamespace(ctx)
	if err == nil {
		switch {
		case !namespace.SchemaExists:
			// Create the schema and singleton together as one atomic claim.
			_, err = tx.ExecContext(ctx, pgschema.DatabaseIdentitySchema)
			if err == nil {
				genesisHash, networkMagic, signetDigest := identity.Values()
				err = sqlc.New(tx).InsertDatabaseIdentity(
					ctx, sqlc.InsertDatabaseIdentityParams{
						GenesisHash:           genesisHash,
						NetworkMagic:          networkMagic,
						SignetChallengeDigest: signetDigest,
					},
				)
			}

		case !namespace.IdentityExists:
			// Never claim an existing unmarked namespace as wallet-owned.
			return fmt.Errorf("%w: unmarked", db.ErrDatabaseIdentityMismatch)

		default:
			err = verifyDatabaseIdentity(ctx, sqlc.New(tx), identity)
		}
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
