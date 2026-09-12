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
		return fmt.Errorf("begin identity transaction: %w", err)
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

		case !namespace.IdentityReadable:
			return fmt.Errorf("%w: malformed identity table",
				db.ErrDatabaseIdentityMismatch)

		default:
			queries := sqlc.New(tx)

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
