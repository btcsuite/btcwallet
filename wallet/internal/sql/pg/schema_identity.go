package pg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/sql/schemaid"
)

// EnsureSchemaFamily verifies that the PostgreSQL database belongs to this
// schema family, applies the embedded migrations, and records the identity
// marker. It is the production entry point that wraps ApplyMigrations with the
// schema-family gate; ApplyMigrations itself remains exported for tests.
func EnsureSchemaFamily(ctx context.Context, db *sql.DB) error {
	return schemaid.Ensure(ctx, &schemaBackend{db: db})
}

// OpenAndMigrate opens a PostgreSQL database and runs the schema-family gate,
// returning a ready connection pool. The production open path should call this
// rather than Open followed by a bare ApplyMigrations.
func OpenAndMigrate(ctx context.Context, cfg Config) (*sql.DB, error) {
	db, err := Open(ctx, cfg)
	if err != nil {
		return nil, err
	}

	err = EnsureSchemaFamily(ctx, db)
	if err != nil {
		_ = db.Close()

		return nil, err
	}

	return db, nil
}

// schemaBackend adapts a PostgreSQL database handle to the schemaid.Backend
// interface using raw database/sql access.
type schemaBackend struct {
	db *sql.DB
}

// ListTables returns the names of the base tables in the public schema.
func (b *schemaBackend) ListTables(ctx context.Context) ([]string, error) {
	rows, err := b.db.QueryContext(
		ctx, "SELECT table_name FROM information_schema.tables "+
			"WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}

		tables = append(tables, name)
	}

	return tables, rows.Err()
}

// ReadMarker returns the identity marker, or nil when the identity table holds
// no row.
func (b *schemaBackend) ReadMarker(
	ctx context.Context) (*schemaid.Marker, error) {

	var marker schemaid.Marker
	err := b.db.QueryRowContext(
		ctx, "SELECT family, generation FROM "+
			schemaid.IdentityTable+" LIMIT 1",
	).Scan(&marker.Family, &marker.Generation)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil

	case err != nil:
		return nil, err

	default:
		return &marker, nil
	}
}

// ReadDirty reports whether the migration bookkeeping table records a dirty
// state.
func (b *schemaBackend) ReadDirty(ctx context.Context) (bool, error) {
	var dirty bool
	err := b.db.QueryRowContext(
		ctx, "SELECT dirty FROM schema_migrations LIMIT 1",
	).Scan(&dirty)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil

	case err != nil:
		return false, err

	default:
		return dirty, nil
	}
}

// ApplyMigrations runs the embedded PostgreSQL migration runner.
func (b *schemaBackend) ApplyMigrations() error {
	return ApplyMigrations(b.db)
}

// InsertMarker inserts the single identity row for the current family and
// generation.
func (b *schemaBackend) InsertMarker(ctx context.Context) error {
	_, err := b.db.ExecContext(
		ctx, "INSERT INTO "+schemaid.IdentityTable+
			" (id, family, generation, created_at) VALUES (1, $1, $2, $3)",
		schemaid.Family, schemaid.Generation, time.Now().Unix(),
	)

	return err
}

// Compile-time assertion that schemaBackend satisfies schemaid.Backend.
var _ schemaid.Backend = (*schemaBackend)(nil)
