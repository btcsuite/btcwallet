// Package schemaid implements the schema-family identity gate that runs before
// and after the SQL migration runner. It classifies a database, rejects
// foreign, dirty, or unknown schemas without mutation, and records a stable
// family marker so a wrong binary cannot silently migrate an incompatible
// database. The dialect packages supply the raw database/sql access through the
// Backend interface; the classification and orchestration live here so both
// dialects share one tested decision.
package schemaid

import (
	"context"
	"errors"
	"fmt"
)

const (
	// Family is the stable identifier of the salvage schema lineage this
	// binary reads and writes. It is recorded in the marker row and never
	// changes for a given lineage.
	Family = "btcwallet-salvage"

	// Generation is the current salvage schema generation. It increases
	// monotonically as the runtime schema evolves so an older binary can
	// detect a newer database.
	Generation = 2

	// MinGeneration is the oldest schema generation this binary can still
	// open. Databases below it are rejected as unsupported.
	MinGeneration = 1

	// IdentityTable is the name of the table that stores the schema marker.
	IdentityTable = "btcwallet_schema_identity"

	// migrationTable is the golang-migrate bookkeeping table. It is ignored
	// when deciding whether an unmarked database is empty.
	migrationTable = "schema_migrations"
)

var (
	// ErrForeignSchemaFamily is returned when a database belongs to a
	// different schema family than this binary supports, detected either from
	// the marker family string or from a recognizably foreign table shape.
	ErrForeignSchemaFamily = errors.New(
		"database belongs to a foreign schema family",
	)

	// ErrDirtySchema is returned when a previous migration left the database
	// in a dirty, half-applied state. The gate rejects rather than repairs it.
	ErrDirtySchema = errors.New("database schema is dirty")

	// ErrNewerGeneration is returned when a database was written by a newer
	// schema generation than this binary supports.
	ErrNewerGeneration = errors.New(
		"database schema generation is newer than supported",
	)

	// ErrUnsupportedGeneration is returned when a database uses an old schema
	// generation this binary no longer supports.
	ErrUnsupportedGeneration = errors.New(
		"database schema generation is no longer supported",
	)

	// ErrUnknownSchema is returned when a non-empty, unmarked database matches
	// neither the salvage schema fingerprint nor a recognized foreign family.
	ErrUnknownSchema = errors.New("database schema shape is unknown")
)

// salvageTables is the full set of tables created by migrations 000001 through
// 000010, i.e. the pre-marker salvage schema fingerprint. An unmarked database
// must contain all of them to be backfilled with a marker.
var salvageTables = []string{
	"blocks", "wallets", "wallet_sync_states", "address_types",
	"key_scopes", "accounts", "addresses", "transactions",
	"transaction_inputs", "transaction_labels", "credits",
	"active_credit_incidences", "credit_spends", "utxo_leases",
}

// foreignTables are tables that exist only in a different, normalized btcwallet
// schema family and never in the salvage schema. Their presence identifies a
// foreign database that must be rejected without mutation.
var foreignTables = []string{"utxos", "tx_replacements"}

// Marker is the identity row recorded in a marked database.
type Marker struct {
	// Family is the schema lineage identifier recorded for this database.
	Family string

	// Generation is the schema generation recorded for this database.
	Generation int64
}

// Action describes what the gate must do after inspecting a database and
// applying migrations.
type Action int

const (
	// ActionBootstrap marks a freshly created, empty database after migrations
	// create the identity table.
	ActionBootstrap Action = iota

	// ActionBackfill marks a known pre-marker salvage database that predates
	// the identity table, after migrations add it.
	ActionBackfill

	// ActionValidateOnly indicates the database already carries a valid marker
	// and needs no further marking.
	ActionValidateOnly
)

// String returns a human-readable name for the action.
func (a Action) String() string {
	switch a {
	case ActionBootstrap:
		return "bootstrap"
	case ActionBackfill:
		return "backfill"
	case ActionValidateOnly:
		return "validate-only"
	default:
		return fmt.Sprintf("unknown(%d)", int(a))
	}
}

// Backend abstracts the dialect-specific database access the gate needs. The
// SQLite and PostgreSQL packages implement it with raw database/sql calls so
// the gate can run before and around the migration runner.
type Backend interface {
	// ListTables returns the names of the base tables in the database.
	ListTables(ctx context.Context) ([]string, error)

	// ReadMarker returns the identity marker, or nil when the identity table
	// exists but holds no row. It is only called when the identity table is
	// present.
	ReadMarker(ctx context.Context) (*Marker, error)

	// ReadDirty reports whether the migration bookkeeping table records a
	// dirty state. It is only called when that table is present.
	ReadDirty(ctx context.Context) (bool, error)

	// ApplyMigrations runs the embedded migration runner to the latest
	// version.
	ApplyMigrations() error

	// InsertMarker inserts the single identity row for the current family and
	// generation.
	InsertMarker(ctx context.Context) error
}

// Ensure runs the schema-family identity gate: it inspects the database,
// rejects a foreign, dirty, newer, unsupported, or unknown schema without
// mutation, applies migrations, and records the family marker when the database
// is bootstrapped or backfilled. It is idempotent for an already-marked
// database.
func Ensure(ctx context.Context, b Backend) error {
	tables, err := b.ListTables(ctx)
	if err != nil {
		return fmt.Errorf("list schema tables: %w", err)
	}

	var marker *Marker
	if contains(tables, IdentityTable) {
		marker, err = b.ReadMarker(ctx)
		if err != nil {
			return fmt.Errorf("read schema marker: %w", err)
		}
	}

	var dirty bool
	if contains(tables, migrationTable) {
		dirty, err = b.ReadDirty(ctx)
		if err != nil {
			return fmt.Errorf("read migration state: %w", err)
		}
	}

	// Classify before touching the database so a rejected schema is never
	// mutated.
	action, err := Evaluate(tables, marker, dirty)
	if err != nil {
		return err
	}

	if err := b.ApplyMigrations(); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	// A validated marked database already carries its marker.
	if action == ActionValidateOnly {
		return nil
	}

	if err := b.InsertMarker(ctx); err != nil {
		return fmt.Errorf("record schema marker: %w", err)
	}

	return nil
}

// Evaluate classifies a database from its table inventory, optional identity
// marker, and migration dirty flag. It returns the action the caller must take
// after applying migrations, or a typed sentinel error that rejects the
// database without mutation. It performs no database access and is the single
// tested decision shared by both dialects.
func Evaluate(tables []string, marker *Marker, dirty bool) (Action, error) {
	// A marked database is trusted to describe its own family and generation,
	// so the recorded values decide its fate.
	if marker != nil {
		switch {
		case marker.Family != Family:
			return 0, ErrForeignSchemaFamily
		case dirty:
			return 0, ErrDirtySchema
		case marker.Generation > Generation:
			return 0, ErrNewerGeneration
		case marker.Generation < MinGeneration:
			return 0, ErrUnsupportedGeneration
		default:
			return ActionValidateOnly, nil
		}
	}

	// An unmarked database is classified by its tables. The migration
	// bookkeeping table is ignored when deciding whether it is empty.
	userTables := make([]string, 0, len(tables))
	for _, name := range tables {
		if name != migrationTable {
			userTables = append(userTables, name)
		}
	}

	// An empty database is bootstrapped, unless a failed first migration left
	// it dirty.
	if len(userTables) == 0 {
		if dirty {
			return 0, ErrDirtySchema
		}

		return ActionBootstrap, nil
	}

	// A recognizably different schema family is rejected before any mutation,
	// even if it also happens to be dirty.
	if containsAny(userTables, foreignTables) {
		return 0, ErrForeignSchemaFamily
	}

	// A dirty in-progress migration is rejected rather than repaired.
	if dirty {
		return 0, ErrDirtySchema
	}

	// A non-empty database that does not carry the full pre-marker salvage
	// schema is an unknown shape.
	if !containsAll(userTables, salvageTables) {
		return 0, ErrUnknownSchema
	}

	// The database is the known pre-marker salvage schema, so the marker is
	// backfilled after migrations create the identity table.
	return ActionBackfill, nil
}

// contains reports whether name is present in items.
func contains(items []string, name string) bool {
	for _, item := range items {
		if item == name {
			return true
		}
	}

	return false
}

// containsAny reports whether any of the want names is present in have.
func containsAny(have, want []string) bool {
	set := toSet(have)
	for _, name := range want {
		if _, ok := set[name]; ok {
			return true
		}
	}

	return false
}

// containsAll reports whether every want name is present in have.
func containsAll(have, want []string) bool {
	set := toSet(have)
	for _, name := range want {
		if _, ok := set[name]; !ok {
			return false
		}
	}

	return true
}

// toSet builds a lookup set from a slice of names.
func toSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}

	return set
}
