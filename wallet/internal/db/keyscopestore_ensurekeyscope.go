package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// getAddrSchemaForScope returns the address schema for a given key scope or
// returns an error if the scope is not in ScopeAddrMap.
func getAddrSchemaForScope(scope KeyScope) (ScopeAddrSchema, error) {
	addrSchema, exists := ScopeAddrMap[scope]
	if !exists {
		return ScopeAddrSchema{}, fmt.Errorf("%w: scope %d/%d",
			ErrUnknownKeyScope, scope.Purpose, scope.Coin)
	}

	return addrSchema, nil
}

// EnsureKeyScope retrieves an existing key scope or creates it if missing. It
// returns the scope ID once available.
func EnsureKeyScope[Row any, GetArgs any, CreateArgs any](
	ctx context.Context, getter func(context.Context, GetArgs) (Row, error),
	getArgs GetArgs, creator func(context.Context, CreateArgs) (int64, error),
	createArgs func(ScopeAddrSchema) CreateArgs, rowToID func(Row) int64,
	rowToSchema func(Row) (ScopeAddrSchema, error),
	scope KeyScope, schemaOverride *ScopeAddrSchema,
) (int64, ScopeAddrSchema, error) {

	scopeInfo, err := getter(ctx, getArgs)
	if err == nil {
		// Fast path: when the scope already exists. Use the persisted
		// schema so callers see whatever was originally stored, not the
		// caller's override or the ScopeAddrMap default.
		persisted, err := rowToSchema(scopeInfo)
		if err != nil {
			return 0, ScopeAddrSchema{}, fmt.Errorf("scope "+
				"schema: %w", err)
		}

		return rowToID(scopeInfo), persisted, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return 0, ScopeAddrSchema{}, fmt.Errorf("check key scope: %w", err)
	}

	var addrSchema ScopeAddrSchema
	if schemaOverride != nil {
		addrSchema = *schemaOverride
	} else {
		defaultAddrSchema, err := getAddrSchemaForScope(scope)
		if err != nil {
			return 0, ScopeAddrSchema{}, err
		}

		addrSchema = defaultAddrSchema
	}

	// Slow path: needs to create the scope. The SQL uses
	// "ON CONFLICT ... DO NOTHING RETURNING id", which means:
	// - If INSERT succeeds (no conflict): returns the new row's id.
	// - If INSERT conflicts (scope exists): returns NO rows, causing sqlc to
	//   return sql.ErrNoRows.
	id, err := creator(ctx, createArgs(addrSchema))
	if err == nil {
		return id, addrSchema, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		// A real database error occurred (not a conflict).
		return 0, ScopeAddrSchema{}, fmt.Errorf("create key scope: %w", err)
	}

	// ErrNoRows means the scope was created concurrently by another process
	// (the INSERT hit DO NOTHING due to conflict). Re-fetch the scope that
	// now exists so we return the schema that actually landed in the DB,
	// not the one we tried to insert.
	scopeInfo, err = getter(ctx, getArgs)
	if err != nil {
		return 0, ScopeAddrSchema{}, fmt.Errorf("get scope after "+
			"create: %w", err)
	}

	persisted, err := rowToSchema(scopeInfo)
	if err != nil {
		return 0, ScopeAddrSchema{}, fmt.Errorf("scope schema after "+
			"create: %w", err)
	}

	return rowToID(scopeInfo), persisted, nil
}
