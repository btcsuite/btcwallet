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

// EnsureKeyScopeOps is the backend adapter the shared EnsureKeyScope workflow
// uses when a backend only needs the scope ID and keeps row-shape adaptation
// local.
type EnsureKeyScopeOps interface {
	// GetKeyScope returns the existing scope row ID for the wallet/scope pair.
	GetKeyScope(ctx context.Context, walletID uint32, scope KeyScope) (int64,
		error)

	// CreateKeyScope inserts the scope row using the resolved address schema
	// and returns the created scope row ID.
	CreateKeyScope(ctx context.Context, walletID uint32, scope KeyScope,
		addrSchema ScopeAddrSchema) (int64, error)
}

// EnsureKeyScopeWithOps retrieves an existing key scope or creates it if
// missing. It returns the scope ID once available.
func EnsureKeyScopeWithOps(ctx context.Context, ops EnsureKeyScopeOps,
	walletID uint32, scope KeyScope,
	schemaOverride *ScopeAddrSchema) (int64, error) {

	scopeID, getErr := ops.GetKeyScope(ctx, walletID, scope)
	if getErr == nil {
		return scopeID, nil
	}

	if !errors.Is(getErr, sql.ErrNoRows) {
		return 0, fmt.Errorf("check key scope: %w", getErr)
	}

	var addrSchema ScopeAddrSchema
	if schemaOverride != nil {
		addrSchema = *schemaOverride
	} else {
		defaultAddrSchema, err := getAddrSchemaForScope(scope)
		if err != nil {
			return 0, err
		}

		addrSchema = defaultAddrSchema
	}

	id, err := ops.CreateKeyScope(ctx, walletID, scope, addrSchema)
	if err == nil {
		return id, nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("create key scope: %w", err)
	}

	scopeID, err = ops.GetKeyScope(ctx, walletID, scope)
	if err != nil {
		return 0, fmt.Errorf("get scope after create: %w", err)
	}

	return scopeID, nil
}
