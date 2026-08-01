package db

import (
	"database/sql"
	"errors"
	"fmt"
)

// MapGetAccountSecretErr returns the typed ErrAccountNotFound when err is
// sql.ErrNoRows, describing the selector the caller queried by, and falls back
// to a wrapped form otherwise.
//
// It is shared rather than per backend because it names no generated query or
// driver type: sql.ErrNoRows is the database/sql sentinel both SQL backends
// return for a missing row. Backend-specific classification of driver error
// codes stays in each backend's ClassifyError.
func MapGetAccountSecretErr(err error, query GetAccountSecretQuery) error {
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("get account secret: %w", err)
	}

	return fmt.Errorf("account %d in scope %d/%d: %w",
		query.AccountNumber, query.Scope.Purpose, query.Scope.Coin,
		ErrAccountNotFound)
}
