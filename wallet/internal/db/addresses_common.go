package db

import (
	"errors"
	"fmt"
)

// DefaultImportedAccountName is the default account name for imported
// addresses.
const DefaultImportedAccountName = "imported"

// requireUnreservedAccountName rejects caller-initiated account operations
// that target the reserved imported alias. Raw imported addresses use this
// alias for compatibility, but SQL must not materialize it as an account row.
// Centralized here so all account paths share one definition of "reserved".
func requireUnreservedAccountName(name string) error {
	if name == DefaultImportedAccountName {
		return fmt.Errorf("%q: %w", name, ErrReservedAccountName)
	}

	return nil
}

var (
	// ErrInvalidListAddressesQuery is returned when a list-addresses request
	// mixes derived-account and raw-import selector fields.
	ErrInvalidListAddressesQuery = errors.New(
		"list addresses requires both Scope and AccountName, or neither",
	)
)
