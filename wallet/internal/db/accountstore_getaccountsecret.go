package db

import "errors"

// ErrAccountSecretUnavailable is returned when a backend does not expose
// store-side account secret material through AccountStore.
var ErrAccountSecretUnavailable = errors.New("account secret unavailable")

// Validate checks whether a GetAccountSecretQuery identifies exactly one
// account selector.
func (query GetAccountSecretQuery) Validate() error {
	if query.Name == nil && query.AccountNumber == nil {
		return ErrInvalidAccountQuery
	}

	if query.Name != nil && query.AccountNumber != nil {
		return ErrInvalidAccountQuery
	}

	return nil
}
