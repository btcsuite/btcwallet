package db

// Validate checks that the address query provides a script pubkey selector.
func (query GetAddressQuery) Validate() error {
	if len(query.ScriptPubKey) == 0 {
		return ErrInvalidAddressQuery
	}

	return nil
}
