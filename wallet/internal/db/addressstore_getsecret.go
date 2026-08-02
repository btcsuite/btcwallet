package db

// Validate checks that the address-secret query provides exactly one address
// selector.
//
// It uses the same sentinel as GetAddressQuery.Validate: the two queries share
// the selector and the failure, so a caller that already distinguishes a
// malformed address query needs no second error to switch on.
func (query GetAddressSecretQuery) Validate() error {
	hasAddressID := query.AddressID != nil

	hasScriptPubKey := len(query.ScriptPubKey) > 0
	if hasAddressID == hasScriptPubKey {
		return ErrInvalidAddressQuery
	}

	return nil
}
