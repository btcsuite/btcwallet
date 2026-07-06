package db

// ListAddressesTarget identifies which address listing a ListAddresses query
// selects.
type ListAddressesTarget int

const (
	// ListTargetByAccount lists the derived or imported-xpub child addresses
	// of the account named by the query's Scope and AccountName.
	ListTargetByAccount ListAddressesTarget = iota

	// ListTargetRawImported lists raw imported addresses, which have no
	// account identity.
	ListTargetRawImported
)

// Target validates the account-selector fields and reports which listing the
// query maps to: neither Scope nor AccountName set selects raw imported
// addresses; both set selects by-account. Setting only one is invalid. Keeping
// this rule on the query type lets both SQL backends share one definition of
// the selector invariant without a shared ops workflow.
func (q ListAddressesQuery) Target() (ListAddressesTarget, error) {
	switch {
	case q.Scope == nil && q.AccountName == nil:
		return ListTargetRawImported, nil

	case q.Scope == nil || q.AccountName == nil:
		return ListTargetByAccount, ErrInvalidListAddressesQuery

	default:
		return ListTargetByAccount, nil
	}
}

// NextListAddressesQuery returns a query with its pagination cursor advanced to
// the provided value.
func NextListAddressesQuery(q ListAddressesQuery,
	cursor uint32) ListAddressesQuery {

	q.Page.After = &cursor

	return q
}
