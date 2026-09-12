package db

// NextListWalletsQuery returns a query with its pagination cursor advanced to
// the provided value.
func NextListWalletsQuery(q ListWalletsQuery, cursor uint32) ListWalletsQuery {
	q.Page.After = &cursor

	return q
}
