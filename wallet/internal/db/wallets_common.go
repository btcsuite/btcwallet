package db

// nextListWalletsQuery returns a query with its pagination cursor advanced to
// the provided value.
func nextListWalletsQuery(q ListWalletsQuery, cursor uint32) ListWalletsQuery {
	q.Page = q.Page.WithAfter(cursor)

	return q
}
