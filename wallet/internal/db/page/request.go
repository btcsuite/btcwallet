package page

// Request holds the parameters for a paginated list query.
//
// Limit must be greater than zero.
type Request[Cursor any] struct {
	// Limit is the maximum number of items to return in one page.
	Limit uint32

	// After is the cursor identifying where the next page starts after. Nil
	// means the request targets the first page.
	After *Cursor
}

// BuildResult assembles a page result from a slice of items already fetched by
// the caller.
//
// The caller must pass a positive limit. BuildResult trims an extra lookahead
// row when present and derives Next from the last retained item.
func BuildResult[Cursor, Item any](items []Item, limit uint32,
	nextOf func(Item) Cursor) Result[Item, Cursor] {

	if len(items) == 0 {
		return Result[Item, Cursor]{Items: items}
	}

	if len(items) <= int(limit) {
		return Result[Item, Cursor]{Items: items}
	}

	items = items[:int(limit)]
	last := items[len(items)-1]
	cursor := nextOf(last)

	return Result[Item, Cursor]{
		Items: items,
		Next:  &cursor,
	}
}
