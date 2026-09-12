package page

import "errors"

// ErrInvalidLimit is returned when a request is created with a zero page limit.
var ErrInvalidLimit = errors.New("page limit must be greater than zero")

// Request holds the parameters for a paginated list query.
//
// Use NewRequest to construct a request with a positive page limit.
type Request[Cursor any] struct {
	limit uint32

	// After is the cursor identifying where the next page starts after.
	// Nil means the request targets the first page.
	After *Cursor
}

// NewRequest returns a Request with the given positive page limit.
func NewRequest[Cursor any](limit uint32) (Request[Cursor], error) {
	if limit == 0 {
		return Request[Cursor]{}, ErrInvalidLimit
	}

	return Request[Cursor]{limit: limit}, nil
}

// Limit returns the configured page size.
func (r Request[Cursor]) Limit() uint32 {
	return r.limit
}

// BuildResult assembles a page result from a slice of items already fetched by
// the caller.
//
// BuildResult uses the request limit to trim an extra lookahead row when
// present and derives Next from the last retained item.
func BuildResult[Cursor, Item any](r Request[Cursor], items []Item,
	nextOf func(Item) Cursor) Result[Item, Cursor] {

	if len(items) == 0 {
		return Result[Item, Cursor]{Items: items}
	}

	limit := r.Limit()
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
