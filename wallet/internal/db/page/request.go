package page

const (
	// DefaultLimit is the default number of items that can be returned to a
	// page.
	DefaultLimit = 100

	// MaxLimit is the maximum number of items that can be returned to a page.
	// Store implementations may fetch MaxLimit+1 rows internally to detect
	// whether another page exists.
	MaxLimit = 1000
)

// Request holds the parameters for a paginated list query. The zero value is
// valid and requests the first page at DefaultLimit. All With* methods
// return a modified shallow copy of the request.
//
// Fields are unexported so that callers must use the With* methods and
// accessor functions. This design preserves the normalization of limit (zero
// maps to DefaultLimit via normalizedLimit()) and ensures consistency across
// all page operations.
type Request[Cursor any] struct {
	// limit is the maximum number of items to return per page.
	limit uint32

	// after is the pagination cursor that marks where the next page
	// starts after. Nil means the first page.
	after *Cursor
}

// QueryLimit returns the number of rows the SQL query should fetch. Queries
// fetch normalizedLimit+1 rows, so BuildResult can use the extra row as a
// lookahead signal to determine whether another page exists.
func (r Request[Cursor]) QueryLimit() uint32 {
	return r.normalizedLimit() + 1
}

// WithLimit returns a copy of the request with the limit replaced. The limit is
// not validated here; normalization (zero -> DefaultLimit, over MaxLimit ->
// MaxLimit) happens in normalizedLimit() and QueryLimit(). A caller passing
// 0 or a large value will not see an error, the value will just be normalized
// later.
func (r Request[Cursor]) WithLimit(limit uint32) Request[Cursor] {
	r.limit = limit

	return r
}

// After returns the pagination after from the previous page.
// A false ok return value means the first page is being requested.
func (r Request[Cursor]) After() (Cursor, bool) {
	if r.after == nil {
		var zero Cursor

		return zero, false
	}

	return *r.after, true
}

// WithAfter returns a copy of the request with the after replaced.
// Calling this on a zero-value Request produces a request for the second page
// (the page after this after). It takes the after by value to avoid
// the caller retaining a pointer into the Request.
func (r Request[Cursor]) WithAfter(after Cursor) Request[Cursor] {
	r.after = &after

	return r
}

// BuildResult assembles a page.Result from a slice of items already fetched by
// the caller. It uses r.normalizedLimit to determine whether the query fetched
// an extra lookahead row. The toCursor function is called on the last item of
// the possibly trimmed slice.
//
// An empty slice always returns an empty result.
//
// If len(items) is greater than normalizedLimit, it trims to normalizedLimit
// and sets Next to the after of the last item in the trimmed slice.
// Otherwise, Next is nil.
func BuildResult[Cursor, Item any](r Request[Cursor], items []Item,
	nextOf func(Item) Cursor) Result[Item, Cursor] {

	if len(items) == 0 {
		return Result[Item, Cursor]{Items: items}
	}

	limit := r.normalizedLimit()
	if len(items) <= int(limit) {
		return Result[Item, Cursor]{
			Items: items,
		}
	}

	items = items[:int(limit)]
	last := items[len(items)-1]
	cursor := nextOf(last)

	return Result[Item, Cursor]{
		Items: items,
		Next:  &cursor,
	}
}

// normalizedLimit returns the normalized requested page limit for this request.
// A limit of zero returns DefaultLimit. A limit greater than MaxLimit is
// clamped to MaxLimit.
func (r Request[Cursor]) normalizedLimit() uint32 {
	switch {
	case r.limit == 0:
		return DefaultLimit

	case r.limit > MaxLimit:
		return MaxLimit

	default:
		return r.limit
	}
}
