package page

// Result holds one page of items returned by a paginated list query.
type Result[T any, C any] struct {
	// Items contain the results for this page. It may be empty on the last
	// page.
	Items []T

	// Next is the after to use for fetching the next page. It is nil when no
	// more pages exist.
	Next *C
}
