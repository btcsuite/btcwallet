// Package page provides after-based pagination primitives for SQL-backed
// stores.
//
// # Core types
//
// A [Request] carries the parameters for a single page fetch: page limit,
// and an optional after that identifies where the previous page ended.
// The zero value requests the first page at [DefaultLimit].
//
// A [Result] carries the items returned by one fetch together with
// [Result.Next]. Pass *Next back to [Request.WithAfter] to advance to the
// next page.
//
// Queries fetch normalizedLimit+1 rows internally and return at most
// normalizedLimit items. If the extra row exists, [Result.Next] is non-nil.
// If it does not, [Result.Next] is nil and the current page is the last page.
//
// # Iterating
//
// [Iter] wraps a fetch function in a standard [iter.Seq2] that pages
// transparently until the list is exhausted or the caller breaks early.
// It propagates fetch errors and respects context cancellation through
// the fetchPage callback.
//
// # Store integration
//
// Stores typically translate [Request.After] into an optional backend
// query parameter, fetch [Request.QueryLimit] rows with a single ordered
// SQL query, map the raw rows to domain items, and then call
// [BuildResult] to derive [Result.Next].
package page
