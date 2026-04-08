// Package page provides after-based pagination primitives for SQL-backed
// stores.
//
// # Core types
//
// A [Request] carries the parameters for a single page fetch: page limit,
// and an optional after that identifies where the previous page ended.
//
// A [Result] carries the items returned by one fetch together with
// [Result.Next]. Assign [Result.Next] to [Request.After] to advance to the next
// page.
//
// Stores require [Request.Limit] to be positive, fetch one extra row
// internally, and return at most the requested number of items. If the extra
// row exists, [Result.Next] is non-nil. If it does not, [Result.Next] is nil
// and the current page is the last page.
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
// Stores typically translate [Request.After] into an optional backend query
// parameter, validate [Request.Limit], fetch `limit+1` rows with a single
// ordered SQL query, and call [BuildResult] to derive [Result.Next] from the
// last returned item when another page exists.
package page
