package page

import (
	"context"
	"iter"
)

// Iter iterates through paginated results by repeatedly fetching pages and
// yielding items until exhaustion, caller break, error, or cancellation.
//
// Errors are yielded as the second value in the iterator pair. Callers must
// check the error on every iteration before using the yielded item.
func Iter[Query, Item, Cursor any](ctx context.Context, query Query,
	fetch func(context.Context, Query) (Result[Item, Cursor], error),
	withAfter func(Query, Cursor) Query) iter.Seq2[Item, error] {

	return func(yield func(Item, error) bool) {
		var zero Item

		for {
			err := ctx.Err()
			if err != nil {
				yield(zero, err)

				return
			}

			result, err := fetch(ctx, query)
			if err != nil {
				yield(zero, err)

				return
			}

			for _, item := range result.Items {
				err = ctx.Err()
				if err != nil {
					yield(zero, err)

					return
				}

				if !yield(item, nil) {
					return
				}
			}

			if result.Next == nil {
				return
			}

			query = withAfter(query, *result.Next)
		}
	}
}
