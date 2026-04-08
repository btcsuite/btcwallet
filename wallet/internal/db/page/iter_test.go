package page

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// errTest is a sentinel error used across page package tests.
var errTest = errors.New("test error")

// intPtr returns a pointer to the given int value. It is used in tests to
// construct Result literals that require a *int cursor.
func intPtr(v int) *int {
	return &v
}

// TestIterTraversal verifies that Iter walks all pages in order.
func TestIterTraversal(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pages          [][]int
		wantItems      []int
		wantFetchCalls int
		wantQueries    []int
		wantCursors    []int
	}{
		{
			name:           "empty result",
			pages:          [][]int{{}},
			wantItems:      nil,
			wantFetchCalls: 1,
			wantQueries:    nil,
			wantCursors:    nil,
		},
		{
			name:           "single non-empty page",
			pages:          [][]int{{1, 2}},
			wantItems:      []int{1, 2},
			wantFetchCalls: 1,
			wantQueries:    nil,
			wantCursors:    nil,
		},
		{
			name:           "multi page traversal",
			pages:          [][]int{{1, 2}, {3, 4}, {5}},
			wantItems:      []int{1, 2, 3, 4, 5},
			wantFetchCalls: 3,
			wantQueries:    []int{0, 1},
			wantCursors:    []int{2, 4},
		},
		{
			name:           "exact multiple of page limit",
			pages:          [][]int{{1, 2}, {3, 4}},
			wantItems:      []int{1, 2, 3, 4},
			wantFetchCalls: 2,
			wantQueries:    []int{0},
			wantCursors:    []int{2},
		},
		{
			name:           "limit one traversal",
			pages:          [][]int{{1}, {2}, {3}},
			wantItems:      []int{1, 2, 3},
			wantFetchCalls: 3,
			wantQueries:    []int{0, 1},
			wantCursors:    []int{1, 2},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				fetchCalls  int
				nextQueries []int
				nextCursors []int
				gotItems    []int
			)

			fetchPage := func(_ context.Context,
				query int) (Result[int, int], error) {

				require.Less(t, fetchCalls, len(tc.pages))
				require.Equal(t, fetchCalls, query)

				items := tc.pages[fetchCalls]
				hasMore := fetchCalls < len(tc.pages)-1
				fetchCalls++

				result := Result[int, int]{
					Items: items,
				}
				if hasMore && len(items) > 0 {
					last := items[len(items)-1]
					result.Next = &last
				}

				return result, nil
			}

			setCursor := func(query int, cursor int) int {
				nextQueries = append(nextQueries, query)
				nextCursors = append(nextCursors, cursor)

				return query + 1
			}

			for item, err := range Iter(t.Context(), 0, fetchPage, setCursor) {
				require.NoError(t, err)

				gotItems = append(gotItems, item)
			}

			require.Equal(t, tc.wantItems, gotItems)
			require.Equal(t, tc.wantFetchCalls, fetchCalls)
			require.Equal(t, tc.wantQueries, nextQueries)
			require.Equal(t, tc.wantCursors, nextCursors)
		})
	}
}

// TestIterFetchErrorOnFirstCall verifies that Iter yields the error immediately
// when fetchPage fails on the first call, before any items are produced.
func TestIterFetchErrorOnFirstCall(t *testing.T) {
	t.Parallel()

	var (
		gotItems = make([]int, 0)
		iterErr  error
	)

	fetchPage := func(_ context.Context, _ int) (Result[int, int], error) {
		return Result[int, int]{}, errTest
	}

	setCursor := func(_ int, _ int) int {
		return 0
	}

	for item, err := range Iter(t.Context(), 0, fetchPage, setCursor) {
		if err != nil {
			iterErr = err
			break
		}

		gotItems = append(gotItems, item)
	}

	require.ErrorIs(t, iterErr, errTest)
	require.Empty(t, gotItems)
}

// TestIterFetchErrorAfterTwoPages verifies that Iter yields all items from
// successful pages before propagating an error from a later fetchPage call.
func TestIterFetchErrorAfterTwoPages(t *testing.T) {
	t.Parallel()

	var (
		fetchCalls  int
		nextCursors []int
		iterErr     error
		gotItems    = make([]int, 0, 4)
	)

	fetchPage := func(_ context.Context, _ int) (Result[int, int], error) {
		fetchCalls++
		switch fetchCalls {
		case 1:
			return Result[int, int]{
				Items: []int{1, 2},
				Next:  intPtr(2),
			}, nil
		case 2:
			return Result[int, int]{
				Items: []int{3, 4},
				Next:  intPtr(4),
			}, nil
		default:
			return Result[int, int]{}, errTest
		}
	}

	setCursor := func(query int, cursor int) int {
		nextCursors = append(nextCursors, cursor)
		return query + 1
	}

	for item, err := range Iter(t.Context(), 0, fetchPage, setCursor) {
		if err != nil {
			iterErr = err
			break
		}

		gotItems = append(gotItems, item)
	}

	require.ErrorIs(t, iterErr, errTest)
	require.Equal(t, []int{1, 2, 3, 4}, gotItems)
	require.Equal(t, 3, fetchCalls)
	require.Equal(t, []int{2, 4}, nextCursors)
}

// TestIterContextCancellation tests cancellation behavior for page iteration.
func TestIterContextCancellation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		pages            [][]int
		cancelBefore     bool
		cancelAfterItems int
		wantItems        []int
		wantFetchCalls   int
	}{
		{
			name:           "cancelled before first fetch",
			pages:          [][]int{{1, 2}},
			cancelBefore:   true,
			wantItems:      nil,
			wantFetchCalls: 0,
		},
		{
			name:             "cancelled between pages",
			pages:            [][]int{{1, 2}, {3, 4}},
			cancelAfterItems: 2,
			wantItems:        []int{1, 2},
			wantFetchCalls:   1,
		},
		{
			name:             "cancel mid-page stops before next yield",
			pages:            [][]int{{1, 2, 3}, {4, 5}},
			cancelAfterItems: 1,
			wantItems:        []int{1},
			wantFetchCalls:   1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				fetchCalls int
				gotItems   []int
				iterErr    error
			)

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			if tc.cancelBefore {
				cancel()
			}

			fetchPage := func(ctx context.Context,
				_ int) (Result[int, int], error) {

				err := ctx.Err()
				if err != nil {
					fetchCalls++
					return Result[int, int]{}, err
				}

				require.Less(t, fetchCalls, len(tc.pages))
				items := tc.pages[fetchCalls]
				fetchCalls++

				result := Result[int, int]{Items: items}
				if fetchCalls < len(tc.pages) && len(items) > 0 {
					last := items[len(items)-1]
					result.Next = &last
				}

				return result, nil
			}

			setCursor := func(query int, _ int) int {
				return query + 1
			}

			for item, err := range Iter(ctx, 0, fetchPage, setCursor) {
				if err != nil {
					iterErr = err
					break
				}

				gotItems = append(gotItems, item)
				if tc.cancelAfterItems > 0 &&
					len(gotItems) == tc.cancelAfterItems {

					cancel()
				}
			}

			require.ErrorIs(t, iterErr, context.Canceled)
			require.Equal(t, tc.wantItems, gotItems)
			require.Equal(t, tc.wantFetchCalls, fetchCalls)
		})
	}
}

// TestIterConsumerBreaks verifies that Iter stops without fetching another page
// when the consumer breaks early.
func TestIterConsumerBreaks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pages          [][]int
		stopAfter      int
		wantItems      []int
		wantFetchCalls int
		wantNextCalls  int
	}{
		{
			name:           "mid page",
			pages:          [][]int{{1, 2, 3}, {4, 5}},
			stopAfter:      2,
			wantItems:      []int{1, 2},
			wantFetchCalls: 1,
			wantNextCalls:  0,
		},
		{
			name:           "at page boundary",
			pages:          [][]int{{1, 2}, {3, 4}},
			stopAfter:      2,
			wantItems:      []int{1, 2},
			wantFetchCalls: 1,
			wantNextCalls:  0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				fetchCalls int
				nextCalls  int
				gotItems   []int
			)

			fetchPage := func(_ context.Context,
				_ int) (Result[int, int], error) {

				require.Less(t, fetchCalls, len(tc.pages))

				items := tc.pages[fetchCalls]
				hasMore := fetchCalls < len(tc.pages)-1
				fetchCalls++

				result := Result[int, int]{Items: items}
				if hasMore && len(items) > 0 {
					last := items[len(items)-1]
					result.Next = &last
				}

				return result, nil
			}

			setCursor := func(query int, cursor int) int {
				nextCalls++
				return query + cursor
			}

			for item, err := range Iter(t.Context(), 0, fetchPage, setCursor) {
				require.NoError(t, err)

				gotItems = append(gotItems, item)
				if len(gotItems) == tc.stopAfter {
					break
				}
			}

			require.Equal(t, tc.wantItems, gotItems)
			require.Equal(t, tc.wantFetchCalls, fetchCalls)
			require.Equal(t, tc.wantNextCalls, nextCalls)
		})
	}
}

// TestIterNextNilTermination verifies Iter stops when Next becomes nil without
// requiring an extra empty-page fetch.
func TestIterNextNilTermination(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pages          []Result[int, int]
		wantItems      []int
		wantFetchCalls int
		wantNextCalls  int
	}{
		{
			name: "stops on last non-empty page",
			pages: []Result[int, int]{
				{Items: []int{1, 2}},
			},
			wantItems:      []int{1, 2},
			wantFetchCalls: 1,
			wantNextCalls:  0,
		},
		{
			name: "multi-page stops at nil next",
			pages: []Result[int, int]{
				{Items: []int{1, 2}, Next: intPtr(2)},
				{Items: []int{3}},
			},
			wantItems:      []int{1, 2, 3},
			wantFetchCalls: 2,
			wantNextCalls:  1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				fetchCalls int
				nextCalls  int
				gotItems   []int
			)

			fetchPage := func(_ context.Context,
				_ int) (Result[int, int], error) {

				require.Less(t, fetchCalls, len(tc.pages))

				result := tc.pages[fetchCalls]
				fetchCalls++

				return result, nil
			}

			setCursor := func(query int, _ int) int {
				nextCalls++

				return query + 1
			}

			for item, err := range Iter(t.Context(), 0, fetchPage, setCursor) {
				require.NoError(t, err)

				gotItems = append(gotItems, item)
			}

			require.Equal(t, tc.wantItems, gotItems)
			require.Equal(t, tc.wantFetchCalls, fetchCalls)
			require.Equal(t, tc.wantNextCalls, nextCalls)
		})
	}
}
