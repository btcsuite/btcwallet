package page

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRequestSize verifies that normalizedLimit normalizes the raw limit field.
func TestRequestSize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		size     uint32
		wantSize uint32
	}{
		{
			name:     "zero defaults to DefaultLimit",
			size:     0,
			wantSize: DefaultLimit,
		},
		{
			name:     "minimum in range",
			size:     1,
			wantSize: 1,
		},
		{
			name:     "exactly MaxLimit passes through",
			size:     MaxLimit,
			wantSize: MaxLimit,
		},
		{
			name:     "over MaxLimit clamped to MaxLimit",
			size:     uint32(MaxLimit) + 1,
			wantSize: MaxLimit,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			request := Request[uint32]{}.WithLimit(tc.size)
			require.Equal(t, tc.wantSize, request.normalizedLimit())
		})
	}
}

// TestQueryLimit verifies that QueryLimit returns normalizedLimit+1,
// including at MaxLimit.
func TestQueryLimit(t *testing.T) {
	t.Parallel()

	t.Run("uses limit plus one", func(t *testing.T) {
		t.Parallel()

		r := Request[uint32]{}.WithLimit(25)
		require.Equal(t, r.normalizedLimit()+1, r.QueryLimit())
	})

	t.Run("at max page limit", func(t *testing.T) {
		t.Parallel()

		r := Request[uint32]{}.WithLimit(MaxLimit)
		require.Equal(t, uint32(MaxLimit)+1, r.QueryLimit())
	})
}

// TestRequestChaining verifies that chaining With* calls produces the
// expected limit and after on the resulting Request.
func TestRequestChaining(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		request       Request[uint32]
		wantSize      uint32
		wantCursor    uint32
		wantHasCursor bool
	}{
		{
			name:          "after nil by default",
			request:       Request[uint32]{},
			wantSize:      DefaultLimit,
			wantHasCursor: false,
		},
		{
			name:          "after set without limit",
			request:       Request[uint32]{}.WithAfter(42),
			wantSize:      DefaultLimit,
			wantCursor:    42,
			wantHasCursor: true,
		},
		{
			name:          "limit and after set together",
			request:       Request[uint32]{}.WithLimit(50).WithAfter(99),
			wantSize:      50,
			wantCursor:    99,
			wantHasCursor: true,
		},
		{
			name:          "after overwrites previous after",
			request:       Request[uint32]{}.WithAfter(1).WithAfter(2),
			wantSize:      DefaultLimit,
			wantCursor:    2,
			wantHasCursor: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.wantSize, tc.request.normalizedLimit())

			if !tc.wantHasCursor {
				_, ok := tc.request.After()
				require.False(t, ok)

				return
			}

			after, ok := tc.request.After()
			require.True(t, ok)
			require.Equal(t, tc.wantCursor, after)
		})
	}
}

// TestRequestWithSizeImmutability verifies that WithLimit returns a new
// Request and does not modify the original.
func TestRequestWithSizeImmutability(t *testing.T) {
	t.Parallel()

	original := Request[uint32]{}.WithLimit(10).WithAfter(7)
	updated := original.WithLimit(20)

	require.Equal(t, uint32(10), original.normalizedLimit())
	originalAfter, ok := original.After()
	require.True(t, ok)
	require.Equal(t, uint32(7), originalAfter)

	require.Equal(t, uint32(20), updated.normalizedLimit())
	updatedAfter, ok := updated.After()
	require.True(t, ok)
	require.Equal(t, uint32(7), updatedAfter)
}

// TestRequestWithCursorImmutability verifies that WithAfter returns a new
// Request and does not modify the original.
func TestRequestWithCursorImmutability(t *testing.T) {
	t.Parallel()

	original := Request[uint32]{}.WithLimit(10).WithAfter(7)
	updated := original.WithAfter(9)

	require.Equal(t, uint32(10), original.normalizedLimit())
	originalAfter, ok := original.After()
	require.True(t, ok)
	require.Equal(t, uint32(7), originalAfter)

	require.Equal(t, uint32(10), updated.normalizedLimit())
	updatedAfter, ok := updated.After()
	require.True(t, ok)
	require.Equal(t, uint32(9), updatedAfter)
}

// TestRequestAfterReturnsCursorCopy verifies that mutating the local cursor
// variable returned by After does not mutate the request's internal cursor.
func TestRequestAfterReturnsCursorCopy(t *testing.T) {
	t.Parallel()

	request := Request[uint32]{}.WithAfter(7)
	after, ok := request.After()

	require.True(t, ok)
	require.Equal(t, uint32(7), after)

	after = 9
	require.Equal(t, uint32(9), after)

	originalAfter, ok := request.After()
	require.True(t, ok)
	require.Equal(t, uint32(7), originalAfter)
}

// TestBuildResult verifies BuildResult assembles the correct Result using the
// lookahead row trimming and Next logic.
func TestBuildResult(t *testing.T) {
	t.Parallel()

	toCursor := func(item int) int { return item }

	testCases := []struct {
		name      string
		items     []int
		size      uint32
		wantItems []int
		wantNext  *int
	}{
		{
			name:      "empty slice returns empty result",
			items:     []int{},
			size:      100,
			wantItems: []int{},
			wantNext:  nil,
		},
		{
			name:      "len less than limit leaves Next nil",
			items:     []int{1, 2},
			size:      5,
			wantItems: []int{1, 2},
			wantNext:  nil,
		},
		{
			name:      "len equal to limit leaves Next nil",
			items:     []int{1, 2},
			size:      2,
			wantItems: []int{1, 2},
			wantNext:  nil,
		},
		{
			name:      "len greater than limit trims and sets Next",
			items:     []int{1, 2, 3},
			size:      2,
			wantItems: []int{1, 2},
			wantNext:  func() *int { v := 2; return &v }(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := Request[int]{}.WithLimit(tc.size)
			result := BuildResult(req, tc.items, toCursor)

			require.Equal(t, tc.wantItems, result.Items)
			require.Equal(t, tc.wantNext, result.Next)
		})
	}
}
