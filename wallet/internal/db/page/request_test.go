package page

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// intPtrRequest returns a pointer to the given int value.
func intPtrRequest(v int) *int {
	return &v
}

// TestBuildResult verifies BuildResult assembles the correct Result using the
// lookahead row trimming and Next logic.
func TestBuildResult(t *testing.T) {
	t.Parallel()

	toCursor := func(item int) int { return item }

	testCases := []struct {
		name      string
		items     []int
		limit     uint32
		wantItems []int
		wantNext  *int
	}{
		{
			name:      "empty slice returns empty result",
			items:     []int{},
			limit:     100,
			wantItems: []int{},
			wantNext:  nil,
		},
		{
			name:      "len less than limit leaves Next nil",
			items:     []int{1, 2},
			limit:     5,
			wantItems: []int{1, 2},
			wantNext:  nil,
		},
		{
			name:      "len equal to limit leaves Next nil",
			items:     []int{1, 2},
			limit:     2,
			wantItems: []int{1, 2},
			wantNext:  nil,
		},
		{
			name:      "len greater than limit trims and sets Next",
			items:     []int{1, 2, 3},
			limit:     2,
			wantItems: []int{1, 2},
			wantNext:  intPtrRequest(2),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := BuildResult(tc.items, tc.limit, toCursor)

			require.Equal(t, tc.wantItems, result.Items)
			require.Equal(t, tc.wantNext, result.Next)
		})
	}
}
