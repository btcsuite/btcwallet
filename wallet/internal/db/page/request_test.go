package page

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// intPtrRequest returns a pointer to the given int value.
func intPtrRequest(v int) *int {
	return &v
}

// TestNewRequest verifies NewRequest validates and stores the page limit.
func TestNewRequest(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		limit     uint32
		wantLimit uint32
		wantErr   error
	}{
		{
			name:    "zero limit rejected",
			limit:   0,
			wantErr: ErrInvalidLimit,
		},
		{
			name:      "positive limit accepted",
			limit:     5,
			wantLimit: 5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req, err := NewRequest[int](tc.limit)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantLimit, req.Limit())
		})
	}
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

			req, err := NewRequest[int](tc.limit)
			require.NoError(t, err)

			result := BuildResult(req, tc.items, toCursor)

			require.Equal(t, tc.wantItems, result.Items)
			require.Equal(t, tc.wantNext, result.Next)
		})
	}
}
