package db

import (
	"database/sql"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestInt64ToUint32 checks that an int64 value is converted to uint32 only
// when it is non-negative and fits within the uint32 range. It should fail
// loudly for any value outside those bounds.
func TestInt64ToUint32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		val     int64
		want    uint32
		wantErr bool
	}{
		{name: "zero", val: 0, want: 0},
		{
			name: "max uint32",
			val:  int64(math.MaxUint32),
			want: math.MaxUint32,
		},
		{name: "negative", val: -1, wantErr: true},
		{
			name:    "too large",
			val:     int64(math.MaxUint32) + 1,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := int64ToUint32(tc.val)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrCastingOverflow)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestInt64ToInt32 checks that an int64 value is converted to int32 only
// when it fits within the signed 32 bit range. It should fail loudly for
// any value outside those limits.
func TestInt64ToInt32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		val     int64
		want    int32
		wantErr bool
	}{
		{
			name: "min int32",
			val:  int64(math.MinInt32),
			want: math.MinInt32,
		},
		{
			name: "max int32",
			val:  int64(math.MaxInt32),
			want: math.MaxInt32,
		},
		{
			name:    "below min",
			val:     int64(math.MinInt32) - 1,
			wantErr: true,
		},
		{
			name:    "above max",
			val:     int64(math.MaxInt32) + 1,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := int64ToInt32(tc.val)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrCastingOverflow)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestUint32ToInt32 checks that an uint32 value is safely converted to int32
// only when it fits within the signed 32 bit range. It should fail loudly
// for any value that exceeds those limits.
func TestUint32ToInt32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		val     uint32
		want    int32
		wantErr bool
	}{
		{name: "zero", val: 0, want: 0},
		{name: "max int32", val: math.MaxInt32, want: math.MaxInt32},
		{
			name:    "overflow",
			val:     uint32(math.MaxInt32) + 1,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := uint32ToInt32(tc.val)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrCastingOverflow)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestUint32ToNullInt32 checks that we respect the signed 32 bit limits
// before converting an uint32 value into sql.NullInt32. It should fail
// loudly when the value is out of range or when valid is false.
func TestUint32ToNullInt32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		val     uint32
		want    sql.NullInt32
		wantErr bool
	}{
		{
			name: "zero",
			val:  0,
			want: sql.NullInt32{Int32: 0, Valid: true},
		},
		{
			name: "max int32",
			val:  math.MaxInt32,
			want: sql.NullInt32{
				Int32: math.MaxInt32,
				Valid: true,
			},
		},
		{
			name:    "overflow",
			val:     uint32(math.MaxInt32) + 1,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := uint32ToNullInt32(tc.val)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrCastingOverflow)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestNullInt32ToUint32 checks that we convert a sql.NullInt32 to uint32
// only when the value is marked as valid and fits within the uint32 range.
// It should fail loudly for any out of range or invalid value.
func TestNullInt32ToUint32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		val     sql.NullInt32
		want    uint32
		wantErr error
	}{
		{
			name: "zero",
			val:  sql.NullInt32{Int32: 0, Valid: true},
			want: 0,
		},
		{
			name: "positive",
			val:  sql.NullInt32{Int32: 42, Valid: true},
			want: 42,
		},
		{
			name:    "negative overflow",
			val:     sql.NullInt32{Int32: -1, Valid: true},
			wantErr: ErrCastingOverflow,
		},
		{
			name:    "invalid null",
			val:     sql.NullInt32{Valid: false},
			wantErr: ErrInvalidNullInt,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := nullInt32ToUint32(tc.val)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
