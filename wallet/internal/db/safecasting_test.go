package db

import (
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

			got, err := Int64ToUint32(tc.val)
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

			got, err := Int64ToInt32(tc.val)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrCastingOverflow)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestInt64ToUint8 checks that an int64 value is converted to uint8 only
// when it is non-negative and fits within the uint8 range. It should fail
// loudly for any value outside those bounds.
func TestInt64ToUint8(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		val     int64
		want    uint8
		wantErr bool
	}{
		{
			name: "zero",
			val:  0,
			want: 0,
		},
		{
			name: "max uint8",
			val:  int64(math.MaxUint8),
			want: math.MaxUint8,
		},
		{
			name:    "negative",
			val:     -1,
			wantErr: true,
		},
		{
			name:    "too large",
			val:     int64(math.MaxUint8) + 1,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := int64ToUint8(tc.val)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrCastingOverflow)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestInt16ToUint8 checks that an int16 value is converted to uint8 only
// when it is non-negative and fits within the uint8 range. It should fail
// loudly for any value outside those bounds.
func TestInt16ToUint8(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		val     int16
		want    uint8
		wantErr bool
	}{
		{
			name: "zero",
			val:  0,
			want: 0,
		},
		{
			name: "max uint8",
			val:  int16(math.MaxUint8),
			want: math.MaxUint8,
		},
		{
			name:    "negative",
			val:     -1,
			wantErr: true,
		},
		{
			name:    "too large",
			val:     int16(math.MaxUint8) + 1,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Int16ToUint8(tc.val)
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

			got, err := Uint32ToInt32(tc.val)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrCastingOverflow)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestUint32ToInt16 checks that an uint32 value is safely converted to int16
// only when it fits within the signed 16 bit range. It should fail loudly
// for any value that exceeds those limits.
func TestUint32ToInt16(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		val     uint32
		want    int16
		wantErr bool
	}{
		{name: "zero", val: 0, want: 0},
		{name: "max int16", val: math.MaxInt16, want: math.MaxInt16},
		{
			name:    "overflow",
			val:     uint32(math.MaxInt16) + 1,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Uint32ToInt16(tc.val)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrCastingOverflow)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestInt32ToUint32 checks that non-negative signed values convert to uint32.
func TestInt32ToUint32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		val     int32
		want    uint32
		wantErr error
	}{
		{
			name: "zero",
			val:  0,
			want: 0,
		},
		{
			name: "positive",
			val:  42,
			want: 42,
		},
		{
			name:    "negative",
			val:     -1,
			wantErr: ErrCastingOverflow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Int32ToUint32(tc.val)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
