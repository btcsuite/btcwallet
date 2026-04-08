package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTxStatusString verifies the public string form for every persisted tx
// status value.
func TestTxStatusString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status TxStatus
		want   string
	}{
		{name: "pending", status: TxStatusPending, want: "pending"},
		{name: "published", status: TxStatusPublished, want: "published"},
		{name: "replaced", status: TxStatusReplaced, want: "replaced"},
		{name: "failed", status: TxStatusFailed, want: "failed"},
		{name: "orphaned", status: TxStatusOrphaned, want: "orphaned"},
		{name: "unknown", status: TxStatus(99), want: "unknown"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, test.want, test.status.String())
		})
	}
}
