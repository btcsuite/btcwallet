//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestMigrationsRollbackReapply ensures that the full migration chain
// can be cleanly rolled back and then reapplied without errors.
func TestMigrationsRollbackReapply(t *testing.T) {
	t.Parallel()

	s := NewTestStore(t)

	err := s.RollbackAllMigrations()
	require.NoError(t, err, "failed to rollback all migrations")

	// Reapply all migrations to verify that the database can return to a
	// valid, fully migrated state after a complete rollback.
	err = s.ApplyAllMigrations()
	require.NoError(t, err, "failed to reapply all migrations")
}

// TestInputClaimsDowngradeRejectsAmbiguity verifies a legacy pointer cannot
// silently choose among candidates, while a unique remaining claim downgrades.
func TestInputClaimsDowngradeRejectsAmbiguity(t *testing.T) {
	t.Parallel()

	// Arrange: Retain two live attempts spending the same known wallet credit.
	store := NewTestStore(t)
	walletID, funding := newLeaseSetFixture(t, store, "downgrade-claims", 1)
	a := newRegularTx(
		funding, []*wire.TxOut{
			{Value: 6000, PkScript: []byte{0x51}},
		},
	)
	b := a.Copy()

	b.TxOut[0].Value = 5000
	for _, tx := range []*wire.MsgTx{a, b} {
		require.NoError(
			t, store.CreateTx(
				t.Context(), db.CreateTxParams{
					WalletID: walletID, Tx: tx, Received: time.Unix(1, 0),
					Status: db.TxStatusPending,
				},
			),
		)
	}

	// Act: Run the real down migration against the ambiguous live history.
	err := downgradeInputClaims(t, store.DB())

	// Assert: Refusal leaves schema and claims unchanged. Removing only B
	// allows the same down migration to restore A's unique spending input.
	require.ErrorContains(t, err, "ambiguous")

	var pointer int64

	err = store.DB().QueryRowContext(
		t.Context(),
		"SELECT spent_by_tx_id FROM utxos",
	).Scan(&pointer)
	require.ErrorContains(t, err, "spent_by_tx_id")
	require.Equal(
		t, map[int64]wire.OutPoint{0: funding[0]},
		txInputOutPoints(t, store, walletID, a.TxHash()),
	)
	require.Equal(
		t, map[int64]wire.OutPoint{0: funding[0]},
		txInputOutPoints(t, store, walletID, b.TxHash()),
	)
	require.NoError(
		t, store.DeleteTx(
			t.Context(), db.DeleteTxParams{
				WalletID: walletID, Txid: b.TxHash(),
			},
		),
	)
	require.NoError(t, downgradeInputClaims(t, store.DB()))

	var inputIndex int64

	require.NoError(
		t, store.DB().QueryRowContext(
			t.Context(),
			"SELECT spent_by_tx_id, spent_input_index FROM utxos",
		).Scan(&pointer, &inputIndex),
	)
	txID, ok := txIDByHash(t, store, walletID, a.TxHash())
	require.True(t, ok)
	require.Equal(t, txID, pointer)
	require.Zero(t, inputIndex)
	require.NoError(t, store.ApplyAllMigrations())
	require.True(t, walletUtxoSpent(t, store, walletID, funding[0]))
}
