package itest

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// parityScope is the key scope the semantic parity wallet seeds its account
// under.
var parityScope = waddrmgr.KeyScopeBIP0084

// parityBlockHeight hands out distinct block-height ranges so each parity wallet
// never collides with another fixture in the shared conformance database.
var parityBlockHeight atomic.Int32

// tipRef projects a block fixture into a neutral block reference.
func tipRef(block waddrmgr.BlockStamp) db.BlockRef {
	return db.BlockRef{
		Height:    block.Height,
		Hash:      block.Hash,
		Timestamp: block.Timestamp,
	}
}

// testSemanticParity runs one fixed semantic operation vector against the
// backend's db.RuntimeStore and asserts identical observable results:
// committed facts, public typed errors, and event identities. It runs
// unchanged on KV, SQLite, and PostgreSQL, so passing on every backend proves
// observable parity. It deliberately never inspects a backend-internal journal,
// result fact, or persisted version, since those are asymmetric by design (the
// KV backend has none); only the observable contract is compared.
func testSemanticParity(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	require.NotNil(t, harness.newRuntimeStore,
		"every backend must provide a semantic runtime store")

	ctx := context.Background()

	// Seed an isolated wallet with a synced tip at height H and one account
	// whose external branch starts at index 5.
	base := 3000 + parityBlockHeight.Add(10)
	start := testBlock(base - 1)
	tip := testBlock(base)
	next1 := testBlock(base + 1)
	gap := testBlock(base + 3)

	walletID := harness.createWallet(t, "semantic-parity", start, tip)
	seedParityAccount(t, harness.newStore(walletID))

	rs := harness.newRuntimeStore(walletID)

	// The prepare-phase reads observe the seeded durable state identically.
	index, err := rs.CurrentBranchIndex(
		ctx, parityScope, 0, waddrmgr.ExternalBranch,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(5), index)

	syncedTip, err := rs.CurrentSyncedTip(ctx)
	require.NoError(t, err)
	require.Equal(t, tip.Height, syncedTip.Height)
	require.Equal(t, tip.Hash, syncedTip.Hash)

	// A fresh reservation allocates index 5 and advances to 6, with no event.
	res, err := rs.ReserveNextBranchIndex(ctx, db.ReserveBranchIndexRequest{
		Scope:         parityScope,
		Account:       0,
		Branch:        waddrmgr.ExternalBranch,
		ExpectedIndex: 5,
		OperationID:   []byte("parity-reserve"),
	})
	require.NoError(t, err)
	require.Equal(t, uint32(5), res.AllocatedIndex)
	require.Equal(t, uint32(6), res.NextIndex)
	require.False(t, res.Replayed)
	require.Empty(t, res.Events)

	// A reservation whose expected index is stale fails with the typed error
	// on every backend, without advancing the index.
	_, err = rs.ReserveNextBranchIndex(ctx, db.ReserveBranchIndexRequest{
		Scope:         parityScope,
		Account:       0,
		Branch:        waddrmgr.ExternalBranch,
		ExpectedIndex: 5,
		OperationID:   []byte("parity-reserve-stale"),
	})
	require.ErrorIs(t, err, db.ErrStaleAccountIndex)

	index, err = rs.CurrentBranchIndex(
		ctx, parityScope, 0, waddrmgr.ExternalBranch,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(6), index)

	// A fresh tip advance commits the new block, moves the synced tip, and
	// returns the committed tip plus one event whose identity is derived
	// deterministically from the committed block, identical on every backend.
	wantEvent := db.WalletTipEvent(tipRef(next1))

	advance, err := rs.AdvanceWalletTip(ctx, db.AdvanceTipRequest{
		ExpectedTip: tipRef(tip),
		NewTip:      tipRef(next1),
		OperationID: []byte("parity-tip"),
	})
	require.NoError(t, err)
	require.Equal(t, next1.Height, advance.Tip.Height)
	require.Equal(t, next1.Hash, advance.Tip.Hash)
	require.False(t, advance.Replayed)
	require.Len(t, advance.Events, 1)
	require.Equal(t, db.WalletTipAdvancedKind, advance.Events[0].Kind)
	require.Equal(t, wantEvent.ID, advance.Events[0].ID)
	require.Equal(t, wantEvent.Payload, advance.Events[0].Payload)

	syncedTip, err = rs.CurrentSyncedTip(ctx)
	require.NoError(t, err)
	require.Equal(t, next1.Height, syncedTip.Height)
	require.Equal(t, next1.Hash, syncedTip.Hash)

	// A tip advance whose expected tip is stale fails with the typed error on
	// every backend, without moving the tip.
	_, err = rs.AdvanceWalletTip(ctx, db.AdvanceTipRequest{
		ExpectedTip: tipRef(tip),
		NewTip:      tipRef(next1),
		OperationID: []byte("parity-tip-stale"),
	})
	require.ErrorIs(t, err, db.ErrStaleTip)

	// A tip advance whose new block does not extend the expected tip by exactly
	// one block fails the contiguity check before any durable work,
	// identically on every backend.
	_, err = rs.AdvanceWalletTip(ctx, db.AdvanceTipRequest{
		ExpectedTip: tipRef(next1),
		NewTip:      tipRef(gap),
		OperationID: []byte("parity-tip-gap"),
	})
	require.ErrorIs(t, err, db.ErrNonContiguousTip)

	// The synced tip is unchanged after both rejected advances.
	syncedTip, err = rs.CurrentSyncedTip(ctx)
	require.NoError(t, err)
	require.Equal(t, next1.Height, syncedTip.Height)
	require.Equal(t, next1.Hash, syncedTip.Hash)
}

// seedParityAccount seeds the parity key scope and a single account whose
// external branch starts at index 5, through the backend-neutral db.Store so it
// works on every backend.
func seedParityAccount(t *testing.T, store db.Store) {
	t.Helper()

	err := store.Update(context.Background(), func(tx db.ReadWriteTx) error {
		addr := tx.Addr()

		err := addr.PutKeyScope(waddrmgr.KeyScopeState{
			Scope:      parityScope,
			AddrSchema: waddrmgr.ScopeAddrMap[parityScope],
		})
		if err != nil {
			return err
		}

		return addr.PutAccount(waddrmgr.AccountState{
			Scope:             parityScope,
			Account:           0,
			Type:              waddrmgr.AccountDefault,
			Name:              "parity-account",
			EncryptedPubKey:   []byte{1},
			NextExternalIndex: 5,
		})
	}, func() {})
	require.NoError(t, err)
}
