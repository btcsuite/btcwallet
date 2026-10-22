//go:build itest

package wallet

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// TestTxGraphAdmissionPostgres exercises both concurrent admission orderings
// against the public graph result, including the reproduced MVCC interleaving.
func TestTxGraphAdmissionPostgres(t *testing.T) {
	t.Parallel()

	// Arrange, Act, and Assert live in the shared scenario so both backends
	// check the same public outcomes with their native writer boundaries.
	t.Run("child admission first", func(t *testing.T) {
		t.Parallel()

		testTxGraphAdmission(t, DBBackendPostgres, true)
	})
	t.Run("terminal transition first", func(t *testing.T) {
		t.Parallel()

		testTxGraphAdmission(t, DBBackendPostgres, false)
	})
}

// txGraphFixture keeps wire transactions as the authoritative outpoint source;
// the reader assertions derive hashes from these same immutable records.
type txGraphFixture struct {
	wallet  *Wallet
	syncer  *syncer
	address address.Address
	// funding exposes F at output 0 and independent input Q at output 1.
	funding *wtxmgr.TxRecord
	// root is A, whose output 0 funds B and whose branch W invalidates.
	root *wtxmgr.TxRecord
	// child is B, combining A:0 and Q so invalidation must restore Q.
	child *wtxmgr.TxRecord
	// winner is W, the confirmed transaction competing with A for F.
	winner *wtxmgr.TxRecord
}

// newTxGraphManager reuses normal Manager startup and disposable SQL resources.
// Keeping the mocked backend non-current prevents unrelated background scans.
func newTxGraphManager(t *testing.T, backend DBBackend) *Manager {
	t.Helper()

	// A database per scenario lets Manager own all real Wallets, with cleanup
	// ordered as Manager, Chain expectations, then container.
	source := filepath.Join(t.TempDir(), "graph.sqlite")
	if backend == DBBackendPostgres {
		container, err := postgres.Run(
			t.Context(), "postgres:18-alpine",
			postgres.WithDatabase("graph"),
			postgres.WithUsername("postgres"),
			postgres.WithPassword("postgres"),
			postgres.BasicWaitStrategies(),
		)
		testcontainers.CleanupContainer(t, container)
		require.NoError(t, err)
		source, err = container.ConnectionString(
			t.Context(), "sslmode=disable",
		)
		require.NoError(t, err)
	}

	m, err := NewManager(
		t.Context(), ManagerConfig{
			Backend:     backend,
			DataSource:  source,
			ChainParams: chainParams,
			ChainSource: createTestChain(t),
		},
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Stop()) })
	_, err = m.Start(t.Context())
	require.NoError(t, err)

	return m
}

// newTxGraphWallet uses the maintained account/address APIs so fixture credits
// and broadcast ownership resolve through the real Store rather than a fake.
func newTxGraphWallet(t *testing.T, m *Manager,
	name string) (*Wallet, address.Address) {

	t.Helper()

	// Create and unlock through Manager so subsequent ownership lookups use
	// persisted keys and the normal Wallet lifecycle.
	params := sqliteCreateParams(t)
	params.Name = name
	w, err := m.Create(params)
	require.NoError(t, err)
	require.NoError(
		t, w.Unlock(t.Context(), UnlockRequest{
			Passphrase: params.PrivatePassphrase, Timeout: -1,
		}),
	)

	// A persisted default account lets notification ingestion recognize the
	// fixture's native SegWit outputs as Wallet credits.
	_, err = w.NewAccount(
		t.Context(), NewAccountParams{
			Scope: waddrmgr.KeyScopeBIP0084,
			Name:  waddrmgr.DefaultAccountName,
		},
	)
	require.NoError(t, err)

	// Derive a real receiving address so each transaction exercises Store
	// ownership resolution rather than injecting test-only credit metadata.
	addr, err := w.NewAddress(
		t.Context(), NewAccountSelectorByName(
			waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountName,
		), false,
	)
	require.NoError(t, err)

	return w, addr.Addr
}

// txGraphRecord constructs valid raw graph edges paying the fixture address;
// consensus acceptance is supplied independently by the existing Chain mock.
func txGraphRecord(t *testing.T, addr address.Address,
	inputs []wire.OutPoint, values ...int64) *wtxmgr.TxRecord {

	t.Helper()

	// Every output pays the same owned script; its position, rather than a
	// synthetic credit ID, determines the outpoint used by the oracle.
	script, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Preserve the supplied input and output order so raw graph discovery
	// and reader assertions refer to exactly the same F, Q, and A:0 edges.
	msg := wire.NewMsgTx(2)
	for _, input := range inputs {
		msg.AddTxIn(wire.NewTxIn(&input, nil, nil))
	}

	for _, value := range values {
		msg.AddTxOut(wire.NewTxOut(value, script))
	}

	rec, err := wtxmgr.NewTxRecordFromMsgTx(msg, time.Unix(1, 0))
	require.NoError(t, err)

	return rec
}

// newTxGraphFixture records F, Q, and A through maintained notification
// ingestion. The coinbase variant makes A a rollback root instead of a
// conflict.
func newTxGraphFixture(t *testing.T, m *Manager,
	coinbase bool) txGraphFixture {

	t.Helper()

	// Funding output 0 is F, spent by A and W; output 1 is Q, spent only by B.
	// B combines A:0 with Q to expose a missed descendant's stale spend.
	w, addr := newTxGraphWallet(t, m, "graph")
	funding := txGraphRecord(
		t, addr, []wire.OutPoint{
			{Hash: chainhash.Hash{9}},
		}, 6000, 7000,
	)

	// Rollback needs a confirmed coinbase to orphan; admission tests
	// instead use an ordinary A spending F so W can replace its branch.
	rootInput := wire.OutPoint{Hash: funding.Hash}
	if coinbase {
		rootInput = wire.OutPoint{Index: ^uint32(0)}
	}

	root := txGraphRecord(t, addr, []wire.OutPoint{rootInput}, 5000)
	child := txGraphRecord(
		t, addr, []wire.OutPoint{
			{Hash: root.Hash},
			{Hash: funding.Hash, Index: 1},
		}, 11000,
	)
	winner := txGraphRecord(
		t, addr, []wire.OutPoint{
			{Hash: funding.Hash},
		}, 5500,
	)

	// Settle funding and ancestor history before barriers are installed;
	// only B and the terminal transition should participate in the race.
	s, ok := w.sync.(*syncer)
	require.True(t, ok)
	require.NoError(
		t, s.processChainUpdate(t.Context(), chain.RelevantTx{
			TxRecord: funding,
		}),
	)

	if coinbase {
		require.NoError(t, txGraphConfirm(t.Context(), s, root))
	} else {
		require.NoError(
			t, s.processChainUpdate(
				t.Context(), chain.RelevantTx{TxRecord: root},
			),
		)
	}

	return txGraphFixture{
		wallet:  w,
		syncer:  s,
		address: addr,
		funding: funding,
		root:    root,
		child:   child,
		winner:  winner,
	}
}

// txGraphConfirm enters through the maintained confirmed-notification path,
// including its normal batch, block, sync tip, and conflict effects.
func txGraphConfirm(ctx context.Context, s *syncer,
	rec *wtxmgr.TxRecord) error {

	// A filtered block notification exercises batch conflict handling and tip
	// advancement together, as the maintained chain delivery path does.
	return s.processChainUpdate(
		ctx, chain.FilteredBlockConnected{
			Block: &wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Hash: chainhash.Hash{1}, Height: 1,
				},
				Time: time.Unix(1, 0),
			},
			RelevantTxs: []*wtxmgr.TxRecord{rec},
		},
	)
}

// expectTxGraphBroadcast lets the unfixed outcome settle for the public graph
// oracle; a rejected child needs only acceptance checking, never publication.
func expectTxGraphBroadcast(t *testing.T, m *Manager,
	f txGraphFixture, admitted bool) {

	t.Helper()

	// Keep required Chain calls exact while allowing the broken baseline to
	// settle far enough for public readers to expose its corrupt graph.
	chainMock, ok := m.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	chainMock.On(
		"TestMempoolAccept", []*wire.MsgTx{&f.child.MsgTx}, float64(0),
	).Return(
		[]*btcjson.TestMempoolAcceptResult{{Allowed: true}}, nil,
	).Once()
	notify := chainMock.On("NotifyReceived", []address.Address{f.address}).
		Return(nil)

	send := chainMock.On("SendRawTransaction", &f.child.MsgTx, false).
		Return(&f.child.Hash, nil)
	if admitted {
		notify.Once()
		send.Once()
	} else {
		// Optional publication lets the pre-fix race reach the reader
		// assertions before mock call validation can stop it.
		notify.Maybe()
		send.Maybe()
	}
}

// lockTxGraphOutput supplies a real PostgreSQL barrier after graph admission:
// clearing F stalls invalidation; claiming Q stalls child ingestion at commit.
func lockTxGraphOutput(t *testing.T, ctx context.Context, raw *sql.DB,
	walletID uint32, output wire.OutPoint) *sql.Tx {

	t.Helper()

	// Own the barrier in a separate transaction so the test can release one
	// output without changing the mutation's graph snapshot or commit path.
	barrier, err := raw.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = barrier.Rollback() })

	_, err = barrier.ExecContext(
		ctx, `SELECT u.id FROM utxos AS u
		JOIN transactions AS t ON t.id = u.tx_id
		WHERE t.wallet_id = $1 AND t.tx_hash = $2 AND u.output_index = $3
		FOR UPDATE OF u`, walletID, output.Hash[:], output.Index,
	)
	require.NoError(t, err)

	return barrier
}

// startTxGraphCall joins each admitted operation even after a failed assertion;
// cancellation releases SQL waits before Manager cleanup drains its Wallets.
func startTxGraphCall(t *testing.T, cancel context.CancelFunc,
	call func() error) <-chan error {

	t.Helper()

	// Buffer completion so a failed owner assertion cannot strand the worker;
	// the separate finished signal lets cleanup join even a consumed result.
	result := make(chan error, 1)

	finished := make(chan struct{})
	go func() {
		defer close(finished)

		result <- call()
	}()

	t.Cleanup(func() {
		cancel()
		<-finished
	})

	return result
}

// waitTxGraphCall uses SQL activity only to place the barrier, never as the
// correctness oracle. The unfixed second call may finish instead of waiting.
func waitTxGraphCall(t *testing.T, ctx context.Context, raw *sql.DB,
	result <-chan error, waiting int) {

	t.Helper()

	// Accept completion on the unfixed baseline as well as SQL blocking on the
	// fix, leaving graph correctness to the later public-reader assertions.
	require.Eventually(t, func() bool {
		if len(result) != 0 {
			return true
		}

		var count int

		err := raw.QueryRowContext(
			ctx, `SELECT count(*)
			FROM pg_stat_activity WHERE datname = current_database()
			AND wait_event_type = 'Lock'`,
		).Scan(&count)

		return err == nil && count >= waiting
	}, 10*time.Second, 10*time.Millisecond)
}

// testTxGraphAdmission isolates the demonstrated contract: the winner either
// invalidates an admitted child or precedes and rejects the entire child write.
func testTxGraphAdmission(t *testing.T, backend DBBackend, childFirst bool) {
	t.Helper()

	// Arrange: F belongs to A's branch and Q is an independent owned input.
	// Real Wallet ownership and required Chain calls drive Broadcast.
	m := newTxGraphManager(t, backend)
	f := newTxGraphFixture(t, m, false)
	expectTxGraphBroadcast(t, m, f, childFirst)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	childCall := func() error {
		return f.wallet.Broadcast(ctx, &f.child.MsgTx, "")
	}
	winnerCall := func() error {
		return txGraphConfirm(ctx, f.syncer, f.winner)
	}
	firstCall, secondCall := winnerCall, childCall

	blockedOutput := wire.OutPoint{Hash: f.funding.Hash}
	if childFirst {
		firstCall, secondCall = childCall, winnerCall
		blockedOutput.Index = 1
	}

	// Act: PostgreSQL pauses the first write inside SQL, then admits the
	// second; SQLite retains its existing serialized writer order.
	var firstErr, secondErr error
	if backend == DBBackendPostgres {
		store, ok := f.wallet.store.(*pg.Store)
		require.True(t, ok)

		raw := store.RawDB()
		barrier := lockTxGraphOutput(
			t, ctx, raw, f.wallet.id, blockedOutput,
		)
		first := startTxGraphCall(t, cancel, firstCall)
		waitTxGraphCall(t, ctx, raw, first, 1)

		if childFirst {
			// Wallet-scoped locks let unrelated ingestion commit while
			// this Wallet's child is held.
			other, addr := newTxGraphWallet(t, m, "other")
			rec := txGraphRecord(
				t, addr, []wire.OutPoint{
					{Hash: chainhash.Hash{10}},
				}, 1000,
			)
			otherSyncer, ok := other.sync.(*syncer)
			require.True(t, ok)
			require.NoError(
				t, otherSyncer.processChainUpdate(
					ctx, chain.RelevantTx{TxRecord: rec},
				),
			)
		}

		second := startTxGraphCall(t, cancel, secondCall)
		waitTxGraphCall(t, ctx, raw, second, 2)
		require.NoError(t, barrier.Rollback())

		firstErr, secondErr = <-first, <-second
	} else {
		firstErr, secondErr = firstCall(), secondCall()
	}

	// Assert: Read only public outcomes after both writes settle. No active
	// child credit or independent Q spend may survive the terminal parent.
	childErr, winnerErr := secondErr, firstErr
	if childFirst {
		childErr, winnerErr = firstErr, secondErr
	}

	require.NoError(t, winnerErr)

	root, err := f.wallet.GetTx(ctx, f.root.Hash)
	require.NoError(t, err)
	require.Equal(t, TxStatusReplaced, root.Status)

	child, err := f.wallet.GetTx(ctx, f.child.Hash)
	if childFirst {
		require.NoError(t, childErr)
		require.NoError(t, err)
		require.Equal(t, TxStatusFailed, child.Status)
	} else {
		require.ErrorIs(t, childErr, db.ErrTxInputInvalidParent)
		require.ErrorIs(t, err, ErrTxNotFound)
	}

	_, err = f.wallet.GetUtxo(ctx, wire.OutPoint{Hash: f.child.Hash})
	require.ErrorIs(t, err, ErrUnknownOutput)
	_, err = f.wallet.GetUtxo(
		ctx, wire.OutPoint{Hash: f.funding.Hash, Index: 1},
	)
	require.NoError(t, err)
	_, err = f.wallet.GetUtxo(ctx, wire.OutPoint{Hash: f.funding.Hash})
	require.ErrorIs(t, err, ErrUnknownOutput)
}
