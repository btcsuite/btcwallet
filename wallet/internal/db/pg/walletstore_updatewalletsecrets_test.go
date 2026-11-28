package pg

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockWalletSecretsPool verifies the public Store's transaction admission and
// ownership while the generated read queries use the existing DBTX mock.
type mockWalletSecretsPool struct {
	mock.Mock
}

var _ transactionPool = (*mockWalletSecretsPool)(nil)

// Begin supplies the configured native transaction without a second pool.
func (m *mockWalletSecretsPool) Begin(ctx context.Context) (pgx.Tx, error) {
	args := m.Called(ctx)
	tx, _ := args.Get(0).(pgx.Tx)

	return tx, args.Error(1)
}

// Close verifies that Store lifecycle releases the configured native pool.
func (m *mockWalletSecretsPool) Close() {
	m.Called()
}

// mockWalletSecretsTx reuses native DBTX forwarding for generated queries.
// Every other pgx.Tx method also rejects unconfigured calls through mock.Mock.
type mockWalletSecretsTx struct {
	mockDBTX
}

var _ pgx.Tx = (*mockWalletSecretsTx)(nil)

// Begin records any unexpected nested transaction requested by the subject.
func (m *mockWalletSecretsTx) Begin(ctx context.Context) (pgx.Tx, error) {
	args := m.Called(ctx)
	tx, _ := args.Get(0).(pgx.Tx)

	return tx, args.Error(1)
}

// Commit supplies the native reply whose ambiguity the Store must resolve.
func (m *mockWalletSecretsTx) Commit(ctx context.Context) error {
	args := m.Called(ctx)

	return args.Error(0)
}

// Rollback records deferred cleanup after native transaction completion.
func (m *mockWalletSecretsTx) Rollback(ctx context.Context) error {
	args := m.Called(ctx)

	return args.Error(0)
}

// CopyFrom records any unexpected bulk operation outside the update contract.
func (m *mockWalletSecretsTx) CopyFrom(ctx context.Context,
	table pgx.Identifier, columns []string,
	source pgx.CopyFromSource) (int64, error) {

	args := m.Called(ctx, table, columns, source)

	count, _ := args.Get(0).(int64)

	return count, args.Error(1)
}

// SendBatch records any unexpected batch instead of bypassing call
// expectations.
func (m *mockWalletSecretsTx) SendBatch(ctx context.Context,
	batch *pgx.Batch) pgx.BatchResults {

	args := m.Called(ctx, batch)
	result, _ := args.Get(0).(pgx.BatchResults)

	return result
}

// LargeObjects records access outside the wallet-secret query contract.
func (m *mockWalletSecretsTx) LargeObjects() pgx.LargeObjects {
	args := m.Called()
	objects, _ := args.Get(0).(pgx.LargeObjects)

	return objects
}

// Prepare records any unexpected manual preparation of generated native
// queries.
func (m *mockWalletSecretsTx) Prepare(ctx context.Context, name,
	query string) (*pgconn.StatementDescription, error) {

	args := m.Called(ctx, name, query)
	description, _ := args.Get(0).(*pgconn.StatementDescription)

	return description, args.Error(1)
}

// Conn records direct connection access outside the normal Store query path.
func (m *mockWalletSecretsTx) Conn() *pgx.Conn {
	args := m.Called()
	conn, _ := args.Get(0).(*pgx.Conn)

	return conn
}

// testWalletSecretsUpdate builds distinct field values so mismatch tests prove
// that every credential fact participates in exact commit verification.
func testWalletSecretsUpdate() db.UpdateWalletSecretsParams {
	return db.UpdateWalletSecretsParams{
		WalletID:                 7,
		MasterPrivParams:         []byte{1, 2},
		EncryptedCryptoPrivKey:   []byte{3, 4},
		EncryptedCryptoScriptKey: []byte{5, 6},
		EncryptedMasterHdPrivKey: []byte{7, 8},
	}
}

// newMockWalletSecretsStore binds native transaction and read paths separately
// and verifies each mock once after the Store releases its owned pool.
func newMockWalletSecretsStore(t *testing.T) (*Store,
	*mockWalletSecretsPool, *mockWalletSecretsTx, *mockDBTX) {

	t.Helper()

	pool := &mockWalletSecretsPool{}
	tx := &mockWalletSecretsTx{}
	queries := &mockDBTX{}

	pool.Test(t)
	tx.Test(t)
	queries.Test(t)
	store := &Store{pool: pool, queries: sqlc.New(queries)}
	t.Cleanup(func() {
		require.NoError(t, store.Close())
		pool.AssertExpectations(t)
		tx.AssertExpectations(t)
		queries.AssertExpectations(t)
	})

	return store, pool, tx, queries
}

// newMockWalletSecretsRow configures a single native Scan from explicit fixture
// values, reusing the same SQL nullable conversions as the backend row tests.
func newMockWalletSecretsRow(t *testing.T, values []any) *mockRow {
	t.Helper()

	row := &mockRow{}
	row.Test(t)
	row.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		// Populate only the destinations generated for this query; unexpected
		// row shapes fail rather than manufacturing a successful result.
		dest, ok := args.Get(0).([]any)
		require.True(t, ok)
		require.NoError(t, scanValues(values, dest))
	}).Return(nil).Once()
	t.Cleanup(func() { row.AssertExpectations(t) })

	return row
}

// testWalletRow returns the existing non-watch-only generated wallet shape.
func testWalletRow(t *testing.T, walletID uint32) *mockRow {
	t.Helper()

	return newMockWalletSecretsRow(t, []any{
		int64(walletID), "wallet", false, int64(1), false, []byte{1},
		nil, nil, nil, nil, nil, nil, nil, nil,
	})
}

// testWalletSecretsRow returns the persisted tuple used for exact verification.
func testWalletSecretsRow(t *testing.T,
	params db.UpdateWalletSecretsParams) *mockRow {

	t.Helper()

	return newMockWalletSecretsRow(t, []any{
		int64(params.WalletID), params.MasterPrivParams,
		params.EncryptedCryptoPrivKey, params.EncryptedCryptoScriptKey,
		params.EncryptedMasterHdPrivKey,
	})
}

// TestStoreUpdateWalletSecretsBypassesRead preserves the ordinary commit
// contract: one update, with no verification read on success or definite error.
func TestStoreUpdateWalletSecretsBypassesRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		commitErr error
	}{
		{
			name: "successful commit",
		},
		{
			name:      "definite commit failure",
			commitErr: errors.New("definite commit failure"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Require one native transaction with the wallet lookup
			// and generated update. The read handle has no expectations, so any
			// verification read on these outcomes fails immediately.
			params := testWalletSecretsUpdate()
			store, pool, tx, _ := newMockWalletSecretsStore(t)
			walletRow := testWalletRow(t, params.WalletID)

			pool.On("Begin", mock.Anything).Return(tx, nil).Once()
			pool.On("Close").Return().Once()
			tx.On("QueryRow", mock.Anything, sqlc.GetWalletByID,
				[]any{int64(params.WalletID)}).Return(walletRow).Once()
			tx.On("Exec", mock.Anything, sqlc.UpdateWalletSecrets, []any{
				params.MasterPrivParams, params.EncryptedCryptoPrivKey,
				params.EncryptedCryptoScriptKey,
				params.EncryptedMasterHdPrivKey,
				int64(params.WalletID),
			}).Return(pgconn.NewCommandTag("UPDATE 1"), nil).Once()
			tx.On("Commit", mock.Anything).Return(test.commitErr).Once()
			tx.On("Rollback", mock.Anything).Return(pgx.ErrTxClosed).Once()

			// Act: Let the public Store classify the configured commit result
			// after its real shared runtime has executed the sole mutation.
			err := store.UpdateWalletSecrets(t.Context(), params)

			// Assert: Success stays nil, definite failure retains its cause,
			// and neither outcome records ambiguity. Cleanup verifies each
			// native call and the absence of a verification read exactly once.
			require.ErrorIs(t, err, test.commitErr)
			require.Zero(t, store.StatsSnapshot().AmbiguousTxCommits)
		})
	}
}

// TestStoreUpdateWalletSecretsVerifiesAmbiguousCommit covers the actual native
// receive error: PostgreSQL may commit before pgx reports UnexpectedEOF.
func TestStoreUpdateWalletSecretsVerifiesAmbiguousCommit(t *testing.T) {
	t.Parallel()

	// Arrange: Commit the sole generated update with pgx's actual lost reply
	// error, then expose the matching durable tuple through one Store read.
	// Strict native expectations prohibit a second transaction or mutation.
	params := testWalletSecretsUpdate()
	store, pool, tx, queries := newMockWalletSecretsStore(t)
	walletRow := testWalletRow(t, params.WalletID)
	secretsRow := testWalletSecretsRow(t, params)

	pool.On("Begin", mock.Anything).Return(tx, nil).Once()
	pool.On("Close").Return().Once()
	tx.On("QueryRow", mock.Anything, sqlc.GetWalletByID,
		[]any{int64(params.WalletID)}).Return(walletRow).Once()
	tx.On("Exec", mock.Anything, sqlc.UpdateWalletSecrets, []any{
		params.MasterPrivParams, params.EncryptedCryptoPrivKey,
		params.EncryptedCryptoScriptKey, params.EncryptedMasterHdPrivKey,
		int64(params.WalletID),
	}).Return(pgconn.NewCommandTag("UPDATE 1"), nil).Once()
	tx.On("Commit", mock.Anything).Return(io.ErrUnexpectedEOF).Once()
	tx.On("Rollback", mock.Anything).Return(pgx.ErrTxClosed).Once()
	queries.On("QueryRow", mock.Anything, sqlc.GetWalletSecrets,
		[]any{int64(params.WalletID)}).Return(secretsRow).Once()

	// Act: Run the public Store update so native classification decides whether
	// durable verification is required; the test supplies no ambiguity flag.
	err := store.UpdateWalletSecrets(t.Context(), params)

	// Assert: One matching durable observation turns the unknown outcome into
	// success without retrying the update. Cleanup verifies all call budgets.
	require.NoError(t, err)
	require.Equal(t, uint64(1), store.StatsSnapshot().AmbiguousTxCommits)
}

// mockWalletSecretsReader controls verifier-only reads while using mock.Mock
// to retain strict expectations for focused policy tests.
type mockWalletSecretsReader struct {
	mock.Mock
}

// GetWalletSecrets returns one configured durable row so verifier tests can
// cover matching, unavailable, and bounded-read outcomes independently.
func (m *mockWalletSecretsReader) GetWalletSecrets(ctx context.Context,
	walletID uint32) (*db.WalletSecrets, error) {

	args := m.Called(ctx, walletID)
	secrets, _ := args.Get(0).(*db.WalletSecrets)

	return secrets, args.Error(1)
}

// TestVerifyWalletSecretsCommitClassifiesRead verifies exact success and every
// single-field mismatch without leaking the runtime ambiguity marker.
func TestVerifyWalletSecretsCommitClassifiesRead(t *testing.T) {
	t.Parallel()

	params := testWalletSecretsUpdate()
	errTransport := errors.New("commit connection lost")
	tests := []struct {
		name      string
		persisted db.WalletSecrets
		wantNil   bool
	}{
		{
			name: "exact tuple",
			persisted: db.WalletSecrets{
				MasterPrivParams:         []byte{1, 2},
				EncryptedCryptoPrivKey:   []byte{3, 4},
				EncryptedCryptoScriptKey: []byte{5, 6},
				EncryptedMasterHdPrivKey: []byte{7, 8},
			},
			wantNil: true,
		},
		{
			name: "master parameters differ",
			persisted: db.WalletSecrets{
				MasterPrivParams:         []byte{9, 2},
				EncryptedCryptoPrivKey:   []byte{3, 4},
				EncryptedCryptoScriptKey: []byte{5, 6},
				EncryptedMasterHdPrivKey: []byte{7, 8},
			},
		},
		{
			name: "private crypto key differs",
			persisted: db.WalletSecrets{
				MasterPrivParams:         []byte{1, 2},
				EncryptedCryptoPrivKey:   []byte{9, 4},
				EncryptedCryptoScriptKey: []byte{5, 6},
				EncryptedMasterHdPrivKey: []byte{7, 8},
			},
		},
		{
			name: "script crypto key differs",
			persisted: db.WalletSecrets{
				MasterPrivParams:         []byte{1, 2},
				EncryptedCryptoPrivKey:   []byte{3, 4},
				EncryptedCryptoScriptKey: []byte{9, 6},
				EncryptedMasterHdPrivKey: []byte{7, 8},
			},
		},
		{
			name: "master HD private key differs",
			persisted: db.WalletSecrets{
				MasterPrivParams:         []byte{1, 2},
				EncryptedCryptoPrivKey:   []byte{3, 4},
				EncryptedCryptoScriptKey: []byte{5, 6},
				EncryptedMasterHdPrivKey: []byte{9, 8},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Return the case's complete data-only tuple for one
			// ambiguous result. Canceling the caller proves the follow-up
			// read receives an independent live context with a deadline.
			persisted := test.persisted
			callerCtx, cancel := context.WithCancel(t.Context())
			cancel()

			ambiguousErr := &dbruntime.AmbiguousTxCommitError{
				Err: errTransport,
			}
			reader := &mockWalletSecretsReader{}
			reader.On(
				"GetWalletSecrets", mock.MatchedBy(
					func(ctx context.Context) bool {
						deadline, bounded := ctx.Deadline()

						return ctx.Err() == nil && bounded &&
							deadline.After(time.Now())
					},
				), params.WalletID,
			).Return(&persisted, nil).Once()

			// Act: Resolve the lost commit reply from the configured
			// PostgreSQL observation without retrying the mutation.
			err := verifyWalletSecretsCommit(
				callerCtx, params, time.Second, ambiguousErr,
				reader.GetWalletSecrets,
			)

			// Assert: Only the exact tuple succeeds. Every other
			// observation is an ordinary error retaining its useful
			// causes. The explicit field checks show that every populated
			// verification buffer is destroyed before the helper returns.
			if test.wantNil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.ErrorIs(t, err, errTransport)
				require.NotErrorIs(
					t, err, dbruntime.ErrAmbiguousTxCommit,
				)
			}

			require.Equal(t, []byte{0, 0}, persisted.MasterPrivParams)
			require.Equal(
				t, []byte{0, 0}, persisted.EncryptedCryptoPrivKey,
			)
			require.Equal(
				t, []byte{0, 0}, persisted.EncryptedCryptoScriptKey,
			)
			require.Equal(
				t, []byte{0, 0}, persisted.EncryptedMasterHdPrivKey,
			)
			reader.AssertExpectations(t)
		})
	}
}

// TestVerifyWalletSecretsCommitReturnsReadError verifies an unavailable
// verification read returns both useful causes without fabricating a row.
func TestVerifyWalletSecretsCommitReturnsReadError(t *testing.T) {
	t.Parallel()

	// Arrange: Configure the reader to return the valid Store failure shape
	// of a nil row plus an error after PostgreSQL loses the commit
	// acknowledgement.
	params := testWalletSecretsUpdate()
	errTransport := errors.New("commit connection lost")
	errRead := errors.New("verification unavailable")
	ambiguousErr := &dbruntime.AmbiguousTxCommitError{Err: errTransport}
	reader := &mockWalletSecretsReader{}
	reader.On(
		"GetWalletSecrets", mock.Anything, params.WalletID,
	).Return(nil, errRead).Once()

	// Act: Ask the verifier to settle the ambiguous write from the unavailable
	// read, using the same method value that the public Store passes.
	err := verifyWalletSecretsCommit(
		t.Context(), params, time.Second, ambiguousErr,
		reader.GetWalletSecrets,
	)

	// Assert: The ordinary Store error retains both the transport and read
	// causes, omits the runtime marker, and satisfies the sole read
	// expectation.
	require.ErrorIs(t, err, errTransport)
	require.ErrorIs(t, err, errRead)
	require.NotErrorIs(t, err, dbruntime.ErrAmbiguousTxCommit)
	reader.AssertExpectations(t)
}

// TestUpdateWalletSecretsWithCommitVerificationBoundsRead verifies that a
// detached verification cannot hang after PostgreSQL loses the commit reply.
func TestUpdateWalletSecretsWithCommitVerificationBoundsRead(t *testing.T) {
	t.Parallel()

	// Arrange: Make the verification read block until its own context expires,
	// using a short injected bound so the test proves both deadline propagation
	// and termination without waiting for the production timeout.
	params := testWalletSecretsUpdate()
	errTransport := errors.New("commit connection lost")
	ambiguousErr := &dbruntime.AmbiguousTxCommitError{Err: errTransport}
	reader := &mockWalletSecretsReader{}
	reader.On(
		"GetWalletSecrets", mock.MatchedBy(func(ctx context.Context) bool {
			_, bounded := ctx.Deadline()

			return bounded
		}), params.WalletID,
	).Run(func(args mock.Arguments) {
		// Waiting on the supplied context makes this mock model an unavailable
		// read whose only shutdown path is the production verification bound.
		ctx, ok := args.Get(0).(context.Context)
		if !ok {
			t.Fatalf("verification context has type %T", args.Get(0))
		}

		<-ctx.Done()
	}).Return(nil, context.DeadlineExceeded).Once()

	// Act: Resolve with a millisecond-scale bound and measure the complete call
	// so an accidentally unbounded detached context makes the test time out.
	started := time.Now()
	err := verifyWalletSecretsCommit(
		t.Context(), params, 10*time.Millisecond, ambiguousErr,
		reader.GetWalletSecrets,
	)
	elapsed := time.Since(started)

	// Assert: The read exits from its deadline, retains the transport and
	// timeout causes as an ordinary Store error, and finishes well below a
	// defensive ceiling that tolerates normal scheduler delay.
	require.ErrorIs(t, err, errTransport)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NotErrorIs(t, err, dbruntime.ErrAmbiguousTxCommit)
	require.Less(t, elapsed, time.Second)
	reader.AssertExpectations(t)
}
