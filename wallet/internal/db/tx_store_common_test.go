package db

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// TestSerializeDeserializeMsgTx verifies that the common serialization helpers
// preserve transaction bytes across a round trip.
func TestSerializeDeserializeMsgTx(t *testing.T) {
	t.Parallel()

	// Arrange: Build one regular transaction fixture.
	tx := testRegularMsgTx()

	// Act: Serialize it and deserialize the result.
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	decoded, err := deserializeMsgTx(rawTx)
	require.NoError(t, err)

	var got bytes.Buffer

	err = decoded.Serialize(&got)
	require.NoError(t, err)

	// Assert: The decoded transaction serializes back to the same bytes.
	require.Equal(t, rawTx, got.Bytes())
}

// TestSerializeMsgTxNil verifies that serializeMsgTx rejects a missing
// transaction pointer with the public invalid-param error.
func TestSerializeMsgTxNil(t *testing.T) {
	t.Parallel()

	_, err := serializeMsgTx(nil)
	require.ErrorIs(t, err, ErrInvalidParam)
}

// TestParseTxStatus verifies that stored numeric values map back to the public
// TxStatus enum and that unknown values fail loudly.
//
// The table keeps the setup identical for every case so the loop only varies
// the input status code and the expected result.
func TestParseTxStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int64
		want    TxStatus
		wantErr error
	}{
		{name: "pending", status: 0, want: TxStatusPending},
		{name: "published", status: 1, want: TxStatusPublished},
		{name: "replaced", status: 2, want: TxStatusReplaced},
		{name: "failed", status: 3, want: TxStatusFailed},
		{name: "orphaned", status: 4, want: TxStatusOrphaned},
		{name: "invalid", status: 9, wantErr: ErrInvalidStatus},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseTxStatus(tc.status)
			require.ErrorIs(t, err, tc.wantErr)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestBuildTxInfo verifies the shared row-to-domain conversion used by both
// SQL backends when returning a valid TxInfo value.
func TestBuildTxInfo(t *testing.T) {
	t.Parallel()

	// Arrange: Build one serialized transaction and one block fixture.
	tx := testRegularMsgTx()
	hash := tx.TxHash()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	blockHash := chainhash.Hash{1, 2, 3}
	block := &Block{
		Hash:      blockHash,
		Height:    77,
		Timestamp: time.Unix(500, 0),
	}

	// Act: Convert the normalized row fields into TxInfo.
	info, err := buildTxInfo(
		hash[:], rawTx, time.Unix(600, 0).In(time.FixedZone("X", 3600)),
		block, int64(TxStatusPublished), "note",
	)
	require.NoError(t, err)

	// Assert: The resulting TxInfo preserves the expected public fields.
	require.Equal(t, hash, info.Hash)
	require.Equal(t, rawTx, info.SerializedTx)
	require.Equal(t, TxStatusPublished, info.Status)
	require.Equal(t, "note", info.Label)
	require.Equal(t, time.UTC, info.Received.Location())
	require.Equal(t, block, info.Block)
}

// TestBuildTxInfoInvalidHash verifies that buildTxInfo rejects malformed hash
// bytes.
func TestBuildTxInfoInvalidHash(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	_, err = buildTxInfo([]byte{1, 2, 3}, rawTx, time.Now(), nil,
		int64(TxStatusPending), "")
	require.Error(t, err)
}

// TestBuildTxInfoInvalidStatus verifies that buildTxInfo rejects unknown status
// codes.
func TestBuildTxInfoInvalidStatus(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()
	hash := tx.TxHash()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	_, err = buildTxInfo(hash[:], rawTx, time.Now(), nil, 9, "")
	require.ErrorIs(t, err, ErrInvalidStatus)
}

// TestValidateCreateTxParams verifies the shared CreateTx invariants that both
// SQL backends rely on before opening a write transaction.
//
// The cases vary only the CreateTx input data so the table-driven structure
// stays clear and does not need conditional setup inside the loop.
func TestValidateCreateTxParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		params       CreateTxParams
		wantErr      error
		wantParamErr error
	}{
		{
			name: "coinbase must be published",
			params: CreateTxParams{
				Tx:     testCoinbaseMsgTx(),
				Block:  testBlock(100),
				Status: TxStatusPending,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "coinbase requires block",
			params: CreateTxParams{
				Tx:     testCoinbaseMsgTx(),
				Status: TxStatusPublished,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "orphaned status rejected on create",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Status: TxStatusOrphaned,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "failed status rejected on create",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Status: TxStatusFailed,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "replaced status rejected on create",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Status: TxStatusReplaced,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "credit index out of range",
			params: CreateTxParams{
				Tx:      testRegularMsgTx(),
				Credits: map[uint32]address.Address{2: nil},
				Status:  TxStatusPending,
			},
			wantErr:      ErrIndexOutOfRange,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "duplicate input outpoint",
			params: CreateTxParams{
				Tx: &wire.MsgTx{
					Version: wire.TxVersion,
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: wire.OutPoint{
							Hash:  chainhash.Hash{1},
							Index: 0,
						},
					}, {
						PreviousOutPoint: wire.OutPoint{
							Hash:  chainhash.Hash{1},
							Index: 0,
						},
					}},
					TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
				},
				Status: TxStatusPending,
			},
			wantErr:      ErrDuplicateInputOutPoint,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "confirmed create must be published",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Block:  testBlock(101),
				Status: TxStatusPending,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "valid pending unmined transaction",
			params: CreateTxParams{
				Tx:      testRegularMsgTx(),
				Status:  TxStatusPending,
				Credits: map[uint32]address.Address{0: nil},
			},
		},
		{
			name: "valid published confirmed transaction",
			params: CreateTxParams{
				Tx:      testRegularMsgTx(),
				Block:   testBlock(102),
				Status:  TxStatusPublished,
				Credits: map[uint32]address.Address{0: nil},
			},
		},
		{
			name: "valid published coinbase facts",
			params: CreateTxParams{
				Tx:      testCoinbaseMsgTx(),
				Block:   testBlock(103),
				Status:  TxStatusPublished,
				Credits: map[uint32]address.Address{0: nil},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateCreateTxParams(tc.params)
			require.ErrorIs(t, err, tc.wantErr)
			require.ErrorIs(t, err, tc.wantParamErr)
		})
	}
}

// TestNewCreateTxRequest verifies that the shared CreateTx preparation step
// normalizes the request before either backend opens a write transaction.
func TestNewCreateTxRequest(t *testing.T) {
	t.Parallel()

	// Arrange: Build one valid request with a non-UTC received timestamp.
	params := CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(123, 0).In(time.FixedZone("X", 3600)),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
		Label:    "note",
	}

	// Act: Normalize it through newCreateTxRequest.
	req, err := newCreateTxRequest(params)
	require.NoError(t, err)

	wantRawTx, err := serializeMsgTx(params.Tx)
	require.NoError(t, err)

	// Assert: The prepared request caches the normalized transaction facts.
	require.Equal(t, params, req.params)
	require.Equal(t, params.Tx.TxHash(), req.txHash)
	require.Equal(t, wantRawTx, req.rawTx)
	require.Equal(t, time.UTC, req.received.Location())
	require.False(t, req.isCoinbase)
}

// TestCreateTxWithOpsInsert verifies that the shared CreateTx orchestration
// performs the full insert path in order for one fresh transaction row.
func TestCreateTxWithOpsInsert(t *testing.T) {
	t.Parallel()

	// Arrange: Build one prepared CreateTx request and one stub adapter.
	req := testCreateTxRequest(t)
	ops := &stubCreateTxOps{insertTxID: 11}

	// Act: Run createTxWithOps.
	err := createTxWithOps(context.Background(), req, ops)
	require.NoError(t, err)

	// Assert: The shared flow executes the expected write sequence.
	require.Equal(t,
		[]string{
			"load-existing",
			"prepare-block",
			"insert",
			"credits",
			"inputs",
		},
		ops.calls,
	)
	require.Equal(t, int64(11), ops.creditsTxID)
	require.Equal(t, int64(11), ops.inputsTxID)
	require.Equal(t, req.txHash, ops.insertReq.txHash)
}

// TestCreateTxWithOpsDuplicate verifies that the shared CreateTx helper maps an
// existing wallet-scoped tx hash to ErrTxAlreadyExists.
func TestCreateTxWithOpsDuplicate(t *testing.T) {
	t.Parallel()

	req := testCreateTxRequest(t)
	ops := &stubCreateTxOps{existing: &createTxExistingTarget{id: 4}}

	err := createTxWithOps(context.Background(), req, ops)
	require.ErrorIs(t, err, ErrTxAlreadyExists)
	require.Equal(t, []string{"load-existing"}, ops.calls)
}

// TestCreateTxWithOpsConfirmExisting verifies that the shared CreateTx flow can
// promote one existing unmined row to confirmed state instead of inserting a
// duplicate row.
func TestCreateTxWithOpsConfirmExisting(t *testing.T) {
	t.Parallel()

	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 5,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	ops := &stubCreateTxOps{existing: &createTxExistingTarget{
		id:       7,
		status:   TxStatusPending,
		hasBlock: false,
	}}

	err = createTxWithOps(context.Background(), req, ops)
	require.NoError(t, err)
	require.Equal(t, []string{"load-existing", "confirm-existing"}, ops.calls)
}

// TestCreateTxWithOpsReplaceConflicts verifies that the shared CreateTx flow
// rewrites direct conflict roots to replaced state after inserting the
// confirmed winner and before that winner claims the shared spent-parent edge.
func TestCreateTxWithOpsReplaceConflicts(t *testing.T) {
	t.Parallel()

	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 5,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	ops := &stubCreateTxOps{
		insertTxID:     11,
		conflictIDs:    []int64{5},
		conflictHashes: []chainhash.Hash{{9}},
	}

	err = createTxWithOps(context.Background(), req, ops)
	require.NoError(t, err)
	require.Equal(t, []string{
		"load-existing",
		"prepare-block",
		"insert",
		"list-conflicts",
		"list-unmined-records",
		"clear-spent-utxos",
		"mark-txns-replaced",
		"insert-replacement-edges",
		"credits",
		"inputs",
	}, ops.calls)
	require.Equal(t, int64(11), ops.replacedConflictTxID)
}

// testBlock builds a simple block fixture for CreateTx validation tests.
func testBlock(height uint32) *Block {
	return &Block{
		Hash:      chainhash.Hash{byte(height)},
		Height:    height,
		Timestamp: time.Unix(int64(height), 0),
	}
}

// testRegularMsgTx builds a minimal non-coinbase transaction fixture for the
// shared TxStore helper tests.
func testRegularMsgTx() *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}},
	})
	tx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})

	return tx
}

// testCoinbaseMsgTx builds a minimal coinbase transaction fixture.
func testCoinbaseMsgTx() *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: ^uint32(0)}})
	tx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})

	return tx
}

// stubCreateTxOps records how the shared CreateTx helper drives one backend
// adapter while letting each test control the returned transaction IDs.
type stubCreateTxOps struct {
	existing       *createTxExistingTarget
	insertTxID     int64
	conflictIDs    []int64
	conflictHashes []chainhash.Hash
	unminedTxns    []unminedTxRecord

	listConflictsErr error
	listUnminedErr   error
	clearSpentErr    error
	markFailedErr    error

	calls                []string
	insertReq            createTxRequest
	creditsTxID          int64
	inputsTxID           int64
	clearedTxIDs         []int64
	replacedTxIDs        []int64
	failedTxIDs          []int64
	replacementEdgeTxIDs []int64
	replacedConflictTxID int64
}

var _ createTxOps = (*stubCreateTxOps)(nil)

// loadExisting records that the shared flow checked whether the tx hash already
// exists and returns the test-controlled result.
func (s *stubCreateTxOps) loadExisting(_ context.Context,
	_ createTxRequest) (*createTxExistingTarget, error) {

	s.calls = append(s.calls, "load-existing")

	return s.existing, nil
}

// confirmExisting records that the shared flow promoted one existing row.
func (s *stubCreateTxOps) confirmExisting(_ context.Context,
	_ createTxRequest,
	_ createTxExistingTarget) error {

	s.calls = append(s.calls, "confirm-existing")

	return nil
}

// prepareBlock records that the shared flow validated any optional block
// assignment before insert.
func (s *stubCreateTxOps) prepareBlock(_ context.Context,
	_ createTxRequest) error {

	s.calls = append(s.calls, "prepare-block")

	return nil
}

// listConflictTxns records that the shared flow checked for direct wallet-owned
// conflicts after insert and before input claims.
func (s *stubCreateTxOps) listConflictTxns(_ context.Context,
	_ createTxRequest) ([]int64, []chainhash.Hash, error) {

	s.calls = append(s.calls, "list-conflicts")

	if s.listConflictsErr != nil {
		return nil, nil, s.listConflictsErr
	}

	return s.conflictIDs, s.conflictHashes, nil
}

// loadInvalidateTarget satisfies the embedded invalidateUnminedTxOps interface
// for the shared CreateTx orchestration tests.
func (s *stubCreateTxOps) loadInvalidateTarget(_ context.Context, _ uint32,
	_ chainhash.Hash) (invalidateUnminedTxTarget, error) {

	return invalidateUnminedTxTarget{}, nil
}

// listUnminedTxRecords satisfies the embedded invalidateUnminedTxOps interface
// for the shared CreateTx orchestration tests.
func (s *stubCreateTxOps) listUnminedTxRecords(_ context.Context,
	_ int64) ([]unminedTxRecord, error) {

	s.calls = append(s.calls, "list-unmined-records")

	if s.listUnminedErr != nil {
		return nil, s.listUnminedErr
	}

	return s.unminedTxns, nil
}

// clearSpentUtxos satisfies the embedded invalidateUnminedTxOps interface for
// the shared CreateTx orchestration tests.
func (s *stubCreateTxOps) clearSpentUtxos(_ context.Context, _ int64,
	txID int64) error {

	s.calls = append(s.calls, "clear-spent-utxos")
	s.clearedTxIDs = append(s.clearedTxIDs, txID)

	if s.clearSpentErr != nil {
		return s.clearSpentErr
	}

	return nil
}

// markTxnsFailed satisfies the embedded invalidateUnminedTxOps interface for
// the shared CreateTx orchestration tests.
func (s *stubCreateTxOps) markTxnsFailed(_ context.Context, _ int64,
	txIDs []int64) error {

	s.calls = append(s.calls, "mark-txns-failed")
	s.failedTxIDs = append([]int64(nil), txIDs...)

	if s.markFailedErr != nil {
		return s.markFailedErr
	}

	return nil
}

// markTxnsReplaced satisfies the replacement hooks CreateTx uses for direct
// conflict reconciliation.
func (s *stubCreateTxOps) markTxnsReplaced(_ context.Context, _ int64,
	txIDs []int64) error {

	s.calls = append(s.calls, "mark-txns-replaced")
	s.replacedTxIDs = append([]int64(nil), txIDs...)

	return nil
}

// insertReplacementEdges satisfies the replacement hooks CreateTx uses for
// direct conflict reconciliation.
func (s *stubCreateTxOps) insertReplacementEdges(_ context.Context, _ int64,
	replacedTxIDs []int64, replacementTxID int64) error {

	s.calls = append(s.calls, "insert-replacement-edges")
	s.replacementEdgeTxIDs = append([]int64(nil), replacedTxIDs...)
	s.replacedConflictTxID = replacementTxID

	return nil
}

// insert records the request that the shared flow would store as a fresh
// transaction row.
func (s *stubCreateTxOps) insert(_ context.Context,
	req createTxRequest) (int64, error) {

	s.calls = append(s.calls, "insert")
	s.insertReq = req

	return s.insertTxID, nil
}

// insertCredits records the transaction ID the shared flow used when
// reconciling wallet-owned outputs.
func (s *stubCreateTxOps) insertCredits(_ context.Context,
	_ createTxRequest, txID int64) error {

	s.calls = append(s.calls, "credits")
	s.creditsTxID = txID

	return nil
}

// markInputsSpent records the transaction ID the shared flow used when
// attaching wallet-owned spent inputs.
func (s *stubCreateTxOps) markInputsSpent(_ context.Context,
	_ createTxRequest, txID int64) error {

	s.calls = append(s.calls, "inputs")
	s.inputsTxID = txID

	return nil
}

// testCreateTxRequest builds one valid normalized CreateTx request for the
// shared CreateTx orchestration tests.
func testCreateTxRequest(t *testing.T) createTxRequest {
	t.Helper()

	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 5,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Status:   TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	return req
}

var errConflictMarkFailed = errors.New("mark failed")

// TestCollectConflictDescendants verifies that the helper derives the direct
// root IDs and descendant IDs from the current unmined graph snapshot.
func TestCollectConflictDescendants(t *testing.T) {
	t.Parallel()

	candidates := []unminedTxRecord{{
		id:   12,
		hash: chainhash.Hash{2},
		tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0},
		}}},
	}, {
		id:   13,
		hash: chainhash.Hash{3},
		tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{2}, Index: 0},
		}}},
	}}
	ops := &stubCreateTxOps{unminedTxns: candidates}

	rootIDs := []int64{11, 12}
	rootHashes := []chainhash.Hash{{1}, {2}}

	descendantIDs, err := collectConflictDescendants(
		context.Background(), 7, rootHashes, rootIDs, ops,
	)
	require.NoError(t, err)
	require.Equal(t, []int64{13}, descendantIDs)
	require.Equal(t, []string{"list-unmined-records"}, ops.calls)
}

// TestHandleTxConflicts verifies the shared replacement flow for
// one direct conflict root and its dependent descendants.
func TestHandleTxConflicts(t *testing.T) {
	t.Parallel()

	rootHash := chainhash.Hash{1}
	childHash := chainhash.Hash{2}
	grandchildHash := chainhash.Hash{3}
	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	candidates := []unminedTxRecord{{
		id:   2,
		hash: childHash,
		tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: rootHash, Index: 0},
		}}},
	}, {
		id:   3,
		hash: grandchildHash,
		tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: childHash, Index: 0},
		}}},
	}}

	ops := &stubCreateTxOps{
		conflictIDs:    []int64{1},
		conflictHashes: []chainhash.Hash{rootHash},
		unminedTxns:    candidates,
	}

	err = handleTxConflicts(t.Context(), req, 9, ops)
	require.NoError(t, err)
	require.Equal(t, []string{
		"list-conflicts",
		"list-unmined-records",
		"clear-spent-utxos",
		"mark-txns-replaced",
		"insert-replacement-edges",
		"clear-spent-utxos",
		"clear-spent-utxos",
		"mark-txns-failed",
	}, ops.calls)
	require.Equal(t, []int64{1, 2, 3}, ops.clearedTxIDs)
	require.Equal(t, []int64{1}, ops.replacedTxIDs)
	require.Equal(t, []int64{2, 3}, ops.failedTxIDs)
	require.Equal(t, []int64{1}, ops.replacementEdgeTxIDs)
	require.Equal(t, int64(9), ops.replacedConflictTxID)
}

// TestHandleTxConflictsKeepsDirectRootsReplaced verifies that a
// direct conflict root stays replaced even when it also spends another direct
// root and would otherwise appear in the descendant walk.
func TestHandleTxConflictsKeepsDirectRootsReplaced(t *testing.T) {
	t.Parallel()

	rootAHash := chainhash.Hash{1}
	rootBHash := chainhash.Hash{2}
	childHash := chainhash.Hash{3}
	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &stubCreateTxOps{
		conflictIDs:    []int64{1, 2},
		conflictHashes: []chainhash.Hash{rootAHash, rootBHash},
		unminedTxns: []unminedTxRecord{{
			id:   2,
			hash: rootBHash,
			tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: rootAHash, Index: 0},
			}}},
		}, {
			id:   3,
			hash: childHash,
			tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: rootBHash, Index: 0},
			}}},
		}},
	}

	err = handleTxConflicts(t.Context(), req, 9, ops)
	require.NoError(t, err)
	require.Equal(t, []string{
		"list-conflicts",
		"list-unmined-records",
		"clear-spent-utxos",
		"clear-spent-utxos",
		"mark-txns-replaced",
		"insert-replacement-edges",
		"clear-spent-utxos",
		"mark-txns-failed",
	}, ops.calls)
	require.Equal(t, []int64{1, 2, 3}, ops.clearedTxIDs)
	require.Equal(t, []int64{1, 2}, ops.replacedTxIDs)
	require.Equal(t, []int64{3}, ops.failedTxIDs)
	require.Equal(t, []int64{1, 2}, ops.replacementEdgeTxIDs)
}

// TestHandleTxConflictsNoDescendants verifies that the helper
// skips the descendant-failure batch when no dependent branch exists.
func TestHandleTxConflictsNoDescendants(t *testing.T) {
	t.Parallel()

	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &stubCreateTxOps{
		conflictIDs:    []int64{1},
		conflictHashes: []chainhash.Hash{{1}},
	}

	err = handleTxConflicts(t.Context(), req, 9, ops)
	require.NoError(t, err)
	require.Equal(t, []string{
		"list-conflicts",
		"list-unmined-records",
		"clear-spent-utxos",
		"mark-txns-replaced",
		"insert-replacement-edges",
	}, ops.calls)
	require.Equal(t, []int64{1}, ops.clearedTxIDs)
	require.Equal(t, []int64{1}, ops.replacedTxIDs)
	require.Empty(t, ops.failedTxIDs)
	require.Equal(t, []int64{1}, ops.replacementEdgeTxIDs)
	require.Equal(t, int64(9), ops.replacedConflictTxID)
}

// TestHandleTxConflictsMarkFailedError verifies that the helper records
// replacement edges before returning descendant failure errors.
func TestHandleTxConflictsMarkFailedError(t *testing.T) {
	t.Parallel()

	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &stubCreateTxOps{
		conflictIDs:    []int64{1},
		conflictHashes: []chainhash.Hash{{1}},
		unminedTxns: []unminedTxRecord{{
			id:   2,
			hash: chainhash.Hash{2},
			tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{1},
					Index: 0,
				},
			}}},
		}},
		markFailedErr: errConflictMarkFailed,
	}

	err = handleTxConflicts(t.Context(), req, 9, ops)
	require.ErrorIs(t, err, errConflictMarkFailed)
	require.ErrorContains(t, err, "mark conflict descendants failed")
	require.Equal(t, []string{
		"list-conflicts",
		"list-unmined-records",
		"clear-spent-utxos",
		"mark-txns-replaced",
		"insert-replacement-edges",
		"clear-spent-utxos",
		"mark-txns-failed",
	}, ops.calls)
}

// TestUpdateTxWithOpsLabelAndState verifies that the shared UpdateTx workflow
// can apply both a label patch and a state patch in one atomic sequence.
func TestUpdateTxWithOpsLabelAndState(t *testing.T) {
	t.Parallel()

	// Arrange: Build one request with both a label patch and a state patch.
	label := "note"
	params := UpdateTxParams{
		WalletID: 5,
		Txid:     chainhash.Hash{1},
		Label:    &label,
		State: &UpdateTxState{
			Status: TxStatusPublished,
		},
	}
	ops := &stubUpdateTxOps{isCoinbase: false}

	// Act: Run updateTxWithOps against a stub backend adapter.
	err := updateTxWithOps(context.Background(), params, ops)
	require.NoError(t, err)

	// Assert: The shared flow loads, prepares, and applies both patches.
	require.Equal(t,
		[]string{"load", "prepare-state", "label", "state"},
		ops.calls,
	)
	require.Equal(t, label, ops.updatedLabel)
	require.Equal(t, TxStatusPublished, ops.updatedState.Status)
}

// TestUpdateTxWithOpsEmptyPatch verifies that the shared UpdateTx helper
// rejects requests that do not ask to mutate any field.
func TestUpdateTxWithOpsEmptyPatch(t *testing.T) {
	t.Parallel()

	params := UpdateTxParams{
		WalletID: 5,
		Txid:     chainhash.Hash{1},
	}
	ops := &stubUpdateTxOps{isCoinbase: false}

	err := updateTxWithOps(context.Background(), params, ops)
	require.ErrorIs(t, err, ErrInvalidParam)
	require.Equal(t, []string{"load"}, ops.calls)
}

// TestUpdateTxWithOpsRejectsInvalidatingStates verifies that UpdateTx rejects
// branch-affecting state transitions before any backend write begins.
func TestUpdateTxWithOpsRejectsInvalidatingStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		isCoinbase bool
		state      UpdateTxState
	}{
		{
			name: "failed rejected",
			state: UpdateTxState{
				Status: TxStatusFailed,
			},
		},
		{
			name: "replaced rejected",
			state: UpdateTxState{
				Status: TxStatusReplaced,
			},
		},
		{
			name: "orphaned rejected",
			state: UpdateTxState{
				Status: TxStatusOrphaned,
			},
		},
		{
			name:       "coinbase orphaned rejected",
			isCoinbase: true,
			state: UpdateTxState{
				Status: TxStatusOrphaned,
			},
		},
		{
			name:       "coinbase confirmed patch rejected",
			isCoinbase: true,
			state: UpdateTxState{
				Status: TxStatusPublished,
				Block:  testBlock(55),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			params := UpdateTxParams{
				WalletID: 5,
				Txid:     chainhash.Hash{1},
				State:    &test.state,
			}
			ops := &stubUpdateTxOps{isCoinbase: test.isCoinbase}

			err := updateTxWithOps(context.Background(), params, ops)
			require.ErrorIs(t, err, ErrInvalidParam)
			require.ErrorIs(t, err, ErrInvalidStatus)
			require.Equal(t, []string{"load"}, ops.calls)
		})
	}
}

// stubUpdateTxOps records how the shared UpdateTx helper drives one backend
// adapter while letting tests control the loaded metadata.
type stubUpdateTxOps struct {
	isCoinbase   bool
	calls        []string
	updatedLabel string
	updatedState UpdateTxState
}

var _ updateTxOps = (*stubUpdateTxOps)(nil)

// loadIsCoinbase records that the shared flow loaded the existing transaction
// row metadata.
func (s *stubUpdateTxOps) loadIsCoinbase(_ context.Context, _ uint32,
	_ chainhash.Hash) (bool, error) {

	s.calls = append(s.calls, "load")

	return s.isCoinbase, nil
}

// prepareState records that the shared flow validated and prepared one state
// patch before applying it.
func (s *stubUpdateTxOps) prepareState(_ context.Context,
	_ UpdateTxState) error {

	s.calls = append(s.calls, "prepare-state")

	return nil
}

// updateLabel records the label value the shared flow asked the backend to
// write.
func (s *stubUpdateTxOps) updateLabel(_ context.Context, _ uint32,
	_ chainhash.Hash, label string) error {

	s.calls = append(s.calls, "label")
	s.updatedLabel = label

	return nil
}

// updateState records the state patch the shared flow asked the backend to
// write.
func (s *stubUpdateTxOps) updateState(_ context.Context, _ uint32,
	_ chainhash.Hash, state UpdateTxState) error {

	s.calls = append(s.calls, "state")
	s.updatedState = state

	return nil
}
