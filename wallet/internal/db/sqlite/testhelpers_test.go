package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

var errDummy = errors.New("dummy")

// errorDBTX forces sqlc exec/query calls down their wrapped error paths.
type errorDBTX struct {
	execErr  error
	queryErr error
}

// ExecContext implements the sqlc DBTX interface.
func (e errorDBTX) ExecContext(context.Context, string,
	...any) (sql.Result, error) {

	return nil, e.execErr
}

// PrepareContext implements the sqlc DBTX interface.
func (e errorDBTX) PrepareContext(context.Context,
	string) (*sql.Stmt, error) {

	return nil, errDummy
}

// QueryContext implements the sqlc DBTX interface.
func (e errorDBTX) QueryContext(context.Context, string,
	...any) (*sql.Rows, error) {

	return nil, e.queryErr
}

// QueryRowContext implements the sqlc DBTX interface.
func (e errorDBTX) QueryRowContext(context.Context, string,
	...any) *sql.Row {

	return &sql.Row{}
}

// staticResult is a minimal sql.Result stub with a caller-controlled row count.
type staticResult struct {
	rows int64
}

// LastInsertId implements sql.Result.
func (r staticResult) LastInsertId() (int64, error) {
	return 0, nil
}

// RowsAffected implements sql.Result.
func (r staticResult) RowsAffected() (int64, error) {
	return r.rows, nil
}

// rowDBTX is a sqlc DBTX stub that mixes fixed exec counts with query-row
// scan failures from a temporary sqlite handle.
type rowDBTX struct {
	row      *sql.Row
	queryErr error
	execErr  error
	rows     int64
}

// ExecContext implements the sqlc DBTX interface.
func (r rowDBTX) ExecContext(context.Context, string,
	...any) (sql.Result, error) {

	if r.execErr != nil {
		return nil, r.execErr
	}

	return staticResult{rows: r.rows}, nil
}

// PrepareContext implements the sqlc DBTX interface.
func (r rowDBTX) PrepareContext(context.Context, string) (*sql.Stmt, error) {
	return nil, errDummy
}

// QueryContext implements the sqlc DBTX interface.
func (r rowDBTX) QueryContext(context.Context, string,
	...any) (*sql.Rows, error) {

	return nil, r.queryErr
}

// QueryRowContext implements the sqlc DBTX interface.
func (r rowDBTX) QueryRowContext(context.Context, string,
	...any) *sql.Row {

	if r.row != nil {
		return r.row
	}

	return &sql.Row{}
}

// newRow creates a query row backed by an in-memory sqlite database.
func newRow(t *testing.T, query string, args ...any) *sql.Row {
	t.Helper()

	dbConn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = dbConn.Close()
	})

	return dbConn.QueryRowContext(t.Context(), query, args...)
}

// testBlock builds one deterministic test block.
func testBlock(height uint32) *db.Block {
	return &db.Block{
		Hash:      chainhash.Hash{byte(height), 1, 2, 3},
		Height:    height,
		Timestamp: time.Unix(int64(height), 0),
	}
}

// testRegularMsgTx builds one simple non-coinbase transaction fixture.
func testRegularMsgTx() *wire.MsgTx {
	return &wire.MsgTx{
		Version: wire.TxVersion,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{1, 2, 3},
				Index: 0,
			},
		}},
		TxOut: []*wire.TxOut{{
			Value:    int64(btcutil.SatoshiPerBitcoin),
			PkScript: []byte{0x51},
		}},
	}
}

// testCreateTxRequest builds one prepared CreateTx request for sqlite tests.
func testCreateTxRequest(t *testing.T) db.CreateTxRequest {
	t.Helper()

	req, err := db.NewCreateTxRequest(db.CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	return req
}
