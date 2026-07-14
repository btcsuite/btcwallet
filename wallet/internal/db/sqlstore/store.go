package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/lightningnetwork/lnd/sqldb"
	sqldbsqlc "github.com/lightningnetwork/lnd/sqldb/sqlc"
)

// defaultCoinbaseMaturity is the Bitcoin mainnet coinbase maturity used when
// the caller does not provide a network-specific value.
const defaultCoinbaseMaturity = 100

// Store owns SQL transactions for one wallet's address and transaction
// managers.
type Store struct {
	walletID         int64
	coinbaseMaturity int32
	executor         *sqldb.TransactionExecutor[Queries]
}

// New creates a manager store over an existing SQL connection. Connection
// setup, migrations, and wallet creation remain owned by the backend package.
func New(conn *sql.DB, walletID int64,
	newQueries func(*sql.Tx) Queries, maturity ...uint16) *Store {

	baseDB := &sqldb.BaseDB{
		DB:      conn,
		Queries: sqldbsqlc.New(conn),
	}

	coinbaseMaturity := int32(defaultCoinbaseMaturity)
	if len(maturity) != 0 {
		coinbaseMaturity = int32(maturity[0])
	}

	return &Store{
		walletID:         walletID,
		coinbaseMaturity: coinbaseMaturity,
		executor:         sqldb.NewTransactionExecutor(baseDB, newQueries),
	}
}

// View executes body in a read-only SQL transaction.
func (s *Store) View(ctx context.Context,
	body func(walletstore.ReadTx) error, reset func()) error {

	return s.executor.ExecTx(
		ctx, sqldb.ReadTxOpt(), func(queries Queries) error {
			return body(&readTx{
				addrStore: &addrStore{
					ctx:      ctx,
					walletID: s.walletID,
					queries:  queries,
				},
				txStore: &txStore{
					ctx:              ctx,
					walletID:         s.walletID,
					coinbaseMaturity: s.coinbaseMaturity,
					queries:          queries,
				},
			})
		}, nonNilReset(reset),
	)
}

// Update executes body in a read/write SQL transaction.
func (s *Store) Update(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	return s.executor.ExecTx(
		ctx, sqldb.WriteTxOpt(), func(queries Queries) error {
			return body(&readWriteTx{
				addrStore: &addrStore{
					ctx:      ctx,
					walletID: s.walletID,
					queries:  queries,
				},
				txStore: &txStore{
					ctx:              ctx,
					walletID:         s.walletID,
					coinbaseMaturity: s.coinbaseMaturity,
					queries:          queries,
				},
			})
		}, nonNilReset(reset),
	)
}

// nonNilReset normalizes an optional reset callback for the SQL transaction
// executor.
func nonNilReset(reset func()) func() {
	if reset != nil {
		return reset
	}

	return func() {}
}

type readTx struct {
	addrStore walletstore.AddrReadStore
	txStore   walletstore.TxReadStore
}

// Addr returns the address-manager read view.
//
//nolint:ireturn // The transaction contract returns a domain interface.
func (t *readTx) Addr() walletstore.AddrReadStore {
	return t.addrStore
}

// Tx returns the transaction-manager read view.
//
//nolint:ireturn // The transaction contract returns a domain interface.
func (t *readTx) Tx() walletstore.TxReadStore {
	return t.txStore
}

type readWriteTx struct {
	addrStore walletstore.AddrReadWriteStore
	txStore   walletstore.TxReadWriteStore
}

// Addr returns the address-manager read/write view.
//
//nolint:ireturn // The transaction contract returns a domain interface.
func (t *readWriteTx) Addr() walletstore.AddrReadWriteStore {
	return t.addrStore
}

// Tx returns the transaction-manager read/write view.
//
//nolint:ireturn // The transaction contract returns a domain interface.
func (t *readWriteTx) Tx() walletstore.TxReadWriteStore {
	return t.txStore
}

type addrStore struct {
	// The manager view is scoped to the transaction callback that created it.
	//
	//nolint:containedctx // Domain methods intentionally omit backend context.
	ctx      context.Context
	walletID int64
	queries  Queries
}

// BlockHash returns the block hash at a particular block height.
func (s *addrStore) BlockHash(height int32) (*chainhash.Hash, error) {
	row, err := s.queries.GetBlockByHeight(s.ctx, height)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrBlockNotFound,
			Description: fmt.Sprintf(
				"failed to fetch block hash for height %d", height,
			),
			Err: err,
		}
	}

	if err != nil {
		return nil, fmt.Errorf("get block %d: %w", height, err)
	}

	hash, err := chainhash.NewHash(row.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode block %d hash: %w", height, err)
	}

	return hash, nil
}

// SetSyncedTo marks the address manager as synced through the block.
func (s *addrStore) SetSyncedTo(block *waddrmgr.BlockStamp) error {
	if block == nil {
		row, err := s.queries.GetWalletStartBlock(s.ctx, s.walletID)
		if err != nil {
			return fmt.Errorf("get wallet start block: %w", err)
		}

		hash, err := chainhash.NewHash(row.Hash)
		if err != nil {
			return fmt.Errorf("decode wallet start block hash: %w", err)
		}

		block = &waddrmgr.BlockStamp{
			Height:    row.Height,
			Hash:      *hash,
			Timestamp: time.Unix(row.Timestamp, 0),
		}
	}

	err := s.queries.PutBlock(s.ctx, BlockRow{
		Height:    block.Height,
		Hash:      block.Hash[:],
		Timestamp: block.Timestamp.Unix(),
	})
	if err != nil {
		return fmt.Errorf("put synced-to block %d: %w", block.Height, err)
	}

	rows, err := s.queries.SetWalletSyncedTo(
		s.ctx, s.walletID, block.Height,
	)
	if err != nil {
		return fmt.Errorf("set wallet synced-to block: %w", err)
	}

	if rows != 1 {
		return fmt.Errorf("wallet %d sync state not found", s.walletID)
	}

	return nil
}

type txStore struct {
	// The manager view is scoped to the transaction callback that created it.
	//
	//nolint:containedctx // Domain methods intentionally omit backend context.
	ctx              context.Context
	walletID         int64
	coinbaseMaturity int32
	queries          Queries
}

// Rollback removes all mined transaction incidences at height onwards. The
// retained non-coinbase incidence becomes unmined, while coinbase transactions
// and any unmined descendants that spend them are removed.
func (s *txStore) Rollback(height int32) error {
	rows, err := s.queries.ListMinedTransactionsFromHeight(
		s.ctx, s.walletID, height,
	)
	if err != nil {
		return fmt.Errorf("list rollback transactions: %w", err)
	}

	removed := make(map[int64]struct{})
	for _, row := range rows {
		err := s.rollbackTransaction(row, removed)
		if err != nil {
			return err
		}
	}

	return nil
}

// rollbackTransaction rewinds one mined transaction while preserving the
// surviving incidence rules.
func (s *txStore) rollbackTransaction(row MinedTransactionRow,
	removed map[int64]struct{}) error {

	if row.IsCoinbase {
		err := s.removeUnminedDescendants(row.Hash, removed)
		if err != nil {
			return err
		}

		err = s.deleteTransaction(row.ID)
		if err != nil {
			return fmt.Errorf("delete coinbase transaction: %w", err)
		}

		return nil
	}

	_, err := s.queries.DeleteCreditSpendsBySpendingTx(
		s.ctx, s.walletID, row.ID,
	)
	if err != nil {
		return fmt.Errorf("delete transaction credit spends: %w", err)
	}

	unminedID, err := s.queries.GetUnminedTransactionID(
		s.ctx, s.walletID, row.Hash,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return s.detachMinedTransaction(row.ID)
	}

	if err != nil {
		return fmt.Errorf("get unmined transaction: %w", err)
	}

	err = s.activateTransactionCredits(unminedID)
	if err != nil {
		return err
	}

	err = s.deleteTransaction(row.ID)
	if err != nil {
		return fmt.Errorf("delete duplicate incidence: %w", err)
	}

	return nil
}

// detachMinedTransaction moves one mined transaction incidence back to the
// unmined set.
func (s *txStore) detachMinedTransaction(transactionID int64) error {
	rows, err := s.queries.DetachMinedTransaction(
		s.ctx, s.walletID, transactionID,
	)
	if err != nil {
		return fmt.Errorf("detach mined transaction: %w", err)
	}

	if rows != 1 {
		return fmt.Errorf("mined transaction %d not found", transactionID)
	}

	return nil
}

// activateTransactionCredits marks every credit on the surviving transaction
// incidence as active.
func (s *txStore) activateTransactionCredits(transactionID int64) error {
	creditIDs, err := s.queries.ListTransactionCreditIDs(
		s.ctx, s.walletID, transactionID,
	)
	if err != nil {
		return fmt.Errorf("list transaction credits: %w", err)
	}

	for _, creditID := range creditIDs {
		err := s.queries.SetActiveCreditIncidence(
			s.ctx, s.walletID, creditID,
		)
		if err != nil {
			return fmt.Errorf("activate transaction credit: %w", err)
		}
	}

	return nil
}

// removeUnminedDescendants recursively removes unmined transactions that spend
// the given transaction.
func (s *txStore) removeUnminedDescendants(hash []byte,
	removed map[int64]struct{}) error {

	spenders, err := s.queries.ListUnminedSpendersByPrevHash(
		s.ctx, s.walletID, hash,
	)
	if err != nil {
		return fmt.Errorf("list unmined descendants: %w", err)
	}

	for _, spender := range spenders {
		if _, ok := removed[spender.ID]; ok {
			continue
		}

		removed[spender.ID] = struct{}{}

		err := s.removeUnminedDescendants(spender.Hash, removed)
		if err != nil {
			return err
		}

		err = s.deleteTransaction(spender.ID)
		if err != nil {
			return fmt.Errorf("delete unmined descendant: %w", err)
		}
	}

	return nil
}

// deleteTransaction removes one transaction after clearing the related spend
// state.
func (s *txStore) deleteTransaction(transactionID int64) error {
	rows, err := s.queries.DeleteTransaction(
		s.ctx, s.walletID, transactionID,
	)
	if err != nil {
		return err
	}

	if rows != 1 {
		return fmt.Errorf("transaction %d not found", transactionID)
	}

	return nil
}

var (
	_ walletstore.Store              = (*Store)(nil)
	_ walletstore.ReadTx             = (*readTx)(nil)
	_ walletstore.ReadWriteTx        = (*readWriteTx)(nil)
	_ walletstore.AddrReadStore      = (*addrStore)(nil)
	_ walletstore.AddrReadWriteStore = (*addrStore)(nil)
	_ walletstore.TxReadStore        = (*txStore)(nil)
	_ walletstore.TxReadWriteStore   = (*txStore)(nil)
)
