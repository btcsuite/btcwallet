package sqlstore

import (
	"context"
	"crypto/sha256"
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

// expectWalletRow requires a manager update to affect exactly one wallet row.
func (s *addrStore) expectWalletRow(operation string, rows int64) error {
	if rows == 1 {
		return nil
	}

	return fmt.Errorf("%s: wallet %d state not found", operation, s.walletID)
}

// managerNotFound translates a missing SQL row into the requested legacy
// waddrmgr error.
func managerNotFound(err error, code waddrmgr.ErrorCode,
	description string) error {

	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	return waddrmgr.ManagerError{
		ErrorCode:   code,
		Description: description,
		Err:         err,
	}
}

// missingManagerRow constructs a legacy waddrmgr error for a missing update
// target.
func missingManagerRow(code waddrmgr.ErrorCode,
	description string) error {

	return waddrmgr.ManagerError{
		ErrorCode:   code,
		Description: description,
	}
}

// ManagerState returns the durable root address-manager state.
func (s *addrStore) ManagerState() (waddrmgr.ManagerState, error) {
	state, err := s.queries.GetManagerState(s.ctx, s.walletID)

	return state, managerNotFound(
		err, waddrmgr.ErrNoExist, "address manager does not exist",
	)
}

// SyncState returns the durable address-manager chain position.
func (s *addrStore) SyncState() (waddrmgr.SyncState, error) {
	state, err := s.queries.GetSyncState(s.ctx, s.walletID)

	return state, managerNotFound(
		err, waddrmgr.ErrNoExist, "address manager sync state does not exist",
	)
}

// KeyScope returns the durable state for one key scope.
func (s *addrStore) KeyScope(
	scope waddrmgr.KeyScope) (waddrmgr.KeyScopeState, error) {

	state, err := s.queries.GetKeyScope(s.ctx, s.walletID, scope)

	return state, managerNotFound(
		err, waddrmgr.ErrScopeNotFound,
		fmt.Sprintf("key scope %s not found", scope),
	)
}

// KeyScopes returns all durable key-scope states.
func (s *addrStore) KeyScopes() ([]waddrmgr.KeyScopeState, error) {
	return s.queries.ListKeyScopes(s.ctx, s.walletID)
}

// Account returns one durable scoped account.
func (s *addrStore) Account(scope waddrmgr.KeyScope,
	account uint32) (waddrmgr.AccountState, error) {

	state, err := s.queries.GetAccount(s.ctx, s.walletID, scope, account)

	return state, managerNotFound(
		err, waddrmgr.ErrAccountNotFound,
		fmt.Sprintf("account %d not found", account),
	)
}

// AccountByName returns one durable scoped account by name.
func (s *addrStore) AccountByName(scope waddrmgr.KeyScope,
	name string) (waddrmgr.AccountState, error) {

	state, err := s.queries.GetAccountByName(s.ctx, s.walletID, scope, name)

	return state, managerNotFound(
		err, waddrmgr.ErrAccountNotFound,
		fmt.Sprintf("account name %q not found", name),
	)
}

// Accounts returns all durable accounts in one key scope.
func (s *addrStore) Accounts(
	scope waddrmgr.KeyScope) ([]waddrmgr.AccountState, error) {

	return s.queries.ListAccounts(s.ctx, s.walletID, scope)
}

// Address returns one durable address by its legacy address identifier.
func (s *addrStore) Address(scope waddrmgr.KeyScope,
	addressID []byte) (waddrmgr.AddressState, error) {

	hash := sha256.Sum256(addressID)
	state, err := s.queries.GetAddress(s.ctx, s.walletID, scope, hash[:])

	return state, managerNotFound(
		err, waddrmgr.ErrAddressNotFound, "address not found",
	)
}

// AccountAddresses returns all addresses belonging to one scoped account.
func (s *addrStore) AccountAddresses(scope waddrmgr.KeyScope,
	account uint32) ([]waddrmgr.AddressState, error) {

	return s.queries.ListAccountAddresses(
		s.ctx, s.walletID, scope, account,
	)
}

// ActiveAddresses returns all addresses in one key scope.
func (s *addrStore) ActiveAddresses(
	scope waddrmgr.KeyScope) ([]waddrmgr.AddressState, error) {

	return s.queries.ListActiveAddresses(s.ctx, s.walletID, scope)
}

// PutManagerState replaces the durable root address-manager state.
func (s *addrStore) PutManagerState(state waddrmgr.ManagerState) error {
	rows, err := s.queries.PutManagerState(s.ctx, s.walletID, state)
	if err != nil {
		return fmt.Errorf("put manager state: %w", err)
	}

	return s.expectWalletRow("put manager state", rows)
}

// PutSyncState replaces the complete durable address-manager chain position.
func (s *addrStore) PutSyncState(state waddrmgr.SyncState) error {
	blocks := []waddrmgr.BlockStamp{state.StartBlock, state.SyncedTo}
	if state.BirthdayBlock != nil {
		blocks = append(blocks, *state.BirthdayBlock)
	}

	for _, block := range blocks {
		err := s.queries.PutBlock(s.ctx, BlockRow{
			Height:    block.Height,
			Hash:      block.Hash[:],
			Timestamp: block.Timestamp.Unix(),
		})
		if err != nil {
			return fmt.Errorf("put sync block %d: %w", block.Height, err)
		}
	}

	rows, err := s.queries.PutSyncState(s.ctx, s.walletID, state)
	if err != nil {
		return fmt.Errorf("put sync state: %w", err)
	}

	return s.expectWalletRow("put sync state", rows)
}

// SetBirthday sets the wallet birthday timestamp.
func (s *addrStore) SetBirthday(birthday time.Time) error {
	rows, err := s.queries.SetWalletBirthday(
		s.ctx, s.walletID, birthday.Unix(),
	)
	if err != nil {
		return fmt.Errorf("set wallet birthday: %w", err)
	}

	return s.expectWalletRow("set wallet birthday", rows)
}

// SetBirthdayBlock sets or clears the wallet birthday block.
func (s *addrStore) SetBirthdayBlock(block *waddrmgr.BlockStamp) error {
	var blockHash []byte
	if block != nil {
		err := s.queries.PutBlock(s.ctx, BlockRow{
			Height:    block.Height,
			Hash:      block.Hash[:],
			Timestamp: block.Timestamp.Unix(),
		})
		if err != nil {
			return fmt.Errorf("put birthday block %d: %w", block.Height, err)
		}

		blockHash = block.Hash[:]
	}

	rows, err := s.queries.SetWalletBirthdayBlock(
		s.ctx, s.walletID, blockHash,
	)
	if err != nil {
		return fmt.Errorf("set wallet birthday block: %w", err)
	}

	return s.expectWalletRow("set wallet birthday block", rows)
}

// SetBirthdayBlockVerified sets birthday-block verification state.
func (s *addrStore) SetBirthdayBlockVerified(verified bool) error {
	rows, err := s.queries.SetWalletBirthdayBlockVerified(
		s.ctx, s.walletID, verified,
	)
	if err != nil {
		return fmt.Errorf("set birthday block verification: %w", err)
	}

	return s.expectWalletRow("set birthday block verification", rows)
}

// PutKeyScope creates or replaces one durable key-scope state.
func (s *addrStore) PutKeyScope(state waddrmgr.KeyScopeState) error {
	err := s.queries.PutKeyScope(s.ctx, s.walletID, state)
	if err != nil {
		return fmt.Errorf("put key scope: %w", err)
	}

	return nil
}

// SetCoinTypeKeys replaces one key scope's encrypted coin-type keys.
func (s *addrStore) SetCoinTypeKeys(scope waddrmgr.KeyScope,
	encryptedPub, encryptedPriv []byte) error {

	rows, err := s.queries.SetCoinTypeKeys(
		s.ctx, s.walletID, scope, encryptedPub, encryptedPriv,
	)
	if err != nil {
		return managerNotFound(
			err, waddrmgr.ErrScopeNotFound,
			fmt.Sprintf("key scope %s not found", scope),
		)
	}

	if rows != 1 {
		return missingManagerRow(
			waddrmgr.ErrScopeNotFound,
			fmt.Sprintf("key scope %s not found", scope),
		)
	}

	return nil
}

// SetLastAccount sets the last allocated account for one key scope.
func (s *addrStore) SetLastAccount(scope waddrmgr.KeyScope,
	account uint32) error {

	rows, err := s.queries.SetLastAccount(
		s.ctx, s.walletID, scope, account,
	)
	if err != nil {
		return managerNotFound(
			err, waddrmgr.ErrScopeNotFound,
			fmt.Sprintf("key scope %s not found", scope),
		)
	}

	if rows != 1 {
		return missingManagerRow(
			waddrmgr.ErrScopeNotFound,
			fmt.Sprintf("key scope %s not found", scope),
		)
	}

	return nil
}

// PutAccount creates or replaces one durable scoped account.
func (s *addrStore) PutAccount(state waddrmgr.AccountState) error {
	rows, err := s.queries.PutAccount(s.ctx, s.walletID, state)
	if err != nil {
		return fmt.Errorf("put account: %w", err)
	}

	if rows != 1 {
		return missingManagerRow(
			waddrmgr.ErrScopeNotFound,
			fmt.Sprintf("key scope %s not found", state.Scope),
		)
	}

	return nil
}

// RenameAccount renames one durable scoped account.
func (s *addrStore) RenameAccount(scope waddrmgr.KeyScope,
	account uint32, name string) error {

	// Reject a rename onto a name already owned by a different account,
	// matching the legacy manager and the KV store. Renaming an account to
	// its own current name stays a permitted no-op. Without this guard the
	// bare UPDATE would surface a raw unique-constraint error instead of the
	// typed ErrDuplicateAccount.
	existing, err := s.queries.GetAccountByName(s.ctx, s.walletID, scope, name)
	switch {
	case err == nil:
		if existing.Account != account {
			return missingManagerRow(
				waddrmgr.ErrDuplicateAccount,
				fmt.Sprintf("account name %q already exists", name),
			)
		}

	case !errors.Is(err, sql.ErrNoRows):
		return err
	}

	rows, err := s.queries.RenameAccount(
		s.ctx, s.walletID, scope, account, name,
	)
	if err != nil {
		return managerNotFound(
			err, waddrmgr.ErrScopeNotFound,
			fmt.Sprintf("key scope %s not found", scope),
		)
	}

	if rows != 1 {
		return missingManagerRow(
			waddrmgr.ErrAccountNotFound,
			fmt.Sprintf("account %d not found", account),
		)
	}

	return nil
}

// SetAccountIndexes replaces one account's next derivation indexes.
func (s *addrStore) SetAccountIndexes(scope waddrmgr.KeyScope, account,
	nextExternal, nextInternal uint32) error {

	rows, err := s.queries.SetAccountIndexes(
		s.ctx, s.walletID, scope, account, nextExternal, nextInternal,
	)
	if err != nil {
		return managerNotFound(
			err, waddrmgr.ErrScopeNotFound,
			fmt.Sprintf("key scope %s not found", scope),
		)
	}

	if rows != 1 {
		return missingManagerRow(
			waddrmgr.ErrAccountNotFound,
			fmt.Sprintf("account %d not found", account),
		)
	}

	return nil
}

// PutAddress creates or replaces one durable managed address.
func (s *addrStore) PutAddress(addressID []byte,
	state waddrmgr.AddressState) error {

	hash := sha256.Sum256(addressID)
	state.Hash = hash[:]

	rows, err := s.queries.PutAddress(s.ctx, s.walletID, state)
	if err != nil {
		return fmt.Errorf("put address: %w", err)
	}

	if rows != 1 {
		return missingManagerRow(
			waddrmgr.ErrScopeNotFound,
			fmt.Sprintf("key scope %s not found", state.Scope),
		)
	}

	return nil
}

// MarkAddressUsed marks one managed address as used.
func (s *addrStore) MarkAddressUsed(scope waddrmgr.KeyScope,
	addressID []byte) error {

	hash := sha256.Sum256(addressID)

	rows, err := s.queries.MarkAddressUsed(
		s.ctx, s.walletID, scope, hash[:],
	)
	if err != nil {
		return managerNotFound(
			err, waddrmgr.ErrScopeNotFound,
			fmt.Sprintf("key scope %s not found", scope),
		)
	}

	if rows != 1 {
		return missingManagerRow(
			waddrmgr.ErrAddressNotFound, "address not found",
		)
	}

	return nil
}

// DeletePrivateKeys removes every persisted private key from the manager.
func (s *addrStore) DeletePrivateKeys() error {
	err := s.queries.DeletePrivateKeys(s.ctx, s.walletID)
	if err != nil {
		return fmt.Errorf("delete manager private keys: %w", err)
	}

	return nil
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

// SetSyncedTo marks the address manager as synced through the block. When the
// block is nil the wallet is reset to its start block, matching the legacy
// Manager.SetSyncedTo reset semantics.
//
// It reproduces the durable side effects of legacy waddrmgr.PutSyncedTo:
//
//   - Predecessor guard: once the birthday block is known, the block preceding
//     a non-genesis tip must already be recorded. This mirrors the legacy
//     reorg-safety check and rejects recording a tip whose ancestry has not
//     been observed. Before the birthday block is set the recent-block index
//     is intentionally sparse, so the guard is skipped during initial sync.
//   - Recent-block retention: the block that ages out of the reorg window
//     (tip minus waddrmgr.MaxReorgDepth) is pruned so the shared blocks table
//     does not grow without bound, matching the legacy per-tip prune.
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

	if err := s.checkSyncedToPredecessor(block.Height); err != nil {
		return err
	}

	err := s.queries.PutBlock(s.ctx, BlockRow{
		Height:    block.Height,
		Hash:      block.Hash[:],
		Timestamp: block.Timestamp.Unix(),
	})
	if err != nil {
		return fmt.Errorf("put synced-to block %d: %w", block.Height, err)
	}

	if err := s.pruneStaleSyncBlock(block.Height); err != nil {
		return err
	}

	rows, err := s.queries.SetWalletSyncedTo(
		s.ctx, s.walletID, block.Hash[:],
	)
	if err != nil {
		return fmt.Errorf("set wallet synced-to block: %w", err)
	}

	if rows != 1 {
		return fmt.Errorf("wallet %d sync state not found", s.walletID)
	}

	return nil
}

// checkSyncedToPredecessor enforces the legacy predecessor guard: once the
// birthday block is recorded, the block immediately preceding a non-genesis
// synced-to tip must already exist in storage. It returns a legacy
// ErrBlockNotFound manager error when the predecessor is missing.
func (s *addrStore) checkSyncedToPredecessor(height int32) error {
	if height <= 0 {
		return nil
	}

	// The recent-block index is only guaranteed contiguous once initial sync
	// has completed, which the legacy manager tracks through the birthday
	// block. Skip the guard until then.
	state, err := s.queries.GetSyncState(s.ctx, s.walletID)
	if err != nil {
		return fmt.Errorf("get sync state: %w", err)
	}
	if state.BirthdayBlock == nil {
		return nil
	}

	_, err = s.queries.GetBlockByHeight(s.ctx, height-1)
	if errors.Is(err, sql.ErrNoRows) {
		return waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrBlockNotFound,
			Description: fmt.Sprintf(
				"missing block at height %d preceding synced-to "+
					"height %d", height-1, height,
			),
			Err: err,
		}
	}
	if err != nil {
		return fmt.Errorf(
			"get predecessor block %d: %w", height-1, err,
		)
	}

	return nil
}

// pruneStaleSyncBlock removes the block that has aged out of the reorg-depth
// retention window, mirroring the legacy per-tip prune. The salvage schema
// shares one foreign-keyed blocks table, so the block is only removed when no
// transaction or sync state still references it.
func (s *addrStore) pruneStaleSyncBlock(height int32) error {
	staleHeight := height - waddrmgr.MaxReorgDepth
	if staleHeight <= 0 {
		return nil
	}

	err := s.queries.PruneStaleSyncBlock(s.ctx, staleHeight)
	if err != nil {
		return fmt.Errorf(
			"prune stale sync block %d: %w", staleHeight, err,
		)
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
