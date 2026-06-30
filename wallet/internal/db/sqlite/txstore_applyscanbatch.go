package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// ApplyScanBatch atomically records recovery scan writes for one wallet.
//
// In a single write transaction it extends every reported address horizon
// (deriving and persisting the recovered addresses), records the relevant
// transactions, and connects the discovered synced blocks, mirroring the kvdb
// backend's scan-batch semantics.
func (s *Store) ApplyScanBatch(ctx context.Context,
	params db.ScanBatchParams) error {

	// Reject a batch that mixes wallets before opening the write transaction:
	// the horizons and synced blocks are applied to params.WalletID, so a
	// transaction owned by a different wallet must not ride along in the same
	// atomic batch. Validating up front also avoids wasting horizon derivation
	// and synced-block work on a batch that cannot commit.
	err := db.ValidateBatchTransactionsWalletID(
		params.WalletID, params.Transactions,
	)
	if err != nil {
		return err
	}

	// Reject a nil-Tx member before the parents-first sort below dereferences
	// each transaction; the per-tx NewCreateTxRequest check in
	// applyBatchTransaction runs only after the sort.
	err = db.ValidateBatchTransactionsTx(params.Transactions)
	if err != nil {
		return err
	}

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		ops := scanHorizonOps{qtx: qtx, walletID: params.WalletID}
		for i := range params.Horizons {
			err := db.ExtendScanHorizon(
				ctx, ops, s.deriveAddress, params.Horizons[i],
			)
			if err != nil {
				return fmt.Errorf("horizon %d: %w", i, err)
			}
		}

		// Connect the discovered synced blocks first so their rows exist
		// before any relevant transaction confirmed in those blocks is
		// created. CreateTxWithOps needs the confirming block row during
		// PrepareBlock, so creating transactions first would fail with
		// ErrBlockNotFound.
		err := applyBatchSyncedBlocks(ctx, qtx, params)
		if err != nil {
			return err
		}

		// Record any in-batch parent before its children. Each tx claims
		// its spent parent inputs by updating the parent credit's UTXO row,
		// so a child applied before its in-batch parent would update no row
		// and silently drop the spend edge. Sorting parents first makes the
		// batch order-independent.
		txs := db.SortTxBatchParentsFirst(params.Transactions)

		for i := range txs {
			err = applyBatchTransaction(ctx, qtx, txs[i])
			if err != nil {
				return fmt.Errorf("create tx %d: %w", i, err)
			}
		}

		return nil
	})
}

// applyBatchSyncedBlocks connects the scan batch's discovered synced blocks,
// advancing the wallet sync tip to the final block. Targeted rescans report no
// blocks and leave the sync tip untouched.
func applyBatchSyncedBlocks(ctx context.Context, qtx *sqlc.Queries,
	params db.ScanBatchParams) error {

	for i := range params.SyncedBlocks {
		block := &params.SyncedBlocks[i]

		err := ensureBlockExists(ctx, qtx, block)
		if err != nil {
			return fmt.Errorf("ensure synced block %d: %w", i, err)
		}

		syncParams := buildUpdateSyncParams(db.UpdateWalletParams{
			WalletID: params.WalletID,
			SyncedTo: block,
		})

		rowsAffected, err := qtx.UpdateWalletSyncState(ctx, syncParams)
		if err != nil {
			return fmt.Errorf("update wallet sync state: %w", err)
		}

		if rowsAffected == 0 {
			return fmt.Errorf("wallet sync state for wallet %d: %w",
				params.WalletID, db.ErrWalletNotFound)
		}
	}

	return nil
}

// scanHorizonOps adapts the SQLite sqlc queries to the shared horizon
// extension workflow.
type scanHorizonOps struct {
	qtx      *sqlc.Queries
	walletID uint32
}

// A compile-time assertion that scanHorizonOps satisfies the shared interface.
var _ db.ScanHorizonOps = (*scanHorizonOps)(nil)

// horizonAccountRow is the subset of an account lookup row that both the
// by-name and by-number horizon resolution paths produce, letting them share a
// single HorizonAccount builder.
type horizonAccountRow struct {
	id               int64
	accountNumber    sql.NullInt64
	publicKey        []byte
	internalTypeID   int64
	externalTypeID   int64
	externalKeyCount int64
	internalKeyCount int64
}

// GetHorizonAccount loads the account state needed to extend a horizon. The
// stable AccountID is mandatory because account names are mutable and imported
// xpub accounts do not have BIP44 account numbers.
func (o scanHorizonOps) GetHorizonAccount(ctx context.Context,
	horizon db.ScanHorizon) (*db.HorizonAccount, error) {

	if horizon.AccountID == nil {
		return nil, fmt.Errorf("%w: scan horizon account id is required",
			db.ErrInvalidParam)
	}

	return o.horizonAccountByID(ctx, *horizon.AccountID, horizon.Scope)
}

// buildHorizonAccount assembles the HorizonAccount the shared extension
// workflow needs from a resolved account row. An imported xpub account has a
// NULL account_number, surfaced as a nil AccountNumber so the derivation
// callback receives no wallet-derived number; xpub-based derivation keys off
// the account public key alone. A derived account's number is passed through.
func buildHorizonAccount(row horizonAccountRow) (*db.HorizonAccount, error) {
	schema, err := db.DerivedAddressAccountSchema(
		row.internalTypeID, row.externalTypeID,
	)
	if err != nil {
		return nil, fmt.Errorf("account addr schema: %w", err)
	}

	// A derived account carries a real BIP44 number; an imported xpub
	// account has a NULL account_number and is surfaced as nil so the shared
	// extension presents no wallet-derived number for it.
	var accountNumber *uint32
	if row.accountNumber.Valid {
		num, err := db.Int64ToUint32(row.accountNumber.Int64)
		if err != nil {
			return nil, fmt.Errorf("account number: %w", err)
		}

		accountNumber = &num
	}

	nextExternal, err := db.Int64ToUint32(row.externalKeyCount)
	if err != nil {
		return nil, fmt.Errorf("external next index: %w", err)
	}

	nextInternal, err := db.Int64ToUint32(row.internalKeyCount)
	if err != nil {
		return nil, fmt.Errorf("internal next index: %w", err)
	}

	return &db.HorizonAccount{
		AccountID:         row.id,
		AccountNumber:     accountNumber,
		AccountPubKey:     row.publicKey,
		AddrSchema:        schema,
		NextExternalIndex: nextExternal,
		NextInternalIndex: nextInternal,
	}, nil
}

// InsertDerivedAddress persists one derived address row at a fixed index.
func (o scanHorizonOps) InsertDerivedAddress(ctx context.Context,
	accountID int64, addrType db.AddressType, branch uint32, index uint32,
	scriptPubKey []byte, pubKey []byte) error {

	row, err := o.qtx.CreateDerivedAddress(
		ctx, buildDerivedAddressParams(
			int64(o.walletID), accountID, addrType, scriptPubKey, pubKey,
		),
	)
	if err != nil {
		return fmt.Errorf("create derived address: %w", err)
	}

	err = o.qtx.CreateDerivedAddressPath(
		ctx, sqlc.CreateDerivedAddressPathParams{
			AddressID:     row.ID,
			AccountID:     accountID,
			AddressBranch: int64(branch),
			AddressIndex:  int64(index),
		},
	)
	if err != nil {
		return fmt.Errorf("create derived address path: %w", err)
	}

	return nil
}

// AdvanceNextIndex moves the branch's next-index counter up to nextIndex.
func (o scanHorizonOps) AdvanceNextIndex(ctx context.Context, accountID int64,
	branch uint32, nextIndex uint32) error {

	if branch == 1 {
		err := o.qtx.AdvanceNextInternalIndex(
			ctx, sqlc.AdvanceNextInternalIndexParams{
				NextIndex: int64(nextIndex),
				ID:        accountID,
			},
		)
		if err != nil {
			return fmt.Errorf("advance internal index: %w", err)
		}

		return nil
	}

	err := o.qtx.AdvanceNextExternalIndex(
		ctx, sqlc.AdvanceNextExternalIndexParams{
			NextIndex: int64(nextIndex),
			ID:        accountID,
		},
	)
	if err != nil {
		return fmt.Errorf("advance external index: %w", err)
	}

	return nil
}

// horizonAccountByID resolves the horizon's owning account by stable account
// row ID and verifies that the account belongs to the horizon's key scope.
func (o scanHorizonOps) horizonAccountByID(ctx context.Context,
	accountID uint32, scope db.KeyScope) (*db.HorizonAccount, error) {

	row, err := o.qtx.GetAccountPropsByWalletAndId(
		ctx, sqlc.GetAccountPropsByWalletAndIdParams{
			WalletID: int64(o.walletID),
			ID:       int64(accountID),
		},
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, db.ErrAccountNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get account by id %d: %w", accountID, err)
	}

	scopeMatches := row.Purpose == int64(scope.Purpose) &&
		row.CoinType == int64(scope.Coin)
	if !scopeMatches {
		return nil, db.ErrAccountNotFound
	}

	return buildHorizonAccount(horizonAccountRow{
		id:               int64(accountID),
		accountNumber:    row.AccountNumber,
		publicKey:        row.PublicKey,
		internalTypeID:   row.InternalTypeID,
		externalTypeID:   row.ExternalTypeID,
		externalKeyCount: row.ExternalKeyCount,
		internalKeyCount: row.InternalKeyCount,
	})
}
