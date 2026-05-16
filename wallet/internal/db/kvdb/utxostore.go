// Package kvdb provides a walletdb (kvdb) backed implementation of the
// wallet/internal/db UTXO store interface.
package kvdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// errNotImplemented is returned for unimplemented kvdb store methods.
	errNotImplemented = errors.New("not implemented")

	// errMissingTxmgrNamespace is returned when the legacy transaction manager
	// bucket is not available in the kvdb wallet database.
	errMissingTxmgrNamespace = errors.New("missing wtxmgr namespace")

	// wtxmgrNamespaceKey is the walletdb top-level bucket key used by the
	// transaction manager.
	//
	// NOTE: This must match the namespace used by the wallet package.
	wtxmgrNamespaceKey = []byte("wtxmgr")
)

// notImplemented returns a consistent error for kvdb methods that still need a
// legacy-backed implementation.
func notImplemented(_ context.Context, method string) error {
	return fmt.Errorf("kvdb.Store.%s: %w", method, errNotImplemented)
}

// IsNotImplemented reports whether err was produced by a kvdb Store method
// stub that has not yet been implemented. Wallet-side fallback paths use
// this predicate to detect when to fall back to legacy walletdb walks.
func IsNotImplemented(err error) bool {
	return errors.Is(err, errNotImplemented)
}

// GetUtxo retrieves one current wallet-owned UTXO through the legacy wtxmgr
// query path.
func (s *Store) GetUtxo(_ context.Context,
	query db.GetUtxoQuery) (*db.UtxoInfo, error) {

	var utxo *db.UtxoInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return errMissingTxmgrNamespace
		}

		credit, err := s.txStore.GetUtxo(ns, query.OutPoint)
		if err != nil {
			if errors.Is(err, wtxmgr.ErrUtxoNotFound) {
				return db.ErrUtxoNotFound
			}

			return fmt.Errorf("get utxo: %w", err)
		}

		utxo = utxoInfo(credit)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetUtxo: %w", err)
	}

	return utxo, nil
}

// ListUTXOs lists current wallet-owned UTXOs through the legacy wtxmgr query
// path.
func (s *Store) ListUTXOs(_ context.Context,
	query db.ListUtxosQuery) ([]db.UtxoInfo, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf(
			"kvdb.Store.ListUTXOs: %w", errMissingLegacyAddrStore,
		)
	}

	var utxos []db.UtxoInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		return s.listUTXOsInView(tx, query, &utxos)
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.ListUTXOs: %w", err)
	}

	if len(utxos) == 0 {
		return []db.UtxoInfo{}, nil
	}

	return utxos, nil
}

// LeaseOutput is not yet implemented for kvdb.
func (s *Store) LeaseOutput(ctx context.Context,
	_ db.LeaseOutputParams) (*db.LeasedOutput, error) {

	return nil, notImplemented(ctx, "LeaseOutput")
}

// ReleaseOutput releases a previously leased output.
//
// How it works:
// The method executes a single walletdb update transaction that deletes the
// lock record associated with the specified outpoint.
//
// Database Actions:
//   - Performs exactly one write transaction (walletdb.Update).
//   - Writes to the `wtxmgr` namespace.
//
// NOTE: The legacy kvdb backend only supports a single wallet instance, so the
// WalletID field is ignored.
func (s *Store) ReleaseOutput(_ context.Context,
	params db.ReleaseOutputParams) error {

	lockID := wtxmgr.LockID(params.ID)
	op := params.OutPoint

	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return fmt.Errorf(
				"wtxmgr namespace: %w", walletdb.ErrBucketNotFound,
			)
		}

		err := s.txStore.UnlockOutput(ns, lockID, op)
		if err != nil {
			return fmt.Errorf("unlock output: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.ReleaseOutput: %w", err)
	}

	return nil
}

// ListLeasedOutputs is not yet implemented for kvdb.
func (s *Store) ListLeasedOutputs(ctx context.Context,
	_ uint32) ([]db.LeasedOutput, error) {

	return nil, notImplemented(ctx, "ListLeasedOutputs")
}

// Balance is not yet implemented for kvdb.
func (s *Store) Balance(ctx context.Context,
	_ db.BalanceParams) (db.BalanceResult, error) {

	return db.BalanceResult{}, notImplemented(ctx, "Balance")
}

// utxoInfo maps one legacy wtxmgr credit into the db-native UTXO shape.
func utxoInfo(credit *wtxmgr.Credit) *db.UtxoInfo {
	height := db.UnminedHeight
	if credit.Height >= 0 {
		height = nonNegativeInt32ToUint32(credit.Height)
	}

	return &db.UtxoInfo{
		OutPoint:     credit.OutPoint,
		Amount:       credit.Amount,
		PkScript:     credit.PkScript,
		Received:     credit.Received.UTC(),
		FromCoinBase: credit.FromCoinBase,
		Height:       height,
	}
}

// listUTXOsInView performs the legacy UTXO scan using one walletdb view.
func (s *Store) listUTXOsInView(tx walletdb.ReadTx, query db.ListUtxosQuery,
	utxos *[]db.UtxoInfo) error {

	txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
	if txmgrNs == nil {
		return errMissingTxmgrNamespace
	}

	addrmgrNs := tx.ReadBucket(waddrmgr.NamespaceKey)
	if addrmgrNs == nil {
		return errMissingAddrmgrNamespace
	}

	credits, err := s.txStore.UnspentOutputs(txmgrNs)
	if err != nil {
		return fmt.Errorf("list unspent outputs: %w", err)
	}

	currentHeight := s.addrStore.SyncedTo().Height
	chainParams := s.addrStore.ChainParams()

	for i := range credits {
		credit := &credits[i]

		include, err := s.shouldIncludeUtxo(
			addrmgrNs, credit, currentHeight, chainParams, query,
		)
		if err != nil {
			return err
		}

		if include {
			*utxos = append(*utxos, *utxoInfo(credit))
		}
	}

	return nil
}

// utxoMatchesConfirmations applies the optional db.ListUtxosQuery
// confirmation filters using legacy current-height state.
func utxoMatchesConfirmations(txHeight int32, currentHeight int32,
	query db.ListUtxosQuery) bool {

	confs := calcConfirmations(txHeight, currentHeight)

	if query.MinConfs != nil && confs < *query.MinConfs {
		return false
	}

	if query.MaxConfs != nil && confs > *query.MaxConfs {
		return false
	}

	return true
}

// shouldIncludeUtxo applies the legacy confirmation and optional account
// filters to one credit before it is adapted to db.UtxoInfo.
func (s *Store) shouldIncludeUtxo(addrmgrNs walletdb.ReadBucket,
	credit *wtxmgr.Credit, currentHeight int32,
	chainParams *chaincfg.Params,
	query db.ListUtxosQuery) (bool, error) {

	if !utxoMatchesConfirmations(credit.Height, currentHeight, query) {
		return false, nil
	}

	if query.Account == nil {
		return true, nil
	}

	return s.utxoMatchesAccount(
		addrmgrNs, credit.PkScript, chainParams, *query.Account,
	)
}

// utxoMatchesAccount checks whether one legacy UTXO belongs to the caller's
// requested account number.
func (s *Store) utxoMatchesAccount(addrmgrNs walletdb.ReadBucket,
	pkScript []byte, chainParams *chaincfg.Params,
	account uint32) (bool, error) {

	addr, err := addressFromPkScript(pkScript, chainParams)
	if err != nil {
		return false, err
	}

	_, utxoAccount, err := s.addrStore.AddrAccount(addrmgrNs, addr)
	if err != nil {
		return false, fmt.Errorf("lookup utxo account: %w", err)
	}

	return utxoAccount == account, nil
}

// calcConfirmations mirrors the wallet confirmation calculation used by the
// public UTXO manager.
func calcConfirmations(txHeight, currentHeight int32) int32 {
	switch {
	case txHeight == -1:
		return 0

	case txHeight > currentHeight:
		return 0

	default:
		return currentHeight - txHeight + 1
	}
}
