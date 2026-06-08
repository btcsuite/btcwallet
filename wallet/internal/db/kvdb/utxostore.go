// Package kvdb provides a walletdb (kvdb) backed implementation of the
// wallet/internal/db UTXO store interface.
package kvdb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// A compile-time assertion to ensure Store implements the UTXO store.
var _ db.UTXOStore = (*Store)(nil)

var (
	// errNotImplemented is returned for unimplemented kvdb store methods.
	errNotImplemented = errors.New("not implemented")

	// errMissingTxmgrNamespace is returned when the legacy transaction manager
	// bucket is not available in the kvdb wallet database.
	errMissingTxmgrNamespace = errors.New("missing wtxmgr namespace")

	// errUnownedScript is returned when a legacy credit's pkScript cannot
	// be resolved to a wallet-owned account. The iteration skips the row
	// rather than propagating; wallet-owned outputs should always resolve.
	errUnownedScript = errors.New("pkScript not owned by any account")

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

// GetUtxo retrieves one current wallet-owned UTXO through the legacy wtxmgr
// query path.
func (s *Store) GetUtxo(_ context.Context,
	query db.GetUtxoQuery) (*db.UtxoInfo, error) {

	var utxo *db.UtxoInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		got, err := s.getUtxoInView(tx, query.OutPoint)
		if err != nil {
			return err
		}

		utxo = got

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetUtxo: %w", err)
	}

	return utxo, nil
}

// getUtxoInView resolves one current wallet-owned UTXO inside an open
// walletdb read transaction. It gates the outpoint through the current
// UTXO set first, then emits the enriched wallet-owned row.
func (s *Store) getUtxoInView(tx walletdb.ReadTx,
	outPoint wire.OutPoint) (*db.UtxoInfo, error) {

	txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
	if txmgrNs == nil {
		return nil, errMissingTxmgrNamespace
	}

	credit, leaseSet, err := s.loadCurrentCredit(txmgrNs, outPoint)
	if err != nil {
		return nil, err
	}

	return s.enrichOwnedCredit(tx, credit, leaseSet)
}

// loadCurrentCredit fetches one credit by outpoint and gates it through the
// current UTXO set, returning db.ErrUtxoNotFound for unknown or non-current
// (spent-by-unmined) outputs. The active lease set is returned alongside so
// the caller can mark IsLocked without re-reading the lease bucket.
func (s *Store) loadCurrentCredit(txmgrNs walletdb.ReadBucket,
	outPoint wire.OutPoint) (*wtxmgr.Credit, map[wire.OutPoint]struct{},
	error) {

	credit, err := s.txStore.GetUtxo(txmgrNs, outPoint)
	if err != nil {
		if errors.Is(err, wtxmgr.ErrUtxoNotFound) {
			return nil, nil, db.ErrUtxoNotFound
		}

		return nil, nil, fmt.Errorf("get utxo: %w", err)
	}

	current, err := s.currentUTXOSet(txmgrNs)
	if err != nil {
		return nil, nil, err
	}

	if _, ok := current[outPoint]; !ok {
		return nil, nil, db.ErrUtxoNotFound
	}

	leaseSet, err := s.activeLeaseSet(txmgrNs, current)
	if err != nil {
		return nil, nil, err
	}

	return credit, leaseSet, nil
}

// enrichOwnedCredit resolves the owning account for one current credit and
// produces its enriched db.UtxoInfo. A credit whose script does not join to a
// wallet address is reported as not found, matching the SQL backends which
// inner-join UTXO rows against owned addresses rather than surfacing an
// unenriched row.
func (s *Store) enrichOwnedCredit(tx walletdb.ReadTx,
	credit *wtxmgr.Credit,
	leaseSet map[wire.OutPoint]struct{}) (*db.UtxoInfo, error) {

	addrmgrNs := tx.ReadBucket(waddrmgr.NamespaceKey)
	if addrmgrNs == nil {
		return nil, errMissingAddrmgrNamespace
	}

	chainParams := s.addrStore.ChainParams()

	binding, addr, err := s.resolveAccountForCredit(
		addrmgrNs, credit, chainParams,
	)
	if err != nil {
		if errors.Is(err, errUnownedScript) {
			return nil, db.ErrUtxoNotFound
		}

		return nil, err
	}

	return s.enrichCredit(addrmgrNs, credit, addr, binding, leaseSet)
}

// ListUTXOs lists current wallet-owned UTXOs through the legacy wtxmgr query
// path.
func (s *Store) ListUTXOs(_ context.Context,
	query db.ListUtxosQuery) ([]db.UtxoInfo, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf("kvdb.Store.ListUTXOs: %w",
			errMissingAddrStore)
	}

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	var utxos []db.UtxoInfo

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
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

// LeaseOutput locks one known wallet UTXO through the legacy wtxmgr lease
// path.
func (s *Store) LeaseOutput(_ context.Context,
	params db.LeaseOutputParams) (*db.LeasedOutput, error) {

	if params.Duration <= 0 {
		return nil, fmt.Errorf(
			"%w: lease duration must be positive", db.ErrInvalidParam,
		)
	}

	var expiration time.Time

	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return errMissingTxmgrNamespace
		}

		current, err := s.currentUTXOSet(ns)
		if err != nil {
			return err
		}

		if _, ok := current[params.OutPoint]; !ok {
			return db.ErrUtxoNotFound
		}

		expiration, err = s.txStore.LockOutput(
			ns, wtxmgr.LockID(params.ID), params.OutPoint, params.Duration,
		)
		if err != nil {
			switch {
			case errors.Is(err, wtxmgr.ErrUtxoNotFound),
				errors.Is(err, wtxmgr.ErrUnknownOutput):
				return db.ErrUtxoNotFound

			case errors.Is(err, wtxmgr.ErrOutputAlreadyLocked):
				return db.ErrOutputAlreadyLeased
			}

			return fmt.Errorf("lock output: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.LeaseOutput: %w", err)
	}

	return &db.LeasedOutput{
		OutPoint:   params.OutPoint,
		LockID:     db.LockID(params.ID),
		Expiration: expiration.UTC(),
	}, nil
}

// ReleaseOutput releases a previously leased output, aligning the kvdb
// backend with the shared db.UTXOStore release contract (see
// db.ReleaseOutputWithOps).
//
// The outpoint is first gated through the current wallet UTXO set: a missing
// or non-current (spent-by-unmined) outpoint maps to db.ErrUtxoNotFound, the
// same sentinel the SQL backends return. The legacy unlock is then translated
// onto the shared sentinels: a wrong active lock ID becomes
// db.ErrOutputUnlockNotAllowed, while an already-unlocked or expired lease is
// a no-op. The translation mirrors the wtxmgr.Err* -> db.Err* mapping already
// used by GetUtxo and LeaseOutput in this file.
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

		// Gate the outpoint through the current UTXO set first so a
		// missing or non-current output reports db.ErrUtxoNotFound,
		// matching the SQL backends which resolve the wallet-owned row
		// before attempting the release.
		current, err := s.currentUTXOSet(ns)
		if err != nil {
			return err
		}

		if _, ok := current[op]; !ok {
			return db.ErrUtxoNotFound
		}

		err = s.txStore.UnlockOutput(ns, lockID, op)
		if err != nil {
			switch {
			// wtxmgr only knows the output through the lock bucket,
			// so an unknown output here means it left the current
			// set between the gate above and the unlock; report it
			// as not found for parity with the SQL backends.
			case errors.Is(err, wtxmgr.ErrUnknownOutput),
				errors.Is(err, wtxmgr.ErrUtxoNotFound):
				return db.ErrUtxoNotFound

			case errors.Is(err, wtxmgr.ErrOutputUnlockNotAllowed):
				return db.ErrOutputUnlockNotAllowed
			}

			return fmt.Errorf("unlock output: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.ReleaseOutput: %w", err)
	}

	return nil
}

// ListLeasedOutputs lists the currently active legacy output leases.
func (s *Store) ListLeasedOutputs(_ context.Context,
	_ uint32) ([]db.LeasedOutput, error) {

	var leases []db.LeasedOutput

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return errMissingTxmgrNamespace
		}

		locked, err := s.txStore.ListLockedOutputs(ns)
		if err != nil {
			return fmt.Errorf("list locked outputs: %w", err)
		}

		current, err := s.currentUTXOSet(ns)
		if err != nil {
			return err
		}

		leases = make([]db.LeasedOutput, 0, len(locked))
		for _, lease := range locked {
			if _, ok := current[lease.Outpoint]; !ok {
				continue
			}

			leases = append(leases, db.LeasedOutput{
				OutPoint:   lease.Outpoint,
				LockID:     db.LockID(lease.LockID),
				Expiration: lease.Expiration.UTC(),
			})
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.ListLeasedOutputs: %w", err)
	}

	if len(leases) == 0 {
		return []db.LeasedOutput{}, nil
	}

	return leases, nil
}

// DeleteExpiredLeases removes expired leases through the legacy wtxmgr path.
func (s *Store) DeleteExpiredLeases(_ context.Context, _ uint32) error {
	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return errMissingTxmgrNamespace
		}

		return s.txStore.DeleteExpiredLockedOutputs(ns)
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.DeleteExpiredLeases: %w", err)
	}

	return nil
}

// Balance sums the wallet's unspent outputs that satisfy the supplied
// filters. The walk iterates every UTXO owned by the address manager
// and applies Scope, Account, MinConfs, MaxConfs, and CoinbaseMaturity
// in turn. Outputs whose script does not extract to a recognized
// address, or that waddrmgr cannot map to an account, are skipped.
func (s *Store) Balance(_ context.Context,
	params db.BalanceParams) (db.BalanceResult, error) {

	err := params.Validate()
	if err != nil {
		return db.BalanceResult{}, err
	}

	var scopeFilter *waddrmgr.KeyScope
	if params.Scope != nil {
		scopeFilter = &waddrmgr.KeyScope{
			Purpose: params.Scope.Purpose,
			Coin:    params.Scope.Coin,
		}
	}

	var result db.BalanceResult

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgr.NamespaceKey)
		if addrmgrNs == nil {
			return nil
		}

		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		total, locked, err := s.walkBalanceUTXOs(
			addrmgrNs, txmgrNs, params, scopeFilter,
		)
		if err != nil {
			return err
		}

		result.Total = total
		result.Locked = locked

		return nil
	})
	if err != nil {
		return db.BalanceResult{}, fmt.Errorf("balance: %w", err)
	}

	return result, nil
}

// walkBalanceUTXOs iterates the wallet's unspent outputs and sums total and
// locked amounts for those that satisfy the BalanceParams filters. The caller
// holds the wallet db read transaction.
func (s *Store) walkBalanceUTXOs(addrmgrNs, txmgrNs walletdb.ReadBucket,
	params db.BalanceParams,
	scopeFilter *waddrmgr.KeyScope) (btcutil.Amount, btcutil.Amount, error) {

	if s.txStore == nil || txmgrNs == nil {
		return 0, 0, nil
	}

	nameAcct, nameFound, err := s.resolveBalanceNameFilter(
		addrmgrNs, params, scopeFilter,
	)
	if err != nil {
		return 0, 0, err
	}

	if !nameFound {
		return 0, 0, nil
	}

	syncBlock := s.addrStore.SyncedTo()
	chainParams := s.addrStore.ChainParams()

	unspent, err := s.txStore.UnspentOutputsIncludingLocked(txmgrNs)
	if err != nil {
		return 0, 0, fmt.Errorf("unspent outputs: %w", err)
	}

	var total, locked btcutil.Amount
	for i := range unspent {
		output := &unspent[i]

		accepted, err := s.balanceOutputAccepted(
			addrmgrNs, output, scopeFilter, params, nameAcct,
			syncBlock.Height, chainParams,
		)
		if err != nil {
			return 0, 0, err
		}

		if accepted {
			total, locked = addBalanceOutput(total, locked, output)
		}
	}

	return total, locked, nil
}

// balanceOutputAccepted reports whether one unspent output counts toward the
// balance under the BalanceParams filters. It resolves the owning account,
// applies the Scope/account filters (via balanceFilterAllows) and the
// confirmation filters (via confsAllowed), and returns false for outputs that
// are unowned or filtered out so the caller skips them without error.
func (s *Store) balanceOutputAccepted(addrmgrNs walletdb.ReadBucket,
	output *wtxmgr.Credit, scopeFilter *waddrmgr.KeyScope,
	params db.BalanceParams, nameAcct *uint32, syncHeight int32,
	chainParams *chaincfg.Params) (bool, error) {

	owner, account, ok := s.classifyBalanceUTXO(
		addrmgrNs, output, chainParams,
	)
	if !ok {
		return false, nil
	}

	allowed, err := balanceFilterAllows(
		addrmgrNs, scopeFilter, owner, params, nameAcct, account,
	)
	if err != nil {
		return false, err
	}

	if !allowed {
		return false, nil
	}

	return confsAllowed(output, syncHeight, params), nil
}

// addBalanceOutput adds an accepted output to the total balance and, when the
// output is locked, the locked subset.
func addBalanceOutput(total, locked btcutil.Amount,
	output *wtxmgr.Credit) (btcutil.Amount, btcutil.Amount) {

	total += output.Amount
	if output.Locked {
		locked += output.Amount
	}

	return total, locked
}

// resolveBalanceNameFilter resolves BalanceParams.Name into the real waddrmgr
// account number used for the UTXO walk. It returns (nil, true, nil) when no
// Name filter is set, the resolved account number when one is, and
// (nil, false, nil) when the name does not exist so the caller returns a zero
// balance without an error.
//
// The resolved number is returned separately rather than folded into
// params.Account: a Name filter is the public handle that selects an account
// by name regardless of origin (including imported accounts), whereas a
// numeric params.Account filter must never match imported accounts. Keeping
// the two distinct lets balanceFilterAllows apply the imported exclusion only
// to the numeric path.
func (s *Store) resolveBalanceNameFilter(addrmgrNs walletdb.ReadBucket,
	params db.BalanceParams,
	scopeFilter *waddrmgr.KeyScope) (*uint32, bool, error) {

	if params.Name == nil {
		return nil, true, nil
	}

	scopedMgr, err := s.addrStore.FetchScopedKeyManager(*scopeFilter)
	if err != nil {
		return nil, false, fmt.Errorf("fetch scoped manager: %w", err)
	}

	acctNum, err := scopedMgr.LookupAccount(addrmgrNs, *params.Name)
	if err != nil {
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("lookup account: %w", err)
	}

	return &acctNum, true, nil
}

// classifyBalanceUTXO maps an unspent output to its owning address and
// wallet account. It returns ok=false when the script does not extract
// to a recognized address or waddrmgr cannot map it to an account; the
// caller should skip such outputs.
func (s *Store) classifyBalanceUTXO(addrmgrNs walletdb.ReadBucket,
	output *wtxmgr.Credit,
	chainParams *chaincfg.Params) (waddrmgr.AccountStore, uint32, bool) {

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		output.PkScript, chainParams,
	)
	if err != nil || len(addrs) == 0 {
		return nil, 0, false
	}

	owner, account, err := s.addrStore.AddrAccount(addrmgrNs, addrs[0])
	if err != nil {
		return nil, 0, false
	}

	return owner, account, true
}

// balanceFilterAllows reports whether an output's owning address and account
// survive the Scope and account filters from BalanceParams. nameAcct is the
// account number resolved from a Name filter, if any; it selects that account
// by exact number regardless of origin. A numeric params.Account filter, by
// contrast, never matches an imported account (see numericAccountMatches).
// Account and Name are mutually exclusive, so at most one of the two account
// filters applies.
func balanceFilterAllows(addrmgrNs walletdb.ReadBucket,
	scopeFilter *waddrmgr.KeyScope, owner waddrmgr.AccountStore,
	params db.BalanceParams, nameAcct *uint32, account uint32) (bool, error) {

	if scopeFilter != nil && *scopeFilter != owner.Scope() {
		return false, nil
	}

	// A Name filter resolves to a concrete account number and matches it
	// exactly; imported accounts are reachable this way by design.
	if nameAcct != nil {
		return account == *nameAcct, nil
	}

	if params.Account == nil {
		return true, nil
	}

	imported, err := accountIsImported(addrmgrNs, owner, account)
	if err != nil {
		return false, err
	}

	return numericAccountMatches(
		account, *params.Account, imported,
	), nil
}

// confsAllowed reports whether an unspent output's confirmation depth
// passes the BalanceParams filters (MinConfs, MaxConfs, and the
// CoinbaseMaturity gate that applies to coinbase outputs).
func confsAllowed(output *wtxmgr.Credit, syncHeight int32,
	params db.BalanceParams) bool {

	confs := calcConfs(output.Height, syncHeight)

	if params.MinConfs != nil && confs < *params.MinConfs {
		return false
	}

	if params.MaxConfs != nil && confs > *params.MaxConfs {
		return false
	}

	if output.FromCoinBase && params.CoinbaseMaturity != nil &&
		confs < *params.CoinbaseMaturity {

		return false
	}

	return true
}

// calcConfs returns the number of confirmations for an output at
// outputHeight given a chain tip of curHeight. Unconfirmed outputs
// (height == -1) return 0; future-dated outputs (height > tip) clamp
// to 0.
func calcConfs(outputHeight, curHeight int32) int32 {
	if outputHeight <= 0 || outputHeight > curHeight {
		return 0
	}

	return curHeight - outputHeight + 1
}

// currentUTXOSet returns the set of current UTXOs, including leased outputs
// but excluding outputs already spent by unmined wallet transactions.
func (s *Store) currentUTXOSet(
	txmgrNs walletdb.ReadBucket) (map[wire.OutPoint]struct{}, error) {

	credits, err := s.txStore.UnspentOutputsIncludingLocked(txmgrNs)
	if err != nil {
		return nil, fmt.Errorf("list current utxos: %w", err)
	}

	current := make(map[wire.OutPoint]struct{}, len(credits))
	for i := range credits {
		current[credits[i].OutPoint] = struct{}{}
	}

	return current, nil
}

// utxoInfoBase maps one legacy wtxmgr credit into the bare db UTXO
// shape, without resolving the wallet-derived enrichment fields. It is
// used by the enrichment path below as the starting point before
// account / address-type / lease metadata is layered on.
func utxoInfoBase(credit *wtxmgr.Credit) *db.UtxoInfo {
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

// activeLeaseSet returns the set of currently leased outpoints that
// intersect the current UTXO set so callers can mark IsLocked on each
// row without re-reading the lease bucket per UTXO.
func (s *Store) activeLeaseSet(txmgrNs walletdb.ReadBucket,
	current map[wire.OutPoint]struct{}) (
	map[wire.OutPoint]struct{}, error) {

	locked, err := s.txStore.ListLockedOutputs(txmgrNs)
	if err != nil {
		return nil, fmt.Errorf("list locked outputs: %w", err)
	}

	leaseSet := make(map[wire.OutPoint]struct{}, len(locked))
	for _, lease := range locked {
		if _, ok := current[lease.Outpoint]; !ok {
			continue
		}

		leaseSet[lease.Outpoint] = struct{}{}
	}

	return leaseSet, nil
}

// utxoAccountBinding captures the per-row account resolution shared
// between filter checks and enrichment population. The owning account
// store and number are computed once and reused so callers do not
// re-resolve the same address twice per UTXO row.
type utxoAccountBinding struct {
	acctStore waddrmgr.AccountStore
	acctNum   uint32
	scope     db.KeyScope
}

// resolveAccountForCredit maps one legacy credit's pkScript to its
// owning account store and number. Outputs whose script cannot be
// resolved to a wallet-owned account surface as errUnownedScript so
// callers can skip them defensively.
func (s *Store) resolveAccountForCredit(addrmgrNs walletdb.ReadBucket,
	credit *wtxmgr.Credit, chainParams *chaincfg.Params) (
	*utxoAccountBinding, btcutil.Address, error) {

	addr, err := addressFromPkScript(credit.PkScript, chainParams)
	if err != nil {
		if errors.Is(err, errNoAddressInPkScript) {
			return nil, nil, errUnownedScript
		}

		return nil, nil, fmt.Errorf("extract address: %w", err)
	}

	acctStore, acctNum, err := s.addrStore.AddrAccount(addrmgrNs, addr)
	if err != nil {
		if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
			return nil, nil, errUnownedScript
		}

		return nil, nil, fmt.Errorf("lookup account: %w", err)
	}

	binding := &utxoAccountBinding{
		acctStore: acctStore,
		acctNum:   acctNum,
		scope:     db.KeyScope(acctStore.Scope()),
	}

	return binding, addr, nil
}

// enrichCredit produces an enriched db.UtxoInfo from one legacy credit
// plus its already-resolved account binding. The lease-set lookup is
// the only step that touches per-UTXO state outside the binding so the
// caller can compute the set once for the whole listing.
func (s *Store) enrichCredit(addrmgrNs walletdb.ReadBucket,
	credit *wtxmgr.Credit, addr btcutil.Address,
	binding *utxoAccountBinding,
	leaseSet map[wire.OutPoint]struct{}) (*db.UtxoInfo, error) {

	info := utxoInfoBase(credit)

	props, err := binding.acctStore.AccountProperties(
		addrmgrNs, binding.acctNum,
	)
	if err != nil {
		return nil, fmt.Errorf("account properties: %w", err)
	}

	imported, err := binding.acctStore.IsImportedAccount(
		addrmgrNs, binding.acctNum,
	)
	if err != nil {
		return nil, fmt.Errorf("classify account origin: %w", err)
	}

	origin := db.DerivedAccount
	if imported {
		origin = db.ImportedAccount
	}

	managedAddr, err := s.addrStore.Address(addrmgrNs, addr)
	if err != nil {
		return nil, fmt.Errorf("managed address: %w", err)
	}

	storeType, err := addresstype.FromWallet(managedAddr.AddrType())
	if err != nil {
		return nil, fmt.Errorf("address type: %w", err)
	}

	info.AccountName = props.AccountName
	info.Origin = origin
	info.AddrType = storeType.Type
	info.HasScript = storeType.HasScript
	info.KeyScope = binding.scope

	if _, ok := leaseSet[credit.OutPoint]; ok {
		info.IsLocked = true
	}

	return info, nil
}

// listUTXOsInView performs the legacy UTXO scan using one walletdb view
// and populates the enriched per-row metadata (AccountName, Origin,
// AddrType, HasScript, IsLocked).
func (s *Store) listUTXOsInView(tx walletdb.ReadTx,
	query db.ListUtxosQuery, utxos *[]db.UtxoInfo) error {

	txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
	if txmgrNs == nil {
		return errMissingTxmgrNamespace
	}

	addrmgrNs := tx.ReadBucket(waddrmgr.NamespaceKey)
	if addrmgrNs == nil {
		return errMissingAddrmgrNamespace
	}

	credits, err := s.txStore.UnspentOutputsIncludingLocked(txmgrNs)
	if err != nil {
		return fmt.Errorf("list unspent outputs: %w", err)
	}

	// The credits slice already enumerates the current UTXO set, so build
	// the lease-intersection set directly from it rather than re-scanning
	// the unspent bucket via currentUTXOSet.
	current := make(map[wire.OutPoint]struct{}, len(credits))
	for i := range credits {
		current[credits[i].OutPoint] = struct{}{}
	}

	leaseSet, err := s.activeLeaseSet(txmgrNs, current)
	if err != nil {
		return err
	}

	currentHeight := s.addrStore.SyncedTo().Height
	chainParams := s.addrStore.ChainParams()

	for i := range credits {
		enriched, ok, err := s.buildListedUTXO(
			addrmgrNs, &credits[i], query, leaseSet, currentHeight,
			chainParams,
		)
		if err != nil {
			return err
		}

		if !ok {
			continue
		}

		*utxos = append(*utxos, *enriched)
	}

	return nil
}

// buildListedUTXO converts one current credit into an enriched db.UtxoInfo,
// applying the confirmation, owned-address, and account filters along the
// way. It returns ok=false for a credit that does not pass a filter so the
// caller can skip it without treating the omission as an error.
func (s *Store) buildListedUTXO(addrmgrNs walletdb.ReadBucket,
	credit *wtxmgr.Credit, query db.ListUtxosQuery,
	leaseSet map[wire.OutPoint]struct{}, currentHeight int32,
	chainParams *chaincfg.Params) (*db.UtxoInfo, bool, error) {

	if !utxoMatchesConfirmations(credit.Height, currentHeight, query) {
		return nil, false, nil
	}

	binding, addr, err := s.resolveAccountForCredit(
		addrmgrNs, credit, chainParams,
	)
	if err != nil {
		if !errors.Is(err, errUnownedScript) {
			return nil, false, err
		}

		// A credit whose script does not join to a wallet address is
		// dropped, matching the SQL backends which inner-join UTXO rows
		// against owned addresses. Such rows never surface (even with no
		// account filter).
		return nil, false, nil
	}

	accountOK, err := accountMatchesQuery(addrmgrNs, query, binding)
	if err != nil {
		return nil, false, err
	}

	if !accountOK {
		return nil, false, nil
	}

	enriched, err := s.enrichCredit(
		addrmgrNs, credit, addr, binding, leaseSet,
	)
	if err != nil {
		return nil, false, err
	}

	// The AccountName filter is applied after enrichment because resolving
	// the name requires the account-properties read that enrichCredit does.
	if query.AccountName != nil &&
		enriched.AccountName != *query.AccountName {

		return nil, false, nil
	}

	return enriched, true, nil
}

// utxoMatchesConfirmations applies the optional db.ListUtxosQuery confirmation
// filters using legacy current-height state.
func utxoMatchesConfirmations(txHeight int32, currentHeight int32,
	query db.ListUtxosQuery) bool {

	confs := calcConfs(txHeight, currentHeight)

	if query.MinConfs != nil && confs < *query.MinConfs {
		return false
	}

	if query.MaxConfs != nil && confs > *query.MaxConfs {
		return false
	}

	return true
}

// accountMatchesQuery reports whether the owning account satisfies
// the numeric Account and Scope filters in the query. The
// AccountName filter is applied separately after enrichment because
// resolving the name requires an additional account-properties read.
func accountMatchesQuery(addrmgrNs walletdb.ReadBucket,
	query db.ListUtxosQuery, binding *utxoAccountBinding) (bool, error) {

	if query.Scope != nil && binding.scope != *query.Scope {
		return false, nil
	}

	if query.Account == nil {
		return true, nil
	}

	imported, err := accountIsImported(
		addrmgrNs, binding.acctStore, binding.acctNum,
	)
	if err != nil {
		return false, err
	}

	return numericAccountMatches(
		binding.acctNum, *query.Account, imported,
	), nil
}

// accountIsImported reports whether the owning account is imported,
// using the same on-disk classifier (AccountStore.IsImportedAccount)
// that the enrichment path uses for db.UtxoInfo.Origin. This keeps the
// numeric Account filter aligned with the SQL backends, where imported
// accounts have a NULL account_number and so are never numerically
// selectable, including imported xpub/watch-only accounts that carry
// ordinary kvdb account numbers.
//
// A nil acctStore only occurs for narrow test doubles that pre-date the
// enrichment contract; production AddrStore always resolves a non-nil
// AccountStore. In that case the legacy ImportedAddrAccount
// pseudo-account is the only recognizable imported form.
func accountIsImported(addrmgrNs walletdb.ReadBucket,
	acctStore waddrmgr.AccountStore, acctNum uint32) (bool, error) {

	if acctStore == nil {
		return acctNum == waddrmgr.ImportedAddrAccount, nil
	}

	imported, err := acctStore.IsImportedAccount(addrmgrNs, acctNum)
	if err != nil {
		return false, fmt.Errorf("classify account origin: %w", err)
	}

	return imported, nil
}

// numericAccountMatches reports whether a row owned by ownerAcct
// satisfies a numeric Account filter set to wantAcct, given whether the
// owning account is imported.
//
// Imported accounts have no numeric counterpart on the SQL backends
// (their account_number column is NULL), so an imported row never
// matches a numeric filter on either backend regardless of its kvdb
// account number; such rows are selectable only via (Scope,
// AccountName). This covers both the legacy ImportedAddrAccount
// pseudo-account and imported xpub/watch-only accounts created through
// NewAccountWatchingOnly, which carry ordinary kvdb account numbers. A
// derived row matches iff its account number equals the filter.
func numericAccountMatches(ownerAcct, wantAcct uint32, imported bool) bool {
	if imported {
		return false
	}

	return ownerAcct == wantAcct
}
