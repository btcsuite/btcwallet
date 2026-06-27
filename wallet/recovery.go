package wallet

import (
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// RecoveryState manages the initialization and lookup of ScopeRecoveryStates
// for any actively used key scopes.
//
// In order to ensure that all addresses are properly recovered, the window
// should be sized as the sum of maximum possible inter-block and intra-block
// gap between used addresses of a particular branch.
//
// These are defined as:
//   - Inter-Block Gap: The maximum difference between the derived child indexes
//     of the last addresses used in any block and the next address consumed
//     by a later block.
//   - Intra-Block Gap: The maximum difference between the derived child indexes
//     of the first address used in any block and the last address used in the
//     same block.
type RecoveryState struct {
	// recoveryWindow defines the key-derivation lookahead used when
	// attempting to recover the set of used addresses. This value will be
	// used to instantiate a new RecoveryState for each requested scope.
	recoveryWindow uint32

	// scopes maintains a map of each requested key scope to its active
	// RecoveryState. Used for legacy compatibility.
	//
	// TODO(yy): Deprecated, remove.
	scopes map[waddrmgr.KeyScope]*ScopeRecoveryState

	// branchStates maintains the recovery state for every branch (scope +
	// account + branch). This is the source of truth.
	branchStates map[waddrmgr.BranchScope]*BranchRecoveryState

	// watchedOutPoints contains the set of all outpoints known to the
	// wallet. This is updated iteratively as new outpoints are found during
	// a rescan.
	//
	// TODO(yy): Deprecated, remove.
	watchedOutPoints map[wire.OutPoint]address.Address

	// chainParams are the parameters that describe the chain we're trying
	// to recover funds on. These are set at initialization and remain
	// constant.
	chainParams *chaincfg.Params

	// addrMgr is the address manager used to derive new keys and manage
	// account state.
	addrMgr waddrmgr.AddrStore

	// outpoints tracks unspent outpoints to detect spends. The value is
	// the PkScript of the outpoint. This map is transient, initialized by
	// InitScanState at the beginning of a batch scan and pruned by Prune()
	// at the end to manage memory.
	outpoints map[wire.OutPoint][]byte

	// addrFilters maps encoded addresses to their derivation info for
	// identifying incoming payments. This map is transient, initialized by
	// InitScanState at the beginning of a batch scan and pruned by Prune()
	// at the end to manage memory.
	addrFilters map[string]AddrEntry
}

// NewRecoveryState creates a new RecoveryState using the provided
// recoveryWindow. Each RecoveryState that is subsequently initialized for a
// particular key scope will receive the same recoveryWindow.
func NewRecoveryState(recoveryWindow uint32,
	chainParams *chaincfg.Params,
	addrMgr waddrmgr.AddrStore) *RecoveryState {

	return &RecoveryState{
		recoveryWindow: recoveryWindow,
		scopes: make(
			map[waddrmgr.KeyScope]*ScopeRecoveryState,
		),
		branchStates: make(
			map[waddrmgr.BranchScope]*BranchRecoveryState,
		),
		watchedOutPoints: make(map[wire.OutPoint]address.Address),
		chainParams:      chainParams,
		addrMgr:          addrMgr,
	}
}

// StateForScope returns the recovery state for the default account of the
// provided key scope. This exists for backward compatibility with legacy
// recovery logic which only supports the default account.
//
// TODO(yy): Deprecated, remove.
func (rs *RecoveryState) StateForScope(
	keyScope waddrmgr.KeyScope) *ScopeRecoveryState {

	// If the account recovery state already exists, return it.
	if scopeState, ok := rs.scopes[keyScope]; ok {
		return scopeState
	}

	// Otherwise, initialize the recovery state for this scope with the
	// chosen recovery window.
	rs.scopes[keyScope] = NewScopeRecoveryState(rs.recoveryWindow)

	return rs.scopes[keyScope]
}

// WatchedOutPoints returns the global set of outpoints that are known to belong
// to the wallet during recovery.
//
// TODO(yy): Deprecated, remove.
func (rs *RecoveryState) WatchedOutPoints() map[wire.OutPoint]address.Address {
	return rs.watchedOutPoints
}

// AddWatchedOutPoint updates the recovery state's set of known outpoints that
// we will monitor for spends during recovery.
//
// TODO(yy): Deprecated, remove.
func (rs *RecoveryState) AddWatchedOutPoint(outPoint *wire.OutPoint,
	addr address.Address) {

	rs.watchedOutPoints[*outPoint] = addr
}

// String returns a summary of the recovery state.
func (rs *RecoveryState) String() string {
	return fmt.Sprintf("RecoveryState(addrs=%d, outpoints=%d)",
		len(rs.addrFilters), len(rs.outpoints))
}

// Empty returns true if there are no addresses or outpoints to watch.
func (rs *RecoveryState) Empty() bool {
	return len(rs.addrFilters) == 0 && len(rs.outpoints) == 0
}

// WatchListSize returns the total number of items (addresses + outpoints)
// in the current watchlist.
func (rs *RecoveryState) WatchListSize() int {
	return len(rs.addrFilters) + len(rs.outpoints)
}

// GetBranchState returns the recovery state for the provided branch scope.
// It acts as the source of truth for branch states by either retrieving an
// existing in-memory BranchRecoveryState for the given `bs` (branch scope)
// or creating a new one if it doesn't already exist.
//
// When a new state is created, it fetches the appropriate AccountStore (key
// manager) from the Address Manager. This ensures that the BranchRecoveryState
// is correctly linked to its derivation logic and maintains a consistent,
// up-to-date view of the branch's lookahead horizon and derived addresses
// throughout the recovery process. This centralization prevents redundant
// state creation and ensures all recovery operations for a specific branch
// operate on the same instance.
func (rs *RecoveryState) GetBranchState(bs waddrmgr.BranchScope) (
	*BranchRecoveryState, error) {

	if s, ok := rs.branchStates[bs]; ok {
		return s, nil
	}

	// We assume the scope is valid and active if we are requesting state
	// for it.
	var mgr waddrmgr.AccountStore
	if rs.addrMgr != nil {
		var err error

		mgr, err = rs.addrMgr.FetchScopedKeyManager(bs.Scope)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch manager for "+
				"scope %v: %w", bs.Scope, err)
		}
	}

	s := NewBranchRecoveryState(rs.recoveryWindow, mgr)
	rs.branchStates[bs] = s

	return s, nil
}

// AddrEntry holds the derivation info for an address to support
// reverse lookups during filtering.
type AddrEntry struct {
	// Address is the cached address for script generation.
	Address address.Address

	// Credit records the transaction credit metadata (index, change)
	// when this address matches a transaction output.
	Credit wtxmgr.CreditEntry

	// IsLookahead indicates whether this address is part of the current
	// lookahead window. If true, finding this address *in the block*
	// triggers horizon expansion.
	IsLookahead bool

	// addrScope identifies the specific address derivation path.
	addrScope waddrmgr.AddrScope
}

// Initialize prepares the recovery state for a new batch scan by syncing
// horizons, populating history/UTXOs, and expanding the lookahead window.
//
// TODO(yy): Once RecoveryManager is removed, privatize this method and call
// it directly from NewRecoveryState to simplify the initialization flow.
func (rs *RecoveryState) Initialize(accounts []*waddrmgr.AccountProperties,
	initialAddrs []address.Address, initialUnspent []wtxmgr.Credit) error {

	rs.outpoints = make(map[wire.OutPoint][]byte)
	rs.addrFilters = make(map[string]AddrEntry)

	// 1. Sync Horizons & Derive Lookahead.
	//
	// We iterate over all accounts loaded from the database (horizonData)
	// to sync the recovery horizons. This loop will also populate the
	// rs.branchStates map with all active branches. For each branch, it
	// will derive addresses up to the recovery window size and add them to
	// rs.addrFilters.
	for _, props := range accounts {
		err := rs.initAccountState(props)
		if err != nil {
			return err
		}
	}

	// 2. Populate the filter with "History" - addresses that are already
	// active/used in the wallet database. We monitor these to detect any
	// new payments to existing keys.
	for _, addr := range initialAddrs {
		addrStr := addr.EncodeAddress()

		entry := AddrEntry{
			Address:     addr,
			IsLookahead: false,
		}
		rs.addrFilters[addrStr] = entry
	}

	// 3. Populate the set of unspent outputs (UTXOs) to watch. We monitor
	// these outpoints to detect when they are spent by a transaction in a
	// block.
	for _, u := range initialUnspent {
		rs.outpoints[u.OutPoint] = u.PkScript
	}

	return nil
}

// BuildCFilterData constructs the list of scripts (addresses + outpoints) used
// for CFilter matching. This is an expensive operation (script derivation) and
// should only be called when filters are actually used.
func (rs *RecoveryState) BuildCFilterData() ([][]byte, error) {
	// Calculate size: addrFilters (Addrs) + outpoints (UTXOs).
	size := len(rs.addrFilters) + len(rs.outpoints)
	watchList := make([][]byte, 0, size)

	for _, entry := range rs.addrFilters {
		script, err := txscript.PayToAddrScript(entry.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to gen script for %s: "+
				"%w", entry.Address, err)
		}

		watchList = append(watchList, script)
	}

	for _, script := range rs.outpoints {
		watchList = append(watchList, script)
	}

	return watchList, nil
}

// TxEntry pairs a transaction record with its extracted address entries.
type TxEntry struct {
	Rec     *wtxmgr.TxRecord
	Entries []AddrEntry
}

// TxEntries is a list of matched transaction entries, preserving the order of
// transactions.
type TxEntries []TxEntry

// BlockProcessResult contains the results of processing a block for recovery.
type BlockProcessResult struct {
	// RelevantTxs is a slice of transactions within the block that are
	// relevant to the wallet (i.e., they spend one of our watched
	// outpoints or send funds to one of our addresses).
	RelevantTxs []*btcutil.Tx

	// FoundHorizons maps the BranchScope to the highest child index found
	// in this block. This is used for persistent horizon expansion.
	FoundHorizons map[waddrmgr.BranchScope]uint32

	// RelevantOutputs holds the details of transaction outputs that
	// matched the wallet's filters. This allows efficient access to
	// derivation information without re-parsing scripts or re-fetching
	// addresses.
	RelevantOutputs TxEntries

	// Expanded indicates whether any new addresses were derived and added
	// to the address filters as a result of processing this block (i.e., a
	// lookahead horizon expansion was triggered).
	Expanded bool
}

// ProcessBlock filters a block for relevant transactions and expands the
// recovery horizons if new addresses are found. It handles the "Filter ->
// Expand -> Retry" loop internally and returns the relevant transactions,
// found horizons (for state update), relevant matches (for efficient
// ingestion), and a boolean indicating if any expansion occurred.
func (rs *RecoveryState) ProcessBlock(block *wire.MsgBlock) (
	*BlockProcessResult, error) {

	var (
		expanded        bool
		relevantTxs     []*btcutil.Tx
		foundScopes     map[waddrmgr.AddrScope]struct{}
		relevantOutputs TxEntries
		foundHorizons   map[waddrmgr.BranchScope]uint32
	)

	// A same-block lookahead rerun happens when this block pays to an
	// already-watched lookahead address and expandHorizons derives more
	// addresses before the block is filtered again. filterTx mutates
	// rs.outpoints in place during each pass, so restore the pre-block set
	// before every pass. Otherwise a spent watched outpoint deleted during
	// the first pass would be missing from the second pass, and a spend-only
	// transaction could be dropped from the final overwritten result.
	outpointsSnapshot := copyOutpointMap(rs.outpoints)

	for {
		rs.outpoints = copyOutpointMap(outpointsSnapshot)

		relevantTxs, foundScopes, relevantOutputs = rs.filterBlock(
			block,
		)

		foundHorizons = rs.reportFound(foundScopes)
		if len(foundHorizons) == 0 {
			break
		}

		expandedNow, err := rs.expandHorizons()
		if err != nil {
			return nil, fmt.Errorf("expand horizons: %w", err)
		}

		if !expandedNow {
			break
		}

		expanded = true
	}

	return &BlockProcessResult{
		RelevantTxs:     relevantTxs,
		FoundHorizons:   foundHorizons,
		RelevantOutputs: relevantOutputs,
		Expanded:        expanded,
	}, nil
}

// copyOutpointMap returns a shallow copy of the watched outpoint set.
func copyOutpointMap(src map[wire.OutPoint][]byte) map[wire.OutPoint][]byte {
	dst := make(map[wire.OutPoint][]byte, len(src))
	for op, script := range src {
		dst[op] = script
	}

	return dst
}

// initAccountState initializes the recovery state for a specific account by
// setting up branch recovery states for both external and internal branches.
// It iterates through the known address counts (from the provided account
// properties) to sync the horizons and populate the address filters with
// derived addresses up to the recovery window.
func (rs *RecoveryState) initAccountState(
	props *waddrmgr.AccountProperties) error {

	initBranch := func(branch uint32, lastKnownIndex uint32) error {
		bs := waddrmgr.BranchScope{
			Scope:   props.KeyScope,
			Account: props.AccountNumber,
			Branch:  branch,
		}

		branchState, err := rs.GetBranchState(bs)
		if err != nil {
			return err
		}

		entries, err := branchState.buildAddrFilters(bs, lastKnownIndex)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			rs.addrFilters[entry.Address.EncodeAddress()] = entry
		}

		return nil
	}

	err := initBranch(waddrmgr.ExternalBranch, props.ExternalKeyCount)
	if err != nil {
		return fmt.Errorf("derive external addrs for %s/%d': %w",
			props.KeyScope, props.AccountNumber, err)
	}

	err = initBranch(waddrmgr.InternalBranch, props.InternalKeyCount)
	if err != nil {
		return fmt.Errorf("derive internal addrs for %s/%d': %w",
			props.KeyScope, props.AccountNumber, err)
	}

	return nil
}

// reportFound updates the recovery state with any addresses found in the
// current block. It returns the set of found horizons (max index per branch).
func (rs *RecoveryState) reportFound(
	found map[waddrmgr.AddrScope]struct{}) map[waddrmgr.BranchScope]uint32 {

	foundHorizons := make(map[waddrmgr.BranchScope]uint32)

	// Group by branch and find max index.
	for addrScope := range found {
		bs := addrScope.BranchScope

		idx := addrScope.Index
		if currentMax, ok := foundHorizons[bs]; !ok ||
			idx > currentMax {

			foundHorizons[bs] = idx
		}
	}

	// Update memory state.
	for bs, maxIdx := range foundHorizons {
		state, err := rs.GetBranchState(bs)
		if err != nil {
			// This should theoretically not happen if the found
			// map was populated correctly from filters that
			// correspond to valid branch states. Log this as an
			// error for debugging.
			log.Errorf("Failed to get branch state for %v: %v", bs,
				err)

			continue
		}

		state.ReportFound(maxIdx)
	}

	return foundHorizons
}

// filterBlock checks a block for any transactions relevant to the wallet.
// It returns the relevant transactions and the set of found addresses (by
// branch scope and index).
//
// NOTE: This method mutates the recovery state's outpoints in-place by
// removing spent inputs and adding new relevant outputs. This handles
// intra-block chains correctly.
func (rs *RecoveryState) filterBlock(block *wire.MsgBlock) ([]*btcutil.Tx,
	map[waddrmgr.AddrScope]struct{}, TxEntries) {

	var relevant []*btcutil.Tx

	foundScopes := make(map[waddrmgr.AddrScope]struct{})

	var relevantOutputs TxEntries
	for _, tx := range block.Transactions {
		isRelevant, entries := rs.filterTx(tx, foundScopes)
		if isRelevant {
			relevant = append(relevant, btcutil.NewTx(tx))

			// We create a temporary record here. The timestamp
			// will be updated during commitment.
			rec, _ := wtxmgr.NewTxRecordFromMsgTx(
				tx, time.Time{},
			)

			relevantOutputs = append(relevantOutputs, TxEntry{
				Rec:     rec,
				Entries: entries,
			})
		}
	}

	return relevant, foundScopes, relevantOutputs
}

// filterTx checks a single transaction for relevance and returns any matching
// address entries.
func (rs *RecoveryState) filterTx(tx *wire.MsgTx,
	foundScopes map[waddrmgr.AddrScope]struct{}) (bool, []AddrEntry) {

	var (
		isRelevant bool
		entries    []AddrEntry
	)

	// Check if the transaction spends any of our watched outpoints. If so,
	// it's relevant (a debit).
	for _, txIn := range tx.TxIn {
		if _, ok := rs.outpoints[txIn.PreviousOutPoint]; ok {
			isRelevant = true

			delete(rs.outpoints, txIn.PreviousOutPoint)
		}
	}

	// Check if the transaction pays to any of our watched addresses. If
	// so, it's relevant (a credit).
	for i, txOut := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, rs.chainParams,
		)
		if err != nil {
			log.Debugf("Could not extract addresses from script "+
				"%x: %v", txOut.PkScript, err)

			continue
		}

		for _, a := range addrs {
			entry, ok := rs.addrFilters[a.EncodeAddress()]
			if !ok {
				continue
			}

			isRelevant = true

			if entry.IsLookahead {
				foundScopes[entry.addrScope] = struct{}{}
			}

			//nolint:gosec // Output index fits in uint32.
			idx := uint32(i)

			// Create result entry with Credit populated.
			entry.Credit.Index = idx
			entries = append(entries, entry)

			// Add new output to map immediately to catch
			// intra-block spends.
			op := wire.OutPoint{Hash: tx.TxHash(), Index: idx}
			rs.outpoints[op] = txOut.PkScript
		}
	}

	return isRelevant, entries
}

// expandHorizons ensures that the recovery state's lookahead horizon is
// sufficient by deriving new addresses if needed, and then updates the
// internal batch artifacts (addrFilters) with the lookahead addresses.
func (rs *RecoveryState) expandHorizons() (bool, error) {
	// We iterate over all active branch states and ensure their lookahead
	// windows are sufficiently expanded.
	//
	// NOTE: rs.branchStates contains the set of all active branches
	// determined at initialization. This set remains static for the
	// duration of the batch scan, even as the internal state of each
	// branch (horizon) evolves.
	var expanded bool
	for bs, branchState := range rs.branchStates {
		// Passing 0 for lastKnownIndex means we don't want to update
		// the found status based on historical data, just ensure the
		// lookahead is sufficient based on the current state.
		newEntries, err := branchState.buildAddrFilters(bs, 0)
		if err != nil {
			return false, err
		}

		if len(newEntries) > 0 {
			expanded = true

			for _, entry := range newEntries {
				rs.addrFilters[entry.Address.EncodeAddress()] =
					entry
			}
		}
	}

	return expanded, nil
}

// BranchRecoveryState maintains the required state in-order to properly
// recover addresses derived from a particular account's internal or external
// derivation branch.
//
// A branch recovery state supports operations for:
//   - Expanding the look-ahead horizon based on which indexes have been found.
//   - Registering derived addresses with indexes within the horizon.
//   - Reporting an invalid child index that falls into the horizon.
//   - Reporting that an address has been found.
//   - Retrieving all currently derived addresses for the branch.
//   - Looking up a particular address by its child index.
//
// TODO(yy): Privatize this struct and all its methods.
type BranchRecoveryState struct {
	// recoveryWindow defines the key-derivation lookahead used when
	// attempting to recover the set of addresses on this branch.
	recoveryWindow uint32

	// horizion records the highest child index watched by this branch.
	horizon uint32

	// nextUnfound maintains the child index of the successor to the highest
	// index that has been found during recovery of this branch.
	nextUnfound uint32

	// addresses is a map of child index to address for all actively watched
	// addresses belonging to this branch.
	addresses map[uint32]address.Address

	// invalidChildren records the set of child indexes that derive to
	// invalid keys.
	invalidChildren map[uint32]struct{}

	// manager is the scoped key manager used to derive addresses for this
	// branch.
	manager waddrmgr.AccountStore
}

// NewBranchRecoveryState creates a new BranchRecoveryState that can be used to
// track either the external or internal branch of an account's derivation path.
func NewBranchRecoveryState(recoveryWindow uint32,
	manager waddrmgr.AccountStore) *BranchRecoveryState {

	return &BranchRecoveryState{
		recoveryWindow:  recoveryWindow,
		addresses:       make(map[uint32]address.Address),
		invalidChildren: make(map[uint32]struct{}),
		manager:         manager,
	}
}

// ExtendHorizon returns the current horizon and the number of addresses that
// must be derived in order to maintain the desired recovery window.
func (brs *BranchRecoveryState) ExtendHorizon() (uint32, uint32) {

	// Compute the new horizon, which should surpass our last found address
	// by the recovery window.
	curHorizon := brs.horizon

	nInvalid := brs.NumInvalidInHorizon()
	minValidHorizon := brs.nextUnfound + brs.recoveryWindow + nInvalid

	// If the current horizon is sufficient, we will not have to derive any
	// new keys.
	if curHorizon >= minValidHorizon {
		return curHorizon, 0
	}

	// Otherwise, the number of addresses we should derive corresponds to
	// the delta of the two horizons, and we update our new horizon.
	delta := minValidHorizon - curHorizon
	brs.horizon = minValidHorizon

	return curHorizon, delta
}

// AddAddr adds a freshly derived address from our lookahead into the map of
// known addresses for this branch.
func (brs *BranchRecoveryState) AddAddr(index uint32, addr address.Address) {
	brs.addresses[index] = addr
}

// GetAddr returns the address derived from a given child index.
func (brs *BranchRecoveryState) GetAddr(index uint32) address.Address {
	return brs.addresses[index]
}

// ReportFound updates the last found index if the reported index exceeds the
// current value.
func (brs *BranchRecoveryState) ReportFound(index uint32) {
	if index >= brs.nextUnfound {
		brs.nextUnfound = index + 1

		// Prune all invalid child indexes that fall below our last
		// found index. We don't need to keep these entries any longer,
		// since they will not affect our required look-ahead.
		for childIndex := range brs.invalidChildren {
			if childIndex < index {
				delete(brs.invalidChildren, childIndex)
			}
		}
	}
}

// MarkInvalidChild records that a particular child index results in deriving an
// invalid address. In addition, the branch's horizon is increment, as we expect
// the caller to perform an additional derivation to replace the invalid child.
// This is used to ensure that we are always have the proper lookahead when an
// invalid child is encountered.
func (brs *BranchRecoveryState) MarkInvalidChild(index uint32) {
	brs.invalidChildren[index] = struct{}{}
	brs.horizon++
}

// NextUnfound returns the child index of the successor to the highest found
// child index.
func (brs *BranchRecoveryState) NextUnfound() uint32 {
	return brs.nextUnfound
}

// Addrs returns a map of all currently derived child indexes to the their
// corresponding addresses.
func (brs *BranchRecoveryState) Addrs() map[uint32]address.Address {
	return brs.addresses
}

// NumInvalidInHorizon computes the number of invalid child indexes that lie
// between the last found and current horizon. This informs how many additional
// indexes to derive in order to maintain the proper number of valid addresses
// within our horizon.
func (brs *BranchRecoveryState) NumInvalidInHorizon() uint32 {
	var nInvalid uint32
	for childIndex := range brs.invalidChildren {
		if brs.nextUnfound <= childIndex && childIndex < brs.horizon {
			nInvalid++
		}
	}

	return nInvalid
}

// buildAddrFilters is a helper method that maintains the address lookahead
// window for this branch. It performs two main tasks:
//  1. Syncs the branch state to the provided `lastKnownIndex` (if non-zero),
//     ensuring the state reflects what is known from disk or previous scans.
//  2. Extends the lookahead window if necessary, deriving new addresses and
//     creating filter entries for them.
//
// The returned entries are used to populate the batch-wide address filter.
func (brs *BranchRecoveryState) buildAddrFilters(bs waddrmgr.BranchScope,
	lastKnownIndex uint32) ([]AddrEntry, error) {

	// 1. Sync State.
	// If a last known index is provided (e.g., from DB during
	// initialization), we update our state to reflect that we've found
	// addresses up to this point.
	if lastKnownIndex > 0 {
		brs.ReportFound(lastKnownIndex - 1)
	}

	// 2. Compute Extension.
	// Determine the current horizon and how many new addresses are needed
	// to maintain the required lookahead window (recoveryWindow) beyond
	// the last found address.
	curHorizon, windowToDerive := brs.ExtendHorizon()
	count, childIndex := uint32(0), curHorizon

	var newEntries []AddrEntry

	// 3. Derive & Cache.
	// Iterate to derive the required number of new addresses.
	for count < windowToDerive {
		addr, _, err := brs.manager.DeriveAddr(
			bs.Account, bs.Branch, childIndex,
		)
		if err != nil {
			// Handle invalid children (rare in HD, but possible).
			// We skip the invalid index, mark it, and continue to
			// ensure we still generate the full window of *valid*
			// addresses.
			if errors.Is(err, hdkeychain.ErrInvalidChild) {
				brs.MarkInvalidChild(childIndex)
				childIndex++

				continue
			}

			return nil, fmt.Errorf("derive addr: %w", err)
		}

		// Cache the valid address in the branch state for future
		// lookups.
		brs.AddAddr(childIndex, addr)

		// Create a filter entry for the new address. This entry
		// contains the metadata (Scope, Account, Branch, Index) needed
		// to map a future hit back to this specific derivation path.
		as := waddrmgr.AddrScope{BranchScope: bs, Index: childIndex}
		entry := AddrEntry{
			Address:     addr,
			addrScope:   as,
			IsLookahead: true,
		}
		newEntries = append(newEntries, entry)

		childIndex++
		count++
	}

	return newEntries, nil
}
