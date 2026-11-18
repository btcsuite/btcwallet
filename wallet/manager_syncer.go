package wallet

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// chainRegistry lets Wallets request subscriptions from Manager without
// exposing its internal routing state or lifecycle authority.
// Wallet and its processor hold references to the same Manager through it;
// the actual watch ownership data stays in Manager's private chainSyncer.
type chainRegistry interface {
	// watchAddresses hands live address interests to Manager and performs
	// tip-based native registration.
	watchAddresses(ctx context.Context, id uint32,
		addrs []address.Address) error

	// watchOutpoints hands input-only interests to Manager for native
	// spent-output notifications.
	watchOutpoints(ctx context.Context, id uint32,
		points []*wire.OutPoint) error

	// notifyReceived preserves accepted publication's native subscription.
	notifyReceived(ctx context.Context, id uint32,
		addrs []address.Address) error

	// notifyBlocks enables the backend's existing block/control notifications.
	notifyBlocks(ctx context.Context) error
}

// chainRouter supplies live subscriptions and prepared events. Manager owns
// native delivery and each Wallet owns transaction persistence.
type chainRouter interface {
	// routeChainEvent prepares matches for the current membership snapshot.
	routeChainEvent(n any, wallets []*Wallet) map[uint32]chainEvent

	// registerWatchSet records ownership on Manager's loop before the
	// owner can route another notification.
	registerWatchSet(req watchRegistrationReq)

	// watchAddresses records recipients before native tip-based activation.
	watchAddresses(ctx context.Context, id uint32,
		addrs []address.Address) error

	// watchOutpoints records input-only recipients before native activation.
	watchOutpoints(ctx context.Context, id uint32,
		points []*wire.OutPoint) error

	// notifyReceived preserves accepted publication's native subscription.
	notifyReceived(ctx context.Context, id uint32,
		addrs []address.Address) error

	// notifyBlocks enables the backend's existing block/control notifications.
	notifyBlocks(ctx context.Context) error
}

// watchRegistrationReq owns address keys and outpoint values sent through
// Manager's unbuffered inbox, without retaining caller-owned script memory.
// Receipt commits an update that the owner applies before returning to any
// select that can route notifications, so native activation needs no reply.
type watchRegistrationReq struct {
	addresses []string
	outpoints []wire.OutPoint
	walletID  uint32
}

// chainSyncer owns live subscriptions and matching for a Manager's Wallets.
// Manager owns the native event read; this component starts no worker.
type chainSyncer struct {
	// source is borrowed from the caller; Manager never starts or stops it.
	source chain.Interface

	// params selects the network when shared output scripts are decoded.
	params *chaincfg.Params

	// watches records live ownership independently of Wallet persistence.
	watches *watchRegistry
}

// chainSyncer implements the behavior shared by Manager and its Wallets.
var _ chainRouter = (*chainSyncer)(nil)

// watchRegistry indexes observed addresses/outpoints directly to Wallet ID
// sets, so shared interests need no per-Wallet scan or second reverse index.
// Interests remain additive for its Manager's lifetime: deleting on first
// spend loses replacement/reorg spends, and an address can receive again.
type watchRegistry struct {
	// mu guards the mutable sets; no caller holds it during I/O or delivery.
	mu sync.Mutex

	// addresses maps encoded addresses to their watching Wallet IDs.
	addresses map[string]map[uint32]struct{}

	// outpoints maps declared or learned outputs to their owning Wallet IDs.
	outpoints map[wire.OutPoint]map[uint32]struct{}
}

// newChainSyncer retains the caller-owned source without starting any work.
func newChainSyncer(source chain.Interface,
	params *chaincfg.Params) *chainSyncer {

	return &chainSyncer{
		source: source,
		params: params,
		watches: &watchRegistry{
			addresses: make(map[string]map[uint32]struct{}),
			outpoints: make(map[wire.OutPoint]map[uint32]struct{}),
		},
	}
}

// registerWatchSet installs copied keys and values in one Manager owner turn.
// Routing cannot interleave with this update, even if native I/O has started.
func (s *chainSyncer) registerWatchSet(req watchRegistrationReq) {
	registry := s.watches

	for _, key := range req.addresses {
		if registry.addresses[key] == nil {
			registry.addresses[key] = make(map[uint32]struct{})
		}

		registry.addresses[key][req.walletID] = struct{}{}
	}

	for _, point := range req.outpoints {
		registry.recordOutpoint(req.walletID, point)
	}
}

// recordAddresses associates recipients before backend activation can emit
// events. The registry lock never spans backend I/O or Wallet processing.
func (r *watchRegistry) recordAddresses(id uint32, addrs []address.Address) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, addr := range addrs {
		key := addr.EncodeAddress()
		if r.addresses[key] == nil {
			r.addresses[key] = make(map[uint32]struct{})
		}

		r.addresses[key][id] = struct{}{}
	}
}

// recordOutpoints installs input ownership before the native call can emit;
// the caller performs that I/O only after this method releases the lock.
func (r *watchRegistry) recordOutpoints(id uint32, points []*wire.OutPoint) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, point := range points {
		r.recordOutpoint(id, *point)
	}
}

// registerWatches hands a declaration to Manager's loop from a Wallet caller.
// ctx belongs to that caller, not the owner; receipt commits the update before
// the owner can route subsequent notifications.
func (m *Manager) registerWatches(ctx context.Context, id uint32,
	watches watchSet) {

	req := watchRegistrationReq{
		walletID:  id,
		addresses: make([]string, len(watches.addresses)),
		outpoints: make([]wire.OutPoint, len(watches.outpoints)),
	}

	// An address can reference a PSBT script returned to its caller, who may
	// then mutate those bytes. Copy index inputs before handoff so the owner
	// reads only request-owned data while finishing this declaration.
	for i, addr := range watches.addresses {
		req.addresses[i] = addr.EncodeAddress()
	}

	for i, point := range watches.outpoints {
		req.outpoints[i] = *point
	}

	select {
	case m.walletRequests <- req:
		// Unbuffered receipt selects the owner case, which applies watches
		// inline before selecting any native event. No reply is needed.

	case <-ctx.Done():
		// Release an unaccepted send when its Wallet/caller stops waiting.

	case <-m.lifetimeCtx.Done():
		// Publication strips caller cancellation. Once the owner stops
		// receiving, release its send so Wallet can finish joined native I/O.
	}
}

// watchAddresses retains tip-based native registration and its causal errors.
// A retry always reaches the backend, even if the association already exists.
func (s *chainSyncer) watchAddresses(ctx context.Context, id uint32,
	addrs []address.Address) error {

	s.watches.recordAddresses(id, addrs)

	err := s.source.WatchAddrsFromTip(ctx, addrs)
	if err != nil {
		return fmt.Errorf("watch chain addresses: %w", err)
	}

	return nil
}

// watchOutpoints subscribes to input-only spends using native NotifySpent.
// Native subscription errors remain on the existing processor retry path.
func (s *chainSyncer) watchOutpoints(ctx context.Context, id uint32,
	points []*wire.OutPoint) error {

	s.watches.recordOutpoints(id, points)

	// Native NotifySpent cannot cancel in flight. Preflight the existing
	// worker lifetime and let its normal shutdown join any accepted RPC.
	err := ctx.Err()
	if err != nil {
		return err
	}

	err = s.source.NotifySpent(points)
	if err != nil {
		return fmt.Errorf("watch chain outpoints: %w", err)
	}

	return nil
}

// notifyReceived preserves accepted publication's native completion semantics.
// Caller cancellation cannot interrupt that API; Wallet shutdown joins it.
func (s *chainSyncer) notifyReceived(_ context.Context, id uint32,
	addrs []address.Address) error {

	s.watches.recordAddresses(id, addrs)

	// Accepted publication must finish through concurrent shutdown. The
	// native API has no cancellation; Wallet's request join owns its drain.
	err := s.source.NotifyReceived(addrs)
	if err != nil {
		return fmt.Errorf("notify received addresses: %w", err)
	}

	return nil
}

// notifyBlocks retains explicit block subscription on backends where address
// registration does not enable connected and disconnected notifications.
func (s *chainSyncer) notifyBlocks(ctx context.Context) error {
	err := ctx.Err()
	if err != nil {
		return err
	}

	err = s.source.NotifyBlocks()
	if err != nil {
		return fmt.Errorf("notify chain blocks: %w", err)
	}

	return nil
}

// chainEvent carries shared immutable preparation to the existing Wallet
// worker. Original block/control metadata is preserved for its normal handler.
type chainEvent struct {
	notification any
	matches      TxEntries
}

// routeChainEvent selects recipients without Store reads or backend calls.
// Only actual filtered blocks carry prepared block matches; a header remains
// a wakeup for catch-up to scan recovery-window addresses before checkpointing.
func (s *chainSyncer) routeChainEvent(n any,
	wallets []*Wallet) map[uint32]chainEvent {

	events := make(map[uint32]chainEvent, len(wallets))
	for _, w := range wallets {
		events[w.id] = chainEvent{notification: n}
	}

	var records []*wtxmgr.TxRecord
	switch update := n.(type) {
	case chain.RelevantTx:
		records = []*wtxmgr.TxRecord{update.TxRecord}

	case chain.FilteredBlockConnected:
		records = update.RelevantTxs

	default:
		// Headers and controls need no matching. Manager intercepts
		// disconnects for every storage backend before ordinary routing.
		return events
	}

	matches := s.prepareTxMatches(records)

	for _, match := range matches {
		recipients := s.watches.matchRecipients(match, s.params)

		// Each recipient gets one immutable entry even when several of
		// its watched inputs and outputs match the same transaction.
		for id := range recipients {
			event, active := events[id]
			if !active {
				// Create can register after this event's membership
				// snapshot, before publishing its new Wallet.
				continue
			}

			event.matches = append(event.matches, match)
			events[id] = event
		}
	}

	// Blocks advance every processor, even with no matching transactions.
	// Standalone transactions are admitted only to interested Wallets.
	if _, tx := n.(chain.RelevantTx); tx {
		maps.DeleteFunc(
			events, func(_ uint32, event chainEvent) bool {
				return len(event.matches) == 0
			},
		)
	}

	return events
}

// prepareTxMatches decodes each transaction once for shared routing while
// retaining its record and output indices for Wallet Store application.
func (s *chainSyncer) prepareTxMatches(recs []*wtxmgr.TxRecord) TxEntries {
	matches := make(TxEntries, 0, len(recs))
	for _, rec := range recs {
		entries := s.extractAddrEntries(rec.MsgTx.TxOut)
		matches = append(matches, TxEntry{
			Rec:     rec,
			Entries: entries,
		})
	}

	return matches
}

// extractAddrEntries collects all addresses from transaction outputs and
// creates initial AddrEntry objects with output indices.
func (s *chainSyncer) extractAddrEntries(txOuts []*wire.TxOut) []AddrEntry {
	var entries []AddrEntry
	for i, output := range txOuts {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, s.params,
		)
		if err != nil {
			log.Warnf("Cannot extract non-std pkScript=%x",
				output.PkScript)

			continue
		}

		for _, addr := range addrs {
			entries = append(entries, AddrEntry{
				Address: addr,
				Credit: wtxmgr.CreditEntry{
					//nolint:gosec // bounded.
					Index: uint32(i),
				},
			})
		}
	}

	return entries
}

// recordOutpoint adds an association while the caller holds mu. Both native
// registration and queued-parent learning retain the same additive ownership.
func (r *watchRegistry) recordOutpoint(id uint32, point wire.OutPoint) {
	if r.outpoints[point] == nil {
		r.outpoints[point] = make(map[uint32]struct{})
	}

	r.outpoints[point][id] = struct{}{}
}

// matchRecipients unions output owners with input address/outpoint owners,
// including spends whose funding outpoints recovery has not learned yet. It
// learns owned outputs under the lock before matching another transaction.
func (r *watchRegistry) matchRecipients(match TxEntry,
	params *chaincfg.Params) map[uint32]struct{} {

	// Recovery can register addresses before learning their outpoints.
	// Mirror native input matching without creating output credits.
	inputAddrs := make([]string, 0, len(match.Rec.MsgTx.TxIn))
	for _, input := range match.Rec.MsgTx.TxIn {
		pkScript, err := txscript.ComputePkScript(
			input.SignatureScript, input.Witness,
		)
		if err != nil {
			// Unsupported scripts still use known-outpoint matching.
			continue
		}

		addr, err := pkScript.Address(params)
		if err != nil {
			continue
		}

		inputAddrs = append(inputAddrs, addr.EncodeAddress())
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	recipients := make(map[uint32]struct{})
	for _, entry := range match.Entries {
		owners := r.addresses[entry.Address.EncodeAddress()]
		point := wire.OutPoint{
			Hash:  match.Rec.Hash,
			Index: entry.Credit.Index,
		}

		// Learn owned outputs before another record can spend them,
		// including while the parent waits in a Wallet's mailbox.
		for id := range owners {
			recipients[id] = struct{}{}
			r.recordOutpoint(id, point)
		}
	}

	for _, addr := range inputAddrs {
		for id := range r.addresses[addr] {
			recipients[id] = struct{}{}
		}
	}

	for _, input := range match.Rec.MsgTx.TxIn {
		for id := range r.outpoints[input.PreviousOutPoint] {
			recipients[id] = struct{}{}
		}
	}

	return recipients
}
