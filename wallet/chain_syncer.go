package wallet

import (
	"context"
	"errors"
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

// chainRouter supplies live subscriptions and prepared events while its caller
// owns the reader lifetime and each Wallet owns transaction persistence.
type chainRouter interface {
	// run reads the borrowed stream until cancellation or source failure.
	run(ctx context.Context,
		dispatch func(context.Context, any) error) error

	// routeChainEvent prepares matches for the current membership snapshot.
	routeChainEvent(n any, wallets []*Wallet) map[uint32]chainEvent

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

// chainSyncer owns live subscriptions and matching for a Manager's Wallets.
// Manager supplies its lifetime to the blocking reader instead of giving this
// worker independent lifecycle state.
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

// watchAddresses records ownership before delegating tip-based registration.
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

// watchOutpoints preserves input-only routing before NotifySpent can emit.
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

// notifyReceived retains publication's native subscription semantics while
// installing recipients before the backend can deliver its first event.
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
		// Headers and control events need no transaction matching. Every
		// processor retains its own catch-up and disconnect handling.
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

// run is the sole managed consumer of the borrowed backend stream. A
// closed stream is terminal; cancellation releases blocked mailbox delivery.
func (s *chainSyncer) run(ctx context.Context,
	dispatch func(context.Context, any) error) error {

	notifications := s.source.Notifications()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case n, ok := <-notifications:
			if !ok {
				return errors.New("chain notification source closed")
			}

			err := dispatch(ctx, n)
			if err != nil {
				return err
			}
		}
	}
}
