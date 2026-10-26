package wallet

import (
	"context"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
)

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

// recordOutpoint adds an association while the caller holds mu. Both native
// registration and queued-parent learning retain the same additive ownership.
func (r *watchRegistry) recordOutpoint(id uint32, point wire.OutPoint) {
	if r.outpoints[point] == nil {
		r.outpoints[point] = make(map[uint32]struct{})
	}

	r.outpoints[point][id] = struct{}{}
}
