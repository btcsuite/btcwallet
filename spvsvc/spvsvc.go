package spvsvc

import (
	"fmt"
	"net"
	"time"

	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/spvsvc/spvchain"
	"github.com/btcsuite/btcwallet/wallet"
)

// SynchronizationService provides an SPV, p2p-based backend for a wallet to
// synchronize it with the network and send transactions it signs.
type SynchronizationService struct {
	wallet       *wallet.Wallet
	chainService spvchain.ChainService
}

// SynchronizationServiceOpt is the return type of functional options for
// creating a SynchronizationService object.
type SynchronizationServiceOpt func(*SynchronizationService) error

// NewSynchronizationService creates a new SynchronizationService with
// functional options.
func NewSynchronizationService(opts ...SynchronizationServiceOpt) (*SynchronizationService, error) {
	s := SynchronizationService{
		userAgentName:    defaultUserAgentName,
		userAgentVersion: defaultUserAgentVersion,
	}
	for _, opt := range opts {
		err := opt(&s)
		if err != nil {
			return nil, err
		}
	}
	return &s, nil
}

// UserAgent is a functional option to set the user agent information as it
// appears to other nodes.
func UserAgent(agentName, agentVersion string) SynchronizationServiceOpt {
	return func(s *SynchronizationService) error {
		s.userAgentName = agentName
		s.userAgentVersion = agentVersion
		return nil
	}
}

// AddrManager is a functional option to create an address manager for the
// synchronization service. It takes a string as an argument to specify the
// directory in which to store addresses.
func AddrManager(dir string) SynchronizationServiceOpt {
	return func(s *SynchronizationService) error {
		m := addrmgr.New(dir, spvLookup)
		s.addrManager = m
		return nil
	}
}

// ConnManagerOpt is the return type of functional options to create a
// connection manager for the synchronization service.
type ConnManagerOpt func(*connmgr.Config) error

// ConnManager is a functional option to create a connection manager for the
// synchronization service.
func ConnManager(opts ...ConnManagerOpt) SynchronizationServiceOpt {
	return func(s *SynchronizationService) error {
		c := connmgr.Config{
			TargetOutbound: defaultTargetOutbound,
			RetryDuration:  connectionRetryInterval,
			GetNewAddress:  s.getNewAddress,
		}
		for _, opt := range opts {
			err := opt(&c)
			if err != nil {
				return err
			}
		}
		connManager, err := connmgr.New(&c)
		if err != nil {
			return err
		}
		s.connManager = connManager
		return nil
	}
}

// TargetOutbound is a functional option to specify how many outbound
// connections should be made by the ConnManager to peers. Defaults to 8.
func TargetOutbound(target uint32) ConnManagerOpt {
	return func(c *connmgr.Config) error {
		c.TargetOutbound = target
		return nil
	}
}

// RetryDuration is a functional option to specify how long to wait before
// retrying a connection request. Defaults to 5s.
func RetryDuration(duration time.Duration) ConnManagerOpt {
	return func(c *connmgr.Config) error {
		c.RetryDuration = duration
		return nil
	}
}

func (s *SynchronizationService) getNewAddress() (net.Addr, error) {
	if s.addrManager == nil {
		return nil, log.Error("Couldn't get address for new " +
			"connection: address manager is nil.")
	}
	s.addrManager.Start()
	for tries := 0; tries < 100; tries++ {
		addr := s.addrManager.GetAddress()
		if addr == nil {
			break
		}
		// If we already have peers in this group, skip this address
		key := addrmgr.GroupKey(addr.NetAddress())
		if s.outboundGroupCount(key) != 0 {
			continue
		}
		if tries < 30 && time.Since(addr.LastAttempt()) < 10*time.Minute {
			continue
		}
		if tries < 50 && fmt.Sprintf("%d", addr.NetAddress().Port) !=
			s.wallet.ChainParams().DefaultPort {
			continue
		}
		addrString := addrmgr.NetAddressKey(addr.NetAddress())
		return addrStringToNetAddr(addrString)
	}
	return nil, log.Error("Couldn't get address for new connection: no " +
		"valid addresses known.")
}

func (s *SynchronizationService) outboundGroupCount(key string) int {
	replyChan := make(chan int)
	s.query <- getOutboundGroup{key: key, reply: replyChan}
	return <-replyChan
}

// SynchronizeWallet associates a wallet with the consensus RPC client,
// synchronizes the wallet with the latest changes to the blockchain, and
// continuously updates the wallet through RPC notifications.
//
// This function does not return without error until the wallet is synchronized
// to the current chain state.
func (s *SynchronizationService) SynchronizeWallet(w *wallet.Wallet) error {
	s.wallet = w

	s.wg.Add(3)
	go s.notificationQueueHandler()
	go s.processQueuedNotifications()
	go s.queryHandler()

	return s.syncWithNetwork(w)
}

func (s *SynchronizationService) queryHandler() {

}

func (s *SynchronizationService) processQueuedNotifications() {
	for n := range s.dequeueNotification {
		var err error
	notificationSwitch:
		switch n := n.(type) {
		case *wire.MsgBlock:
			if n.BlockHash().String() != "" {
				break notificationSwitch
			}
		case *wire.MsgHeaders:
		case *wire.MsgInv:
		case *wire.MsgReject:
		}

		if err != nil {
			log.Errorf("Cannot handle peer notification: %v", err)
		}
	}
	s.wg.Done()
}

// syncWithNetwork brings the wallet up to date with the current chain server
// connection.  It creates a rescan request and blocks until the rescan has
// finished.
func (s *SynchronizationService) syncWithNetwork(w *wallet.Wallet) error {
	/*chainClient := s.rpcClient

	// Request notifications for connected and disconnected blocks.
	//
	// TODO(jrick): Either request this notification only once, or when
	// btcrpcclient is modified to allow some notification request to not
	// automatically resent on reconnect, include the notifyblocks request
	// as well.  I am leaning towards allowing off all btcrpcclient
	// notification re-registrations, in which case the code here should be
	// left as is.
	err := chainClient.NotifyBlocks()
	if err != nil {
		return err
	}

	// Request notifications for transactions sending to all wallet
	// addresses.
	addrs, unspent, err := w.ActiveData()
	if err != nil {
		return err
	}

	// TODO(jrick): How should this handle a synced height earlier than
	// the chain server best block?

	// When no addresses have been generated for the wallet, the rescan can
	// be skipped.
	//
	// TODO: This is only correct because activeData above returns all
	// addresses ever created, including those that don't need to be watched
	// anymore.  This code should be updated when this assumption is no
	// longer true, but worst case would result in an unnecessary rescan.
	if len(addrs) == 0 && len(unspent) == 0 {
		// TODO: It would be ideal if on initial sync wallet saved the
		// last several recent blocks rather than just one.  This would
		// avoid a full rescan for a one block reorg of the current
		// chain tip.
		hash, height, err := chainClient.GetBestBlock()
		if err != nil {
			return err
		}
		return w.Manager.SetSyncedTo(&waddrmgr.BlockStamp{
			Hash:   *hash,
			Height: height,
		})
	}

	// Compare previously-seen blocks against the chain server.  If any of
	// these blocks no longer exist, rollback all of the missing blocks
	// before catching up with the rescan.
	iter := w.Manager.NewIterateRecentBlocks()
	rollback := iter == nil
	syncBlock := waddrmgr.BlockStamp{
		Hash:   *w.ChainParams().GenesisHash,
		Height: 0,
	}
	for cont := iter != nil; cont; cont = iter.Prev() {
		bs := iter.BlockStamp()
		log.Debugf("Checking for previous saved block with height %v hash %v",
			bs.Height, bs.Hash)
		_, err = chainClient.GetBlock(&bs.Hash)
		if err != nil {
			rollback = true
			continue
		}

		log.Debug("Found matching block.")
		syncBlock = bs
		break
	}
	if rollback {
		err = w.Manager.SetSyncedTo(&syncBlock)
		if err != nil {
			return err
		}
		// Rollback unconfirms transactions at and beyond the passed
		// height, so add one to the new synced-to height to prevent
		// unconfirming txs from the synced-to block.
		err = w.TxStore.Rollback(syncBlock.Height + 1)
		if err != nil {
			return err
		}
	}

	return s.initialRescan(addrs, unspent, w.Manager.SyncedTo()) */
	return nil
}
