// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

type Session struct {
	Wallet *Wallet
	quit   chan struct{}

	chainClient        *chain.RPCClient
	chainClientSynced  bool
	chainClientSyncMtx sync.Mutex
}

// Stop signals all wallet goroutines to shutdown.
func (s *Session) Stop() {
	select {
	case <-s.quit:
	default:
		close(s.quit)
	}
}

// ShuttingDown returns whether the wallet is currently in the process of
// shutting down or not.
func (s *Session) ShuttingDown() bool {
	select {
	case <-s.quit:
		return true
	default:
		return false
	}
}

// SynchronizingToNetwork returns whether the wallet is currently synchronizing
// with the Bitcoin network.
func (s *Session) SynchronizingToNetwork() bool {
	// At the moment, RPC is the only synchronization method.  In the
	// future, when SPV is added, a separate check will also be needed, or
	// SPV could always be enabled if RPC was not explicitly specified when
	// creating the wallet.
	return !s.ShuttingDown()
}

// ChainSynced returns whether the wallet has been attached to a chain server
// and synced up to the best block on the main chain.
func (s *Session) ChainSynced() bool {
	s.chainClientSyncMtx.Lock()
	synced := s.chainClientSynced
	s.chainClientSyncMtx.Unlock()
	return synced
}

// setChainSynced marks whether the wallet is connected to and currently in sync
// with the latest block notified by the chain server.
//
// NOTE: Due to an API limitation with rpcclient, this may return true after
// the client disconnected (and is attempting a reconnect).  This will be unknown
// until the reconnect notification is received, at which point the wallet can be
// marked out of sync again until after the next rescan completes.
func (s *Session) setChainSynced(synced bool) {
	s.chainClientSyncMtx.Lock()
	s.chainClientSynced = synced
	s.chainClientSyncMtx.Unlock()
}

func (s *Session) ChainClient() *chain.RPCClient {
	return s.chainClient
}

// syncWithChain brings the wallet up to date with the current chain server
// connection.  It creates a rescan request and blocks until the rescan has
// finished.
//
func (s *Session) syncWithChain() error {
	// Request notifications for connected and disconnected blocks.
	//
	// TODO(jrick): Either request this notification only once, or when
	// rpcclient is modified to allow some notification request to not
	// automatically resent on reconnect, include the notifyblocks request
	// as well.  I am leaning towards allowing off all rpcclient
	// notification re-registrations, in which case the code here should be
	// left as is.
	err := s.chainClient.NotifyBlocks()
	if err != nil {
		return err
	}

	// Request notifications for transactions sending to all wallet
	// addresses.
	addrs, unspent, err := s.Wallet.activeData()
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
		hash, height, err := s.chainClient.GetBestBlock()
		if err != nil {
			return err
		}
		return s.Wallet.Manager.SetSyncedTo(&waddrmgr.BlockStamp{
			Hash:   *hash,
			Height: height,
		})
	}

	// Compare previously-seen blocks against the chain server.  If any of
	// these blocks no longer exist, rollback all of the missing blocks
	// before catching up with the rescan.
	iter := s.Wallet.Manager.NewIterateRecentBlocks()
	rollback := iter == nil
	syncBlock := waddrmgr.BlockStamp{
		Hash:   *s.Wallet.chainParams.GenesisHash,
		Height: 0,
	}
	for cont := iter != nil; cont; cont = iter.Prev() {
		bs := iter.BlockStamp()
		log.Debugf("Checking for previous saved block with height %v hash %v",
			bs.Height, bs.Hash)
		_, err = s.chainClient.GetBlock(&bs.Hash)
		if err != nil {
			rollback = true
			continue
		}

		log.Debug("Found matching block.")
		syncBlock = bs
		break
	}
	if rollback {
		err = s.Wallet.Manager.SetSyncedTo(&syncBlock)
		if err != nil {
			return err
		}
		// Rollback unconfirms transactions at and beyond the passed
		// height, so add one to the new synced-to height to prevent
		// unconfirming txs from the synced-to block.
		err = s.Wallet.TxStore.Rollback(syncBlock.Height + 1)
		if err != nil {
			return err
		}
	}

	return s.Rescan(addrs, unspent)
}

type (
	createTxRequest struct {
		account uint32
		outputs []*wire.TxOut
		minconf int32
		resp    chan createTxResponse
	}
	createTxResponse struct {
		tx  *txauthor.AuthoredTx
		err error
	}
)

// txCreator is responsible for the input selection and creation of
// transactions.  These functions are the responsibility of this method
// (designed to be run as its own goroutine) since input selection must be
// serialized, or else it is possible to create double spends by choosing the
// same inputs for multiple transactions.  Along with input selection, this
// method is also responsible for the signing of transactions, since we don't
// want to end up in a situation where we run out of inputs as multiple
// transactions are being created.  In this situation, it would then be possible
// for both requests, rather than just one, to fail due to not enough available
// inputs.
func (s *Session) txCreator() {
out:
	for {
		select {
		case txr := <-s.Wallet.createTxRequests:
			tx, err := s.txToOutputs(txr.outputs, txr.account, txr.minconf)
			txr.resp <- createTxResponse{tx, err}

		case <-s.quit:
			break out
		}
	}

	s.Wallet.wg.Done()
}

// GetTransactions returns transaction results between a starting and ending
// block.  Blocks in the block range may be specified by either a height or a
// hash.
//
// Because this is a possibly lenghtly operation, a cancel channel is provided
// to cancel the task.  If this channel unblocks, the results created thus far
// will be returned.
//
// Transaction results are organized by blocks in ascending order and unmined
// transactions in an unspecified order.  Mined transactions are saved in a
// Block structure which records properties about the block.
func (s *Session) GetTransactions(startBlock, endBlock *BlockIdentifier, cancel <-chan struct{}) (*GetTransactionsResult, error) {
	var start, end int32 = 0, -1

	// TODO: Fetching block heights by their hashes is inherently racy
	// because not all block headers are saved but when they are for SPV the
	// db can be queried directly without this.
	var startResp, endResp rpcclient.FutureGetBlockVerboseResult
	if startBlock != nil {
		if startBlock.hash == nil {
			start = startBlock.height
		} else {
			if s.chainClient == nil {
				return nil, errors.New("no chain server client")
			}
			startResp = s.chainClient.GetBlockVerboseAsync(startBlock.hash)
		}
	}
	if endBlock != nil {
		if endBlock.hash == nil {
			end = endBlock.height
		} else {
			if s.chainClient == nil {
				return nil, errors.New("no chain server client")
			}
			endResp = s.chainClient.GetBlockVerboseAsync(endBlock.hash)
		}
	}
	if startResp != nil {
		resp, err := startResp.Receive()
		if err != nil {
			return nil, err
		}
		start = int32(resp.Height)
	}
	if endResp != nil {
		resp, err := endResp.Receive()
		if err != nil {
			return nil, err
		}
		end = int32(resp.Height)
	}

	var res GetTransactionsResult
	err := s.Wallet.TxStore.RangeTransactions(start, end, func(details []wtxmgr.TxDetails) (bool, error) {
		// TODO: probably should make RangeTransactions not reuse the
		// details backing array memory.
		dets := make([]wtxmgr.TxDetails, len(details))
		copy(dets, details)
		details = dets

		txs := make([]TransactionSummary, 0, len(details))
		for i := range details {
			txs = append(txs, makeTxSummary(s.Wallet, &details[i]))
		}

		if details[0].Block.Height != -1 {
			blockHash := details[0].Block.Hash
			res.MinedTransactions = append(res.MinedTransactions, Block{
				Hash:         &blockHash,
				Height:       details[0].Block.Height,
				Timestamp:    details[0].Block.Time.Unix(),
				Transactions: txs,
			})
		} else {
			res.UnminedTransactions = txs
		}

		select {
		case <-cancel:
			return true, nil
		default:
			return false, nil
		}
	})
	return &res, err
}

// ResendUnminedTxs iterates through all transactions that spend from wallet
// credits that are not known to have been mined into a block, and attempts
// to send each to the chain server for relay.
func (s *Session) ResendUnminedTxs() {
	txs, err := s.Wallet.TxStore.UnminedTxs()
	if err != nil {
		log.Errorf("Cannot load unmined transactions for resending: %v", err)
		return
	}
	for _, tx := range txs {
		resp, err := s.chainClient.SendRawTransaction(tx, false)
		if err != nil {
			// TODO(jrick): Check error for if this tx is a double spend,
			// remove it if so.
			log.Debugf("Could not resend transaction %v: %v",
				tx.TxHash(), err)
			continue
		}
		log.Debugf("Resent unmined transaction %v", resp)
	}
}

// NewAddress returns the next external chained address for a wallet.
func (s *Session) NewAddress(account uint32) (btcutil.Address, error) {
	// Get next address from wallet.
	addrs, err := s.Wallet.Manager.NextExternalAddresses(account, 1)
	if err != nil {
		return nil, err
	}

	// Request updates from btcd for new transactions sent to this address.
	utilAddrs := make([]btcutil.Address, len(addrs))
	for i, addr := range addrs {
		utilAddrs[i] = addr.Address()
	}

	err = s.chainClient.NotifyReceived(utilAddrs)
	if err != nil {
		return nil, err
	}

	props, err := s.Wallet.Manager.AccountProperties(account)
	if err != nil {
		log.Errorf("Cannot fetch account properties for notification "+
			"after deriving next external address: %v", err)
	} else {
		s.Wallet.NtfnServer.notifyAccountProperties(props)
	}

	return utilAddrs[0], nil
}

// NewChangeAddress returns a new change address for a wallet.
func (s *Session) NewChangeAddress(account uint32) (btcutil.Address, error) {
	// Get next chained change address from wallet for account.
	addrs, err := s.Wallet.Manager.NextInternalAddresses(account, 1)
	if err != nil {
		return nil, err
	}

	// Request updates from btcd for new transactions sent to this address.
	utilAddrs := make([]btcutil.Address, len(addrs))
	for i, addr := range addrs {
		utilAddrs[i] = addr.Address()
	}

	err = s.chainClient.NotifyReceived(utilAddrs)
	if err != nil {
		return nil, err
	}

	return utilAddrs[0], nil
}

// CurrentAddress gets the most recently requested Bitcoin payment address
// from a wallet.  If the address has already been used (there is at least
// one transaction spending to it in the blockchain or btcd mempool), the next
// chained address is returned.
func (s *Session) CurrentAddress(account uint32) (btcutil.Address, error) {
	addr, err := s.Wallet.Manager.LastExternalAddress(account)
	if err != nil {
		// If no address exists yet, create the first external address
		if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
			return s.NewAddress(account)
		}
		return nil, err
	}

	// Get next chained address if the last one has already been used.
	used, err := addr.Used()
	if err != nil {
		return nil, err
	}
	if used {
		return s.NewAddress(account)
	}

	return addr.Address(), nil
}

// SendOutputs creates and sends payment transactions. It returns the
// transaction hash upon success.
func (s *Session) SendOutputs(outputs []*wire.TxOut, account uint32,
	minconf int32) (*chainhash.Hash, error) {

	var err error
	relayFee := s.Wallet.RelayFee()
	for _, output := range outputs {
		err = txrules.CheckOutput(output, relayFee)
		if err != nil {
			return nil, err
		}
	}

	// Create transaction, replying with an error if the creation
	// was not successful.
	createdTx, err := s.Wallet.CreateSimpleTx(account, outputs, minconf)
	if err != nil {
		return nil, err
	}

	// Create transaction record and insert into the db.
	rec, err := wtxmgr.NewTxRecordFromMsgTx(createdTx.Tx, time.Now())
	if err != nil {
		log.Errorf("Cannot create record for created transaction: %v", err)
		return nil, err
	}
	err = s.Wallet.TxStore.InsertTx(rec, nil)
	if err != nil {
		log.Errorf("Error adding sent tx history: %v", err)
		return nil, err
	}

	if createdTx.ChangeIndex >= 0 {
		err = s.Wallet.TxStore.AddCredit(rec, nil, uint32(createdTx.ChangeIndex), true)
		if err != nil {
			log.Errorf("Error adding change address for sent "+
				"tx: %v", err)
			return nil, err
		}
	}

	// TODO: The record already has the serialized tx, so no need to
	// serialize it again.
	return s.chainClient.SendRawTransaction(&rec.MsgTx, false)
}

// PublishTransaction sends the transaction to the consensus RPC server so it
// can be propigated to other nodes and eventually mined.
//
// This function is unstable and will be removed once syncing code is moved out
// of the wallet.
func (s *Session) PublishTransaction(tx *wire.MsgTx) error {
	_, err := s.chainClient.SendRawTransaction(tx, false)
	return err
}
