/*
 * Copyright (c) 2013 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"github.com/conformal/btcws"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	// ErrNoWallet describes an error where a wallet does not exist and
	// must be created first.
	ErrNoWallet = errors.New("wallet file does not exist")

	// ErrNoUtxos describes an error where the wallet file was successfully
	// read, but the UTXO file was not.  To properly handle this error,
	// a rescan should be done since the wallet creation block.
	ErrNoUtxos = errors.New("utxo file cannot be read")

	// ErrNoTxs describes an error where the wallet and UTXO files were
	// successfully read, but the TX history file was not.  It is up to
	// the caller whether this necessitates a rescan or not.
	ErrNoTxs = errors.New("tx file cannot be read")

	cfg *config

	curBlock = struct {
		sync.RWMutex
		wallet.BlockStamp
	}{
		BlockStamp: wallet.BlockStamp{
			Height: int32(btcutil.BlockHeightUnknown),
		},
	}

	wallets = NewBtcWalletStore()
)

// BtcWallet is a structure containing all the components for a
// complete wallet.  It contains the Armory-style wallet (to store
// addresses and keys), and tx and utxo data stores, along with locks
// to prevent against incorrect multiple access.
type BtcWallet struct {
	*wallet.Wallet
	mtx               sync.RWMutex
	name              string
	dirty             bool
	fullRescan        bool
	NewBlockTxSeqN    uint64
	SpentOutpointSeqN uint64
	UtxoStore         struct {
		sync.RWMutex
		dirty bool
		s     tx.UtxoStore
	}
	TxStore struct {
		sync.RWMutex
		dirty bool
		s     tx.TxStore
	}
}

// BtcWalletStore stores all wallets currently being handled by
// btcwallet.  Wallet are stored in a map with the account name as the
// key.  A RWMutex is used to protect against incorrect concurrent
// access.
type BtcWalletStore struct {
	sync.Mutex
	m map[string]*BtcWallet
}

// NewBtcWalletStore returns an initialized and empty BtcWalletStore.
func NewBtcWalletStore() *BtcWalletStore {
	return &BtcWalletStore{
		m: make(map[string]*BtcWallet),
	}
}

// Rollback rolls back each BtcWallet saved in the store.
//
// TODO(jrick): This must also roll back the UTXO and TX stores, and notify
// all wallets of new account balances.
func (s *BtcWalletStore) Rollback(height int32, hash *btcwire.ShaHash) {
	for _, w := range s.m {
		w.Rollback(height, hash)
	}
}

// Rollback reverts each stored BtcWallet to a state before the block
// with the passed chainheight and block hash was connected to the main
// chain.  This is used to remove transactions and utxos for each wallet
// that occured on a chain no longer considered to be the main chain.
func (w *BtcWallet) Rollback(height int32, hash *btcwire.ShaHash) {
	w.UtxoStore.Lock()
	w.UtxoStore.dirty = w.UtxoStore.dirty || w.UtxoStore.s.Rollback(height, hash)
	w.UtxoStore.Unlock()

	w.TxStore.Lock()
	w.TxStore.dirty = w.TxStore.dirty || w.TxStore.s.Rollback(height, hash)
	w.TxStore.Unlock()

	if err := w.writeDirtyToDisk(); err != nil {
		log.Errorf("cannot sync dirty wallet: %v", err)
	}
}

// walletdir returns the directory path which holds the wallet, utxo,
// and tx files.
func walletdir(cfg *config, account string) string {
	var wname string
	if account == "" {
		wname = "btcwallet"
	} else {
		wname = fmt.Sprintf("btcwallet-%s", account)
	}

	return filepath.Join(cfg.DataDir, wname)
}

// OpenWallet opens a wallet described by account in the data
// directory specified by cfg.  If the wallet does not exist, ErrNoWallet
// is returned as an error.
//
// Wallets opened from this function are not set to track against a
// btcd connection.
func OpenWallet(cfg *config, account string) (*BtcWallet, error) {
	wdir := walletdir(cfg, account)
	fi, err := os.Stat(wdir)
	if err != nil {
		if os.IsNotExist(err) {
			// Attempt data directory creation
			if err = os.MkdirAll(wdir, 0700); err != nil {
				return nil, fmt.Errorf("cannot create data directory: %s", err)
			}
		} else {
			return nil, fmt.Errorf("error checking data directory: %s", err)
		}
	} else {
		if !fi.IsDir() {
			return nil, fmt.Errorf("data directory '%s' is not a directory", cfg.DataDir)
		}
	}

	wfilepath := filepath.Join(wdir, "wallet.bin")
	utxofilepath := filepath.Join(wdir, "utxo.bin")
	txfilepath := filepath.Join(wdir, "tx.bin")
	var wfile, utxofile, txfile *os.File

	// Read wallet file.
	if wfile, err = os.Open(wfilepath); err != nil {
		if os.IsNotExist(err) {
			// Must create and save wallet first.
			return nil, ErrNoWallet
		}
		return nil, fmt.Errorf("cannot open wallet file: %s", err)
	}
	defer wfile.Close()

	wlt := new(wallet.Wallet)
	if _, err = wlt.ReadFrom(wfile); err != nil {
		return nil, fmt.Errorf("cannot read wallet: %s", err)
	}

	w := &BtcWallet{
		Wallet: wlt,
		name:   account,
	}

	// Read utxo file.  If this fails, return a ErrNoUtxos error so a
	// rescan can be done since the wallet creation block.
	var utxos tx.UtxoStore
	if utxofile, err = os.Open(utxofilepath); err != nil {
		log.Errorf("cannot open utxo file: %s", err)
		return w, ErrNoUtxos
	}
	defer utxofile.Close()
	if _, err = utxos.ReadFrom(utxofile); err != nil {
		log.Errorf("cannot read utxo file: %s", err)
		return w, ErrNoUtxos
	}
	w.UtxoStore.s = utxos

	// Read tx file.  If this fails, return a ErrNoTxs error and let
	// the caller decide if a rescan is necessary.
	if txfile, err = os.Open(txfilepath); err != nil {
		log.Errorf("cannot open tx file: %s", err)
		return w, ErrNoTxs
	}
	defer txfile.Close()
	var txs tx.TxStore
	if _, err = txs.ReadFrom(txfile); err != nil {
		log.Errorf("cannot read tx file: %s", err)
		return w, ErrNoTxs
	}
	w.TxStore.s = txs

	return w, nil
}

// GetCurBlock returns the blockchain height and SHA hash of the most
// recently seen block.  If no blocks have been seen since btcd has
// connected, btcd is queried for the current block height and hash.
func GetCurBlock() (bs wallet.BlockStamp, err error) {
	curBlock.RLock()
	bs = curBlock.BlockStamp
	curBlock.RUnlock()
	if bs.Height != int32(btcutil.BlockHeightUnknown) {
		return bs, nil
	}

	// This is a hack and may result in races, but we need to make
	// sure that btcd is connected and sending a message will succeed,
	// or this will block forever. A better solution is to return an
	// error to the reply handler immediately if btcd is disconnected.
	if !btcdConnected.b {
		return wallet.BlockStamp{
			Height: int32(btcutil.BlockHeightUnknown),
		}, errors.New("current block unavailable")
	}

	n := <-NewJSONID
	cmd := btcws.NewGetBestBlockCmd(fmt.Sprintf("btcwallet(%v)", n))
	mcmd, err := cmd.MarshalJSON()
	if err != nil {
		return wallet.BlockStamp{
			Height: int32(btcutil.BlockHeightUnknown),
		}, errors.New("cannot ask for best block")
	}

	c := make(chan *struct {
		hash   *btcwire.ShaHash
		height int32
	})

	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}, e *btcjson.Error) bool {
		if e != nil {
			c <- nil
			return true
		}
		m, ok := result.(map[string]interface{})
		if !ok {
			c <- nil
			return true
		}
		hashBE, ok := m["hash"].(string)
		if !ok {
			c <- nil
			return true
		}
		hash, err := btcwire.NewShaHashFromStr(hashBE)
		if err != nil {
			c <- nil
			return true
		}
		fheight, ok := m["height"].(float64)
		if !ok {
			c <- nil
			return true
		}
		c <- &struct {
			hash   *btcwire.ShaHash
			height int32
		}{
			hash:   hash,
			height: int32(fheight),
		}
		return true
	}
	replyHandlers.Unlock()

	// send message
	btcdMsgs <- mcmd

	// Block until reply is ready.
	if reply := <-c; reply != nil {
		curBlock.Lock()
		if reply.height > curBlock.BlockStamp.Height {
			bs = wallet.BlockStamp{
				Height: reply.height,
				Hash:   *reply.hash,
			}
			curBlock.BlockStamp = bs
		}
		curBlock.Unlock()
		return bs, nil
	}

	return wallet.BlockStamp{
		Height: int32(btcutil.BlockHeightUnknown),
	}, errors.New("current block unavailable")
}

// CalculateBalance sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance as a
// float64.
//
// If confirmations is 0, all UTXOs, even those not present in a
// block (height -1), will be used to get the balance.  Otherwise,
// a UTXO must be in a block.  If confirmations is 1 or greater,
// the balance will be calculated based on how many how many blocks
// include a UTXO.
func (w *BtcWallet) CalculateBalance(confirms int) float64 {
	var bal uint64 // Measured in satoshi

	bs, err := GetCurBlock()
	if bs.Height == int32(btcutil.BlockHeightUnknown) || err != nil {
		return 0.
	}

	w.UtxoStore.RLock()
	for _, u := range w.UtxoStore.s {
		// Utxos not yet in blocks (height -1) should only be
		// added if confirmations is 0.
		if confirms == 0 || (u.Height != -1 && int(bs.Height-u.Height+1) >= confirms) {
			bal += u.Amt
		}
	}
	w.UtxoStore.RUnlock()
	return float64(bal) / float64(btcutil.SatoshiPerBitcoin)
}

// Track requests btcd to send notifications of new transactions for
// each address stored in a wallet and sets up a new reply handler for
// these notifications.
func (w *BtcWallet) Track() {
	n := <-NewJSONID
	w.mtx.Lock()
	w.NewBlockTxSeqN = n
	w.mtx.Unlock()

	replyHandlers.Lock()
	replyHandlers.m[n] = w.newBlockTxOutHandler
	replyHandlers.Unlock()
	for _, addr := range w.GetActiveAddresses() {
		w.ReqNewTxsForAddress(addr.Address)
	}

	n = <-NewJSONID
	w.mtx.Lock()
	w.SpentOutpointSeqN = n
	w.mtx.Unlock()

	replyHandlers.Lock()
	replyHandlers.m[n] = w.spentUtxoHandler
	replyHandlers.Unlock()
	w.UtxoStore.RLock()
	for _, utxo := range w.UtxoStore.s {
		w.ReqSpentUtxoNtfn(utxo)
	}
	w.UtxoStore.RUnlock()
}

// RescanToBestBlock requests btcd to rescan the blockchain for new
// transactions to all wallet addresses.  This is needed for making
// btcwallet catch up to a long-running btcd process, as otherwise
// it would have missed notifications as blocks are attached to the
// main chain.
func (w *BtcWallet) RescanToBestBlock() {
	beginBlock := int32(0)

	if w.fullRescan {
		// Need to perform a complete rescan since the wallet creation
		// block.
		beginBlock = w.CreatedAt()
		log.Debugf("Rescanning account '%v' for new transactions since block height %v",
			w.name, beginBlock)
	} else {
		// The last synced block height should be used the starting
		// point for block rescanning.  Grab the block stamp here.
		bs := w.SyncedWith()

		log.Debugf("Rescanning account '%v' for new transactions since block height %v hash %v",
			w.name, bs.Height, bs.Hash)

		// If we're synced with block x, must scan the blocks x+1 to best block.
		beginBlock = bs.Height + 1
	}

	n := <-NewJSONID
	cmd, err := btcws.NewRescanCmd(fmt.Sprintf("btcwallet(%v)", n),
		beginBlock, w.ActivePaymentAddresses())
	if err != nil {
		log.Errorf("cannot create rescan request: %v", err)
		return
	}
	mcmd, err := cmd.MarshalJSON()
	if err != nil {
		log.Errorf("cannot create rescan request: %v", err)
		return
	}

	replyHandlers.Lock()
	replyHandlers.m[n] = func(result interface{}, e *btcjson.Error) bool {
		// Rescan is compatible with new txs from connected block
		// notifications, so use that handler.
		_ = w.newBlockTxOutHandler(result, e)

		if result != nil {
			// Notify frontends of new account balance.
			confirmed := w.CalculateBalance(1)
			unconfirmed := w.CalculateBalance(0) - confirmed
			NotifyWalletBalance(frontendNotificationMaster, w.name, confirmed)
			NotifyWalletBalanceUnconfirmed(frontendNotificationMaster, w.name, unconfirmed)

			return false
		}
		if bs, err := GetCurBlock(); err == nil {
			w.SetSyncedWith(&bs)
			w.dirty = true
			if err = w.writeDirtyToDisk(); err != nil {
				log.Errorf("cannot sync dirty wallet: %v",
					err)
			}
		}
		// If result is nil, the rescan has completed.  Returning
		// true removes this handler.
		return true
	}
	replyHandlers.Unlock()

	btcdMsgs <- mcmd
}

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses in an account.
func (w *BtcWallet) SortedActivePaymentAddresses() []string {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	infos := w.GetSortedActiveAddresses()
	addrs := make([]string, len(infos))

	for i, addr := range infos {
		addrs[i] = addr.Address
	}

	return addrs
}

// ActivePaymentAddresses returns a set of all active pubkey hashes
// in an account.
func (w *BtcWallet) ActivePaymentAddresses() map[string]struct{} {
	w.mtx.RLock()
	defer w.mtx.RUnlock()

	infos := w.GetActiveAddresses()
	addrs := make(map[string]struct{}, len(infos))

	for _, info := range infos {
		addrs[info.Address] = struct{}{}
	}

	return addrs
}

// ReqNewTxsForAddress sends a message to btcd to request tx updates
// for addr for each new block that is added to the blockchain.
func (w *BtcWallet) ReqNewTxsForAddress(addr string) {
	log.Debugf("Requesting notifications of TXs sending to address %v", addr)

	w.mtx.RLock()
	n := w.NewBlockTxSeqN
	w.mtx.RUnlock()

	cmd := btcws.NewNotifyNewTXsCmd(fmt.Sprintf("btcwallet(%d)", n),
		[]string{addr})
	mcmd, err := cmd.MarshalJSON()
	if err != nil {
		log.Errorf("cannot request transaction notifications: %v", err)
	}

	btcdMsgs <- mcmd
}

// ReqSpentUtxoNtfn sends a message to btcd to request updates for when
// a stored UTXO has been spent.
func (w *BtcWallet) ReqSpentUtxoNtfn(u *tx.Utxo) {
	log.Debugf("Requesting spent UTXO notifications for Outpoint hash %s index %d",
		u.Out.Hash, u.Out.Index)

	w.mtx.RLock()
	n := w.SpentOutpointSeqN
	w.mtx.RUnlock()

	cmd := btcws.NewNotifySpentCmd(fmt.Sprintf("btcwallet(%d)", n),
		(*btcwire.OutPoint)(&u.Out))
	mcmd, err := cmd.MarshalJSON()
	if err != nil {
		log.Errorf("cannot create spent request: %v", err)
		return
	}

	btcdMsgs <- mcmd
}

// spentUtxoHandler is the handler function for btcd spent UTXO notifications
// resulting from transactions in newly-attached blocks.
func (w *BtcWallet) spentUtxoHandler(result interface{}, e *btcjson.Error) bool {
	if e != nil {
		log.Errorf("Spent UTXO Handler: Error %d received from btcd: %s",
			e.Code, e.Message)
		return false
	}
	v, ok := result.(map[string]interface{})
	if !ok {
		return false
	}
	txHashBE, ok := v["txhash"].(string)
	if !ok {
		log.Error("Spent UTXO Handler: Unspecified transaction hash.")
		return false
	}
	txHash, err := btcwire.NewShaHashFromStr(txHashBE)
	if err != nil {
		log.Errorf("Spent UTXO Handler: Bad transaction hash: %s", err)
		return false
	}
	index, ok := v["index"].(float64)
	if !ok {
		log.Error("Spent UTXO Handler: Unspecified index.")
	}

	_, _ = txHash, index

	// Never remove this handler.
	return false
}

// newBlockTxOutHandler is the handler function for btcd transaction
// notifications resulting from newly-attached blocks.
func (w *BtcWallet) newBlockTxOutHandler(result interface{}, e *btcjson.Error) bool {
	if e != nil {
		log.Errorf("Tx Handler: Error %d received from btcd: %s",
			e.Code, e.Message)
		return false
	}

	v, ok := result.(map[string]interface{})
	if !ok {
		// The first result sent from btcd is nil.  This could be used to
		// indicate that the request for notifications succeeded.
		if result != nil {
			log.Errorf("Tx Handler: Unexpected result type %T.", result)
		}
		return false
	}
	sender, ok := v["sender"].(string)
	if !ok {
		log.Error("Tx Handler: Unspecified sender.")
		return false
	}
	receiver, ok := v["receiver"].(string)
	if !ok {
		log.Error("Tx Handler: Unspecified receiver.")
		return false
	}
	blockhashBE, ok := v["blockhash"].(string)
	if !ok {
		log.Error("Tx Handler: Unspecified block hash.")
		return false
	}
	height, ok := v["height"].(float64)
	if !ok {
		log.Error("Tx Handler: Unspecified height.")
		return false
	}
	txhashBE, ok := v["txhash"].(string)
	if !ok {
		log.Error("Tx Handler: Unspecified transaction hash.")
		return false
	}
	index, ok := v["index"].(float64)
	if !ok {
		log.Error("Tx Handler: Unspecified transaction index.")
		return false
	}
	amt, ok := v["amount"].(float64)
	if !ok {
		log.Error("Tx Handler: Unspecified amount.")
		return false
	}
	pkscript58, ok := v["pkscript"].(string)
	if !ok {
		log.Error("Tx Handler: Unspecified pubkey script.")
		return false
	}
	pkscript := btcutil.Base58Decode(pkscript58)
	spent := false
	if tspent, ok := v["spent"].(bool); ok {
		spent = tspent
	}

	// btcd sends the block and tx hashes as BE strings.  Convert both
	// to a LE ShaHash.
	blockhash, err := btcwire.NewShaHashFromStr(blockhashBE)
	if err != nil {
		log.Errorf("Tx Handler: Block hash string cannot be parsed: %v", err)
		return false
	}
	txhash, err := btcwire.NewShaHashFromStr(txhashBE)
	if err != nil {
		log.Errorf("Tx Handler: Tx hash string cannot be parsed: %v", err)
		return false
	}
	// TODO(jrick): btcd does not find the sender yet.
	senderHash, _, _ := btcutil.DecodeAddress(sender)
	receiverHash, _, err := btcutil.DecodeAddress(receiver)
	if err != nil {
		log.Errorf("Tx Handler: receiver address can not be decoded: %v", err)
		return false
	}

	// Add to TxStore.
	t := &tx.RecvTx{
		Amt: uint64(amt),
	}
	copy(t.TxHash[:], txhash[:])
	copy(t.BlockHash[:], blockhash[:])
	copy(t.SenderAddr[:], senderHash)
	copy(t.ReceiverAddr[:], receiverHash)

	w.TxStore.Lock()
	txs := w.TxStore.s
	w.TxStore.s = append(txs, t)
	w.TxStore.dirty = true
	w.TxStore.Unlock()

	if err = w.writeDirtyToDisk(); err != nil {
		log.Errorf("cannot sync dirty wallet: %v", err)
	}

	// Add to UtxoStore if unspent.
	if !spent {
		// First, iterate through all stored utxos.  If an unconfirmed utxo
		// (not present in a block) has the same outpoint as this utxo,
		// update the block height and hash.
		w.UtxoStore.RLock()
		for _, u := range w.UtxoStore.s {
			if bytes.Equal(u.Out.Hash[:], txhash[:]) && u.Out.Index == uint32(index) {
				// Found a either a duplicate, or a change UTXO.  If not change,
				// ignore it.
				if u.Height != -1 {
					return false
				}
				w.UtxoStore.RUnlock()

				w.UtxoStore.Lock()
				copy(u.BlockHash[:], blockhash[:])
				u.Height = int32(height)
				w.UtxoStore.dirty = true
				w.UtxoStore.Unlock()

				if err = w.writeDirtyToDisk(); err != nil {
					log.Errorf("cannot sync dirty wallet: %v", err)
				}
				return false
			}
		}
		w.UtxoStore.RUnlock()

		// After iterating through all UTXOs, it was not a duplicate or
		// change UTXO appearing in a block.  Append a new Utxo to the end.

		u := &tx.Utxo{
			Amt:       uint64(amt),
			Height:    int32(height),
			Subscript: pkscript,
		}
		copy(u.Out.Hash[:], txhash[:])
		u.Out.Index = uint32(index)
		copy(u.AddrHash[:], receiverHash)
		copy(u.BlockHash[:], blockhash[:])
		w.UtxoStore.Lock()
		w.UtxoStore.s = append(w.UtxoStore.s, u)
		w.UtxoStore.dirty = true
		w.UtxoStore.Unlock()
		if err = w.writeDirtyToDisk(); err != nil {
			log.Errorf("cannot sync dirty wallet: %v", err)
		}

		confirmed := w.CalculateBalance(1)
		unconfirmed := w.CalculateBalance(0) - confirmed
		NotifyWalletBalance(frontendNotificationMaster, w.name, confirmed)
		NotifyWalletBalanceUnconfirmed(frontendNotificationMaster, w.name, unconfirmed)
	}

	// Never remove this handler.
	return false
}

// NewJSONID is used to receive the next unique JSON ID for btcd
// requests, starting from zero and incrementing by one after each
// read.
var NewJSONID = make(chan uint64)

// JSONIDGenerator sends incremental integers across a channel.  This
// is meant to provide a unique value for the JSON ID field for btcd
// messages.
func JSONIDGenerator(c chan uint64) {
	var n uint64
	for {
		c <- n
		n++
	}
}

func main() {
	// Initialize logging and setup deferred flushing to ensure all
	// outstanding messages are written on shutdown
	loggers := setLogLevel(defaultLogLevel)
	defer func() {
		for _, logger := range loggers {
			logger.Flush()
		}
	}()

	tcfg, _, err := loadConfig()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	cfg = tcfg

	// Change the logging level if needed.
	if cfg.DebugLevel != defaultLogLevel {
		loggers = setLogLevel(cfg.DebugLevel)
	}

	// Open default wallet
	w, err := OpenWallet(cfg, "")
	switch err {
	case ErrNoTxs:
		// Do nothing special for now.  This will be implemented when
		// the tx history file is properly written.
		wallets.Lock()
		wallets.m[""] = w
		wallets.Unlock()

	case ErrNoUtxos:
		// Add wallet, but mark wallet as needing a full rescan since
		// the wallet creation block.  This will take place when btcd
		// connects.
		wallets.Lock()
		wallets.m[""] = w
		wallets.Unlock()
		w.fullRescan = true

	case nil:
		wallets.Lock()
		wallets.m[""] = w
		wallets.Unlock()

	default:
		log.Errorf("cannot open wallet: %v", err)
	}

	// Start wallet disk syncer goroutine.
	go DirtyWalletSyncer()

	go func() {
		// Start HTTP server to listen and send messages to frontend and btcd
		// backend.  Try reconnection if connection failed.
		for {
			if err := FrontendListenAndServe(); err != nil {
				log.Info("Unable to start frontend HTTP server: %v", err)
				os.Exit(1)
			}
		}
	}()

	// Begin generating new IDs for JSON calls.
	go JSONIDGenerator(NewJSONID)

	for {
		replies := make(chan error)
		done := make(chan int)
		go func() {
			BtcdConnect(replies)
			close(done)
		}()
	selectLoop:
		for {
			select {
			case <-done:
				break selectLoop
			case err := <-replies:
				switch err {
				case ErrConnRefused:
					btcdConnected.c <- false
					log.Info("btcd connection refused, retying in 5 seconds")
					time.Sleep(5 * time.Second)
				case ErrConnLost:
					btcdConnected.c <- false
					log.Info("btcd connection lost, retrying in 5 seconds")
					time.Sleep(5 * time.Second)
				case nil:
					btcdConnected.c <- true
					log.Info("Established connection to btcd.")
				default:
					log.Infof("Unhandled error: %v", err)
				}
			}
		}
	}
}
