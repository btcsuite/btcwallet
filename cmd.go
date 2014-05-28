/*
 * Copyright (c) 2013, 2014 Conformal Systems LLC <info@conformal.com>
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
	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"
	"time"
)

var (
	cfg *config

	curBlock = struct {
		sync.RWMutex
		wallet.BlockStamp
	}{
		BlockStamp: wallet.BlockStamp{
			Height: int32(btcutil.BlockHeightUnknown),
		},
	}
)

// GetCurBlock returns the blockchain height and SHA hash of the most
// recently seen block.  If no blocks have been seen since btcd has
// connected, btcd is queried for the current block height and hash.
func GetCurBlock() (wallet.BlockStamp, error) {
	curBlock.RLock()
	bs := curBlock.BlockStamp
	curBlock.RUnlock()
	if bs.Height != int32(btcutil.BlockHeightUnknown) {
		return bs, nil
	}

	bb, jsonErr := GetBestBlock(CurrentServerConn())
	if jsonErr != nil {
		return wallet.BlockStamp{
			Height: int32(btcutil.BlockHeightUnknown),
		}, jsonErr
	}

	hash, err := btcwire.NewShaHashFromStr(bb.Hash)
	if err != nil {
		return wallet.BlockStamp{
			Height: int32(btcutil.BlockHeightUnknown),
		}, err
	}

	curBlock.Lock()
	if bb.Height > curBlock.BlockStamp.Height {
		bs = wallet.BlockStamp{
			Height: bb.Height,
			Hash:   *hash,
		}
		curBlock.BlockStamp = bs
	}
	curBlock.Unlock()
	return bs, nil
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
		os.Exit(1)
	}
	cfg = tcfg

	// Change the logging level if needed.
	if cfg.DebugLevel != defaultLogLevel {
		loggers = setLogLevel(cfg.DebugLevel)
	}

	if cfg.Profile != "" {
		go func() {
			listenAddr := net.JoinHostPort("", cfg.Profile)
			log.Infof("Profile server listening on %s", listenAddr)
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			log.Errorf("%v", http.ListenAndServe(listenAddr, nil))
		}()
	}

	// Check and update any old file locations.
	updateOldFileLocations()

	// Start account manager and open accounts.
	AcctMgr.Start()

	// Read CA file to verify a btcd TLS connection.
	cafile, err := ioutil.ReadFile(cfg.CAFile)
	if err != nil {
		log.Errorf("cannot open CA file: %v", err)
		os.Exit(1)
	}

	go func() {
		s, err := newServer(cfg.SvrListeners)
		if err != nil {
			log.Errorf("Unable to create HTTP server: %v", err)
			os.Exit(1)
		}

		// Start HTTP server to listen and send messages to frontend and btcd
		// backend.  Try reconnection if connection failed.
		s.Start()
	}()

	// Begin generating new IDs for JSON calls.
	go JSONIDGenerator(NewJSONID)

	// Begin RPC server goroutines.
	go RPCGateway()
	go WalletRequestProcessor()

	// Begin maintanence goroutines.
	go SendBeforeReceiveHistorySync(SendTxHistSyncChans.add,
		SendTxHistSyncChans.done,
		SendTxHistSyncChans.remove,
		SendTxHistSyncChans.access)
	go StoreNotifiedMempoolRecvTxs(NotifiedRecvTxChans.add,
		NotifiedRecvTxChans.remove,
		NotifiedRecvTxChans.access)
	go NotifyBalanceSyncer(NotifyBalanceSyncerChans.add,
		NotifyBalanceSyncerChans.remove,
		NotifyBalanceSyncerChans.access)

	updateBtcd := make(chan *BtcdRPCConn)
	go func() {
		// Create an RPC connection and close the closed channel.
		//
		// It might be a better idea to create a new concrete type
		// just for an always disconnected RPC connection and begin
		// with that.
		btcd := NewBtcdRPCConn(nil)
		close(btcd.closed)

		// Maintain the current btcd connection.  After reconnects,
		// the current connection should be updated.
		for {
			select {
			case conn := <-updateBtcd:
				btcd = conn

			case access := <-accessServer:
				access.server <- btcd
			}
		}
	}()

	for {
		btcd, err := BtcdConnect(cafile)
		if err != nil {
			log.Info("Retrying btcd connection in 5 seconds")
			time.Sleep(5 * time.Second)
			continue
		}
		updateBtcd <- btcd

		NotifyBtcdConnection(allClients)
		log.Info("Established connection to btcd")

		// Perform handshake.
		if err := Handshake(btcd); err != nil {
			var message string
			if jsonErr, ok := err.(*btcjson.Error); ok {
				message = jsonErr.Message
			} else {
				message = err.Error()
			}
			log.Errorf("Cannot complete handshake: %v", message)
			log.Info("Retrying btcd connection in 5 seconds")
			time.Sleep(5 * time.Second)
			continue
		}

		// Block goroutine until the connection is lost.
		<-btcd.closed
		NotifyBtcdConnection(allClients)
		log.Info("Lost btcd connection")
	}
}

var accessServer = make(chan *AccessCurrentServerConn)

// AccessCurrentServerConn is used to access the current RPC connection
// from the goroutine managing btcd-side RPC connections.
type AccessCurrentServerConn struct {
	server chan ServerConn
}

// CurrentServerConn returns the most recently-connected btcd-side
// RPC connection.
func CurrentServerConn() ServerConn {
	access := &AccessCurrentServerConn{
		server: make(chan ServerConn),
	}
	accessServer <- access
	return <-access.server
}
