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
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"
	"time"

	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
)

var (
	cfg          *config
	server       *rpcServer
	shutdownChan = make(chan struct{})

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

	var bbHash *btcwire.ShaHash
	var bbHeight int32
	client, err := accessClient()
	if err == nil {
		bbHash, bbHeight, err = client.GetBestBlock()
	}
	if err != nil {
		unknown := wallet.BlockStamp{
			Height: int32(btcutil.BlockHeightUnknown),
		}
		return unknown, err
	}

	curBlock.Lock()
	if bbHeight > curBlock.BlockStamp.Height {
		bs = wallet.BlockStamp{
			Height: bbHeight,
			Hash:   *bbHash,
		}
		curBlock.BlockStamp = bs
	}
	curBlock.Unlock()
	return bs, nil
}

var clientAccessChan = make(chan *rpcClient)

func clientAccess(newClient <-chan *rpcClient) {
	var client *rpcClient
	for {
		select {
		case c := <-newClient:
			client = c
		case clientAccessChan <- client:
		}
	}
}

func accessClient() (*rpcClient, error) {
	c := <-clientAccessChan
	if c == nil {
		return nil, errors.New("chain server disconnected")
	}
	return c, nil
}

func clientConnect(certs []byte, newClient chan<- *rpcClient) {
	const initialWait = 5 * time.Second
	wait := initialWait
	for {
		select {
		case <-server.quit:
			return
		default:
		}

		client, err := newRPCClient(certs)
		if err != nil {
			log.Warnf("Unable to open chain server client "+
				"connection: %v", err)
			time.Sleep(wait)
			wait <<= 1
			if wait > time.Minute {
				wait = time.Minute
			}
			continue
		}

		wait = initialWait
		client.Start()
		newClient <- client

		client.WaitForShutdown()
	}
}

func main() {
	// Work around defer not working after os.Exit.
	if err := walletMain(); err != nil {
		os.Exit(1)
	}
}

// walletMain is a work-around main function that is required since deferred
// functions (such as log flushing) are not called with calls to os.Exit.
// Instead, main runs this function and checks for a non-nil error, at which
// point any defers have already run, and if the error is non-nil, the program
// can be exited with an error exit status.
func walletMain() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	tcfg, _, err := loadConfig()
	if err != nil {
		return err
	}
	cfg = tcfg
	defer backendLog.Flush()

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

	// Read CA file to verify a btcd TLS connection.
	certs, err := ioutil.ReadFile(cfg.CAFile)
	if err != nil {
		log.Errorf("cannot open CA file: %v", err)
		return err
	}

	// Check and update any old file locations.
	err = updateOldFileLocations()
	if err != nil {
		return err
	}

	// Start account manager and open accounts.
	AcctMgr.Start()

	server, err = newRPCServer(cfg.SvrListeners)
	if err != nil {
		log.Errorf("Unable to create HTTP server: %v", err)
		return err
	}

	// Start HTTP server to serve wallet client connections.
	server.Start()

	// Shutdown the server if an interrupt signal is received.
	addInterruptHandler(server.Stop)

	// Start client connection to a btcd chain server.  Attempt
	// reconnections if the client could not be successfully connected.
	clientChan := make(chan *rpcClient)
	go clientAccess(clientChan)
	go clientConnect(certs, clientChan)

	// Wait for the server to shutdown either due to a stop RPC request
	// or an interrupt.
	server.WaitForShutdown()
	log.Info("Shutdown complete")
	return nil
}
