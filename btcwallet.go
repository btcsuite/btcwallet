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
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"

	"github.com/btcsuite/btcwallet/chain"
)

var (
	cfg *config
)

func main() {
	// Use all processor cores.
	runtime.GOMAXPROCS(runtime.NumCPU())

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

	// Load the wallet database.  It must have been created with the
	// --create option already or this will return an appropriate error.
	wallet, err := openWallet()
	if err != nil {
		log.Errorf("%v", err)
		return err
	}
	defer wallet.Db().Close()

	// Create and start HTTP server to serve wallet client connections.
	// This will be updated with the wallet and chain server RPC client
	// created below after each is created.
	server, err := newRPCServer(cfg.SvrListeners, cfg.RPCMaxClients,
		cfg.RPCMaxWebsockets)
	if err != nil {
		log.Errorf("Unable to create HTTP server: %v", err)
		return err
	}
	server.Start()
	server.SetWallet(wallet)

	// Shutdown the server if an interrupt signal is received.
	addInterruptHandler(server.Stop)

	// Create channel so that the goroutine which opens the chain server
	// connection can pass the conn to the goroutine which opens the wallet.
	// Buffer the channel so sends are not blocked, since if the wallet is
	// not yet created, the wallet open goroutine does not read this.
	chainSvrChan := make(chan *chain.Client, 1)

	go func() {
		// Read CA certs and create the RPC client.
		var certs []byte
		if !cfg.DisableClientTLS {
			certs, err = ioutil.ReadFile(cfg.CAFile)
			if err != nil {
				log.Warnf("Cannot open CA file: %v", err)
				// If there's an error reading the CA file, continue
				// with nil certs and without the client connection
				certs = nil
			}
		} else {
			log.Info("Client TLS is disabled")
		}
		rpcc, err := chain.NewClient(activeNet.Params, cfg.RPCConnect,
			cfg.BtcdUsername, cfg.BtcdPassword, certs, cfg.DisableClientTLS)
		if err != nil {
			log.Errorf("Cannot create chain server RPC client: %v", err)
			return
		}
		err = rpcc.Start()
		if err != nil {
			log.Warnf("Connection to Bitcoin RPC chain server " +
				"unsuccessful -- available RPC methods will be limited")
		}
		// Even if Start errored, we still add the server disconnected.
		// All client methods will then error, so it's obvious to a
		// client that the there was a connection problem.
		server.SetChainServer(rpcc)

		chainSvrChan <- rpcc
	}()

	go func() {
		// Start wallet goroutines and handle RPC client notifications
		// if the chain server connection was opened.
		select {
		case chainSvr := <-chainSvrChan:
			wallet.Start(chainSvr)
		case <-server.quit:
		}
	}()

	// Wait for the server to shutdown either due to a stop RPC request
	// or an interrupt.
	server.WaitForShutdown()
	log.Info("Shutdown complete")
	return nil
}
