// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/internal/prompt"
	"github.com/decred/dcrwallet/internal/zero"
	"github.com/decred/dcrwallet/rpc/legacyrpc"
	"github.com/decred/dcrwallet/wallet"
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
	log.Infof("load the config")
	tcfg, _, err := loadConfig()
	if err != nil {
		return err
	}
	cfg = tcfg
	defer backendLog.Flush()

	// Show version at startup.
	log.Infof("Version %s", version())

	if cfg.Profile != "" {
		go func() {
			listenAddr := net.JoinHostPort("", cfg.Profile)
			log.Infof("Profile server listening on %s", listenAddr)
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			err := http.ListenAndServe(listenAddr, nil)
			if err != nil {
				fatalf(err.Error())
			}
		}()
	}

	// Write mem profile if requested.
	if cfg.MemProfile != "" {
		f, err := os.Create(cfg.MemProfile)
		if err != nil {
			log.Errorf("Unable to create cpu profile: %v", err)
			return err
		}
		timer := time.NewTimer(time.Minute * 5) // 5 minutes
		go func() {
			<-timer.C
			pprof.WriteHeapProfile(f)
			f.Close()
		}()
	}

	dbDir := networkDir(cfg.AppDataDir, activeNet.Params)
	stakeOptions := &wallet.StakeOptions{
		VoteBits:            cfg.VoteBits,
		VoteBitsExtended:    cfg.VoteBitsExtended,
		StakeMiningEnabled:  cfg.EnableStakeMining,
		BalanceToMaintain:   cfg.BalanceToMaintain,
		RollbackTest:        cfg.RollbackTest,
		PruneTickets:        cfg.PruneTickets,
		AddressReuse:        cfg.ReuseAddresses,
		TicketAddress:       cfg.TicketAddress,
		TicketMaxPrice:      cfg.TicketMaxPrice,
		TicketBuyFreq:       cfg.TicketBuyFreq,
		PoolAddress:         cfg.PoolAddress,
		PoolFees:            cfg.PoolFees,
		StakePoolColdExtKey: cfg.StakePoolColdExtKey,
		TicketFee:           cfg.TicketFee,
	}
	loader := wallet.NewLoader(activeNet.Params, dbDir, stakeOptions,
		cfg.AutomaticRepair, cfg.UnsafeMainNet, cfg.AddrIdxScanLen,
		cfg.AllowHighFees, cfg.RelayFee)

	// Create and start HTTP server to serve wallet client connections.
	// This will be updated with the wallet and chain server RPC client
	// created below after each is created.
	rpcs, legacyRPCServer, err := startRPCServers(loader)
	if err != nil {
		log.Errorf("Unable to create RPC servers: %v", err)
		return err
	}

	// Create and start chain RPC client so it's ready to connect to
	// the wallet when loaded later.
	if !cfg.NoInitialLoad {
		go rpcClientConnectLoop(legacyRPCServer, loader)
	}

	loader.RunAfterLoad(func(w *wallet.Wallet) {
		// TODO(jrick): I think that this prompt should be removed
		// entirely instead of enabling it when --noinitialload is
		// unset.  It can be replaced with an RPC request (either
		// providing the private passphrase as a parameter, or require
		// unlocking the wallet first) to trigger a full accounts
		// rescan.
		//
		// Until then, since --noinitialload users are expecting to use
		// the wallet only over RPC, disable this feature for them.
		if !cfg.NoInitialLoad {
			startPromptPass(w)
		}
		startWalletRPCServices(w, rpcs, legacyRPCServer)
	})

	if !cfg.NoInitialLoad {
		// Load the wallet database.  It must have been created already
		// or this will return an appropriate error.
		_, err = loader.OpenExistingWallet([]byte(cfg.WalletPass), true)
		if err != nil {
			log.Error(err)
			return err
		}
	}

	// Add interrupt handlers to shutdown the various process components
	// before exiting.  Interrupt handlers run in LIFO order, so the wallet
	// (which should be closed last) is added first.
	addInterruptHandler(func() {
		err := loader.UnloadWallet()
		if err != nil && err != wallet.ErrNotLoaded {
			log.Errorf("Failed to close wallet: %v", err)
		}
	})
	if rpcs != nil {
		addInterruptHandler(func() {
			// TODO: Does this need to wait for the grpc server to
			// finish up any requests?
			log.Warn("Stopping RPC server...")
			rpcs.Stop()
			log.Info("RPC server shutdown")
		})
	}
	if legacyRPCServer != nil {
		addInterruptHandler(func() {
			log.Warn("Stopping legacy RPC server...")
			legacyRPCServer.Stop()
			log.Info("Legacy RPC server shutdown")
		})
		go func() {
			<-legacyRPCServer.RequestProcessShutdown()
			simulateInterrupt()
		}()
	}

	<-interruptHandlersDone
	log.Info("Shutdown complete")
	return nil
}

// startPromptPass prompts the user for a password to unlock their wallet in
// the event that it was restored from seed or --promptpass flag is set.
func startPromptPass(w *wallet.Wallet) {
	promptPass := cfg.PromptPass

	// Watching only wallets never require a password.
	if w.Manager.WatchingOnly() {
		return
	}

	// The wallet is totally desynced, so we need to resync accounts.
	// Prompt for the password. Then, set the flag it wallet so it
	// knows which address functions to call when resyncing.
	firstRunBS := w.Manager.SyncedTo()
	if firstRunBS.Hash == *w.ChainParams().GenesisHash {
		promptPass = true
	}
	if promptPass {
		w.SetInitiallyUnlocked(true)
		backendLog.Flush()
		fmt.Println("*** ATTENTION ***")
		fmt.Println("Since this is your first time running we need to sync accounts. Please enter")
		fmt.Println("the private wallet passphrase. This will complete syncing of the wallet")
		fmt.Println("accounts and then leave your wallet unlocked. You may relock wallet after by")
		fmt.Println("calling 'walletlock' through the RPC.")
		fmt.Println("*****************")
	} else {
		return
	}

	// We need to rescan accounts for the initial sync. Unlock the
	// wallet after prompting for the passphrase. The special case
	// of a --createtemp simnet wallet is handled by first
	// attempting to automatically open it with the default
	// passphrase. The wallet should also request to be unlocked
	// if stake mining is currently on, so users with this flag
	// are prompted here as well.
	for {
		if w.ChainParams() == &chaincfg.SimNetParams {
			var unlockAfter <-chan time.Time
			err := w.Unlock(wallet.SimulationPassphrase, unlockAfter)
			if err == nil {
				// Unlock success with the default password.
				return
			}
		}
		if promptPass {
			backendLog.Flush()
			reader := bufio.NewReader(os.Stdin)
			passphrase, err := prompt.PassPrompt(reader, "Enter private passphrase", false)
			if err != nil {
				fmt.Println("Failed to input password. Please try again.")
				continue
			}
			defer zero.Bytes(passphrase)

			var unlockAfter <-chan time.Time
			err = w.Unlock(passphrase, unlockAfter)
			if err != nil {
				fmt.Println("Incorrect password entered. Please " +
					"try again.")
				continue
			}

			break
		}
	}
}

// rpcClientConnectLoop continuously attempts a connection to the consensus RPC
// server.  When a connection is established, the client is used to sync the
// loaded wallet, either immediately or when loaded at a later time.
//
// The legacy RPC is optional.  If set, the connected RPC client will be
// associated with the server for RPC passthrough and to enable additional
// methods.
func rpcClientConnectLoop(legacyRPCServer *legacyrpc.Server, loader *wallet.Loader) {
	certs := readCAFile()

	for {
		chainClient, err := startChainRPC(certs)
		if err != nil {
			log.Errorf("Unable to open connection to consensus RPC server: %v", err)
			continue
		}

		// Rather than inlining this logic directly into the loader
		// callback, a function variable is used to avoid running any of
		// this after the client disconnects by setting it to nil.  This
		// prevents the callback from associating a wallet loaded at a
		// later time with a client that has already disconnected.  A
		// mutex is used to make this concurrent safe.
		associateRPCClient := func(w *wallet.Wallet) {
			w.SynchronizeRPC(chainClient)
			if legacyRPCServer != nil {
				legacyRPCServer.SetChainServer(chainClient)
			}
		}
		mu := new(sync.Mutex)
		loader.RunAfterLoad(func(w *wallet.Wallet) {
			mu.Lock()
			associate := associateRPCClient
			mu.Unlock()
			if associate != nil {
				associate(w)
			}
		})

		chainClient.WaitForShutdown()

		mu.Lock()
		associateRPCClient = nil
		mu.Unlock()

		loadedWallet, ok := loader.LoadedWallet()
		if ok {
			// Do not attempt a reconnect when the wallet was
			// explicitly stopped.
			if loadedWallet.ShuttingDown() {
				return
			}

			loadedWallet.SetChainSynced(false)

			// TODO: Rework the wallet so changing the RPC client
			// does not require stopping and restarting everything.
			loadedWallet.Stop()
			loadedWallet.WaitForShutdown()
			loadedWallet.Start()
		}
	}
}

func readCAFile() []byte {
	// Read certificate file if TLS is not disabled.
	var certs []byte
	if !cfg.DisableClientTLS {
		var err error
		certs, err = ioutil.ReadFile(cfg.CAFile)
		if err != nil {
			log.Warnf("Cannot open CA file: %v", err)
			// If there's an error reading the CA file, continue
			// with nil certs and without the client connection.
			certs = nil
		}
	} else {
		log.Info("Chain server RPC TLS is disabled")
	}

	return certs
}

// startChainRPC opens a RPC client connection to a dtcd server for blockchain
// services.  This function uses the RPC options from the global config and
// there is no recovery in case the server is not available or if there is an
// authentication error.  Instead, all requests to the client will simply error.
func startChainRPC(certs []byte) (*chain.RPCClient, error) {
	log.Infof("Attempting RPC client connection to %v", cfg.RPCConnect)
	rpcc, err := chain.NewRPCClient(activeNet.Params, cfg.RPCConnect,
		cfg.DcrdUsername, cfg.DcrdPassword, certs, cfg.DisableClientTLS, 0)
	if err != nil {
		return nil, err
	}
	err = rpcc.Start()
	return rpcc, err
}
