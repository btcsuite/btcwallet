// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package run

import (
	"context"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stroomnetwork/frost"
	"net"
	"net/http"
	_ "net/http/pprof" // nolint:gosec
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightninglabs/neutrino"
	"github.com/stroomnetwork/btcwallet/chain"
	"github.com/stroomnetwork/btcwallet/rpc/legacyrpc"
	"github.com/stroomnetwork/btcwallet/wallet"
)

const ethChangeAddr = "0x7b3f4f4b3cCf7f3fDf3f3f3f3f3f3f3f3f3f3f3f"

var (
	cfg *Config
)

type BtcwalletConfig struct {
	Signer         frost.Signer
	Pk1, Pk2       *btcec.PublicKey
	BitcoindConfig *chain.BitcoindConfig
	Config         *Config
	InitTimeout    time.Duration
	FeeCoefficient float64
}

func NewBtcwalletConfig(signer frost.Signer, pk1, pk2 *btcec.PublicKey, bitcoindConfig *chain.BitcoindConfig,
	config *Config, initTimeout time.Duration, feeCoefficient float64) *BtcwalletConfig {

	return &BtcwalletConfig{
		Signer:         signer,
		Pk1:            pk1,
		Pk2:            pk2,
		BitcoindConfig: bitcoindConfig,
		Config:         config,
		InitTimeout:    initTimeout,
		FeeCoefficient: feeCoefficient,
	}
}

func SafeInitWallet(config *BtcwalletConfig) (*wallet.Wallet, error) {
	w, err := InitWallet(config)
	return safeChecks(err, w)
}

func SafeInitWalletWithConfig(config *BtcwalletConfig) (*wallet.Wallet, error) {
	w, err := InitWalletWithConfig(config)
	return safeChecks(err, w)
}

func safeChecks(err error, w *wallet.Wallet) (*wallet.Wallet, error) {
	if err != nil {
		return nil, err
	}

	if w == nil {
		return nil, fmt.Errorf("wallet is nil")
	}
	client := w.ChainClient()
	if client == nil {
		return nil, fmt.Errorf("chain client is nil")
	}

	return w, nil
}

// InitWallet Load configuration and parse command line. This function also
// initializes logging and configures it accordingly.
func InitWallet(config *BtcwalletConfig) (*wallet.Wallet, error) {
	tcfg, _, err := parseAndLoadConfig()
	if err != nil {
		return nil, err
	}
	config.Config = tcfg
	return doInit(config)
}

// InitWalletWithConfig creates a new instance of the wallet with provided config
func InitWalletWithConfig(config *BtcwalletConfig) (*wallet.Wallet, error) {
	err := loadConfig(config.Config)
	if err != nil {
		log.Errorf("Error loading config: %v", err)
		return nil, err
	}

	return doInit(config)
}

func doInit(config *BtcwalletConfig) (*wallet.Wallet, error) {
	err := checkConfigForNil(config)
	if err != nil {
		return nil, err
	}

	cfg = config.Config

	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	// Show version at startup.
	log.Infof("Version %s", version())

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

	dbDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)
	loader := wallet.NewLoader(
		activeNet.Params, dbDir, true, cfg.DBTimeout, 250,
	)

	// Create and start HTTP server to serve wallet client connections.
	// This will be updated with the wallet and chain server RPC client
	// created below after each is created.
	rpcs, legacyRPCServer, err := startRPCServers(loader)
	if err != nil {
		log.Errorf("Unable to create RPC servers: %v", err)
		return nil, err
	}

	// Create and start chain RPC client so it's ready to connect to
	// the wallet when loaded later.
	if !cfg.NoInitialLoad {
		go rpcClientConnectLoop(legacyRPCServer, loader, config.BitcoindConfig)
	}

	loader.RunAfterLoad(func(w *wallet.Wallet) {
		startWalletRPCServices(w, rpcs, legacyRPCServer)
	})

	var w *wallet.Wallet
	if !cfg.NoInitialLoad {
		// Load the wallet database.  It must have been created already
		// or this will return an appropriate error.
		w, err = loader.OpenExistingWallet([]byte(cfg.WalletPass), cfg.CanConsolePrompt)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		w.FrostSigner = config.Signer
		w.Pk1 = config.Pk1
		w.Pk2 = config.Pk2

		storage, err := wallet.NewAddressMapStorage(cfg.AppDataDir.Value + "/" + wallet.DefaultStorageFileName)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		w.AddressMapStorage = storage

		err = waitForChainClientInitialized(w, config.InitTimeout)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		changeAddressKey, changeAddress, err := w.GenerateKeyFromEthAddressAndImport(ethChangeAddr)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return nil, fmt.Errorf("cannot import change address: %w", err)
		}
		if changeAddress != nil {
			log.Infof("Change address: %s", changeAddress.Address())
		}
		if changeAddressKey == nil {
			return nil, fmt.Errorf("change key is nil")
		}
		w.ChangeAddressKey = changeAddressKey
		w.FeeCoefficient = config.FeeCoefficient
	}

	// Add interrupt handlers to shut down the various process components
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
	return w, nil
}

func checkConfigForNil(config *BtcwalletConfig) error {
	var errors []string
	if config.Config == nil {
		errors = append(errors, "config is nil")
	}
	if config.Signer == nil {
		errors = append(errors, "signer is nil")
	}
	if config.Pk1 == nil {
		errors = append(errors, "pk1 is nil")
	}
	if config.Pk2 == nil {
		errors = append(errors, "pk2 is nil")
	}
	if config.InitTimeout == 0 {
		config.InitTimeout = 30 * time.Second
	}
	if len(errors) > 0 {
		return fmt.Errorf("BtcwalletConfig errors: %s", strings.Join(errors, ", "))
	}
	return nil
}

func waitForChainClientInitialized(wallet *wallet.Wallet, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)

	for {
		select {
		case <-ticker.C:
			if wallet.ChainClient() != nil {
				return nil
			}
		case <-ctx.Done():
			if wallet.ChainClient() == nil {
				return fmt.Errorf("timeout waiting for chainClient to initialize")
			}
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
func rpcClientConnectLoop(legacyRPCServer *legacyrpc.Server, loader *wallet.Loader, bitcoindConfig *chain.BitcoindConfig) {
	var certs []byte
	if !cfg.UseSPV {
		certs = readCAFile()
	}

	for {
		var (
			chainClient chain.Interface
			err         error
		)

		if cfg.UseSPV {
			var (
				chainService *neutrino.ChainService
				spvdb        walletdb.DB
			)
			netDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)
			spvdb, err = walletdb.Create(
				"bdb", filepath.Join(netDir, "neutrino.db"),
				true, cfg.DBTimeout,
			)
			if err != nil {
				log.Errorf("Unable to create Neutrino DB: %s", err)
				continue
			}
			defer spvdb.Close()
			chainService, err = neutrino.NewChainService(
				neutrino.Config{
					DataDir:      netDir,
					Database:     spvdb,
					ChainParams:  *activeNet.Params,
					ConnectPeers: cfg.ConnectPeers,
					AddPeers:     cfg.AddPeers,
				})
			if err != nil {
				log.Errorf("Couldn't create Neutrino ChainService: %s", err)
				continue
			}
			chainClient = chain.NewNeutrinoClient(activeNet.Params, chainService)
			err = chainClient.Start()
			if err != nil {
				log.Errorf("Couldn't start Neutrino client: %s", err)
			}
		} else {
			if bitcoindConfig != nil {
				bitcoindConfig.ChainParams = activeNet.Params
				chainClient, err = chain.SetupBitcoind(bitcoindConfig)
			} else {
				chainClient, err = startChainRPC(certs)
			}
			if err != nil {
				log.Errorf("Unable to open connection to consensus RPC server: %v", err)
				continue
			}
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
		certs, err = os.ReadFile(cfg.CAFile.Value)
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

// startChainRPC opens a RPC client connection to a btcd server for blockchain
// services.  This function uses the RPC options from the global config and
// there is no recovery in case the server is not available or if there is an
// authentication error.  Instead, all requests to the client will simply error.
func startChainRPC(certs []byte) (*chain.RPCClient, error) {
	log.Infof("Attempting RPC client connection to %v", cfg.RPCConnect)
	rpcc, err := chain.NewRPCClient(activeNet.Params, cfg.RPCConnect,
		cfg.BtcdUsername, cfg.BtcdPassword, certs, cfg.DisableClientTLS, 0)
	if err != nil {
		return nil, err
	}
	err = rpcc.Start()
	return rpcc, err
}
