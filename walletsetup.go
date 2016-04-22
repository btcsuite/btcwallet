// Copyright (c) 2014-2015 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrutil/hdkeychain"
	"github.com/decred/dcrwallet/internal/legacy/keystore"
	"github.com/decred/dcrwallet/internal/prompt"
	"github.com/decred/dcrwallet/pgpwordlist"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/wallet"
	"github.com/decred/dcrwallet/walletdb"
	_ "github.com/decred/dcrwallet/walletdb/bdb"
)

// networkDir returns the directory name of a network directory to hold wallet
// files.
func networkDir(dataDir string, chainParams *chaincfg.Params) string {
	netname := chainParams.Name

	// For now, we must always name the testnet data directory as "testnet"
	// and not "testnet" or any other version, as the chaincfg testnet
	// paramaters will likely be switched to being named "testnet" in the
	// future.  This is done to future proof that change, and an upgrade
	// plan to move the testnet data directory can be worked out later.
	if chainParams.Net == wire.TestNet {
		netname = "testnet"
	}

	return filepath.Join(dataDir, netname)
}

// convertLegacyKeystore converts all of the addresses in the passed legacy
// key store to the new waddrmgr.Manager format.  Both the legacy keystore and
// the new manager must be unlocked.
func convertLegacyKeystore(legacyKeyStore *keystore.Store, manager *waddrmgr.Manager) error {
	netParams := legacyKeyStore.Net()
	blockStamp := waddrmgr.BlockStamp{
		Height: 0,
		Hash:   *netParams.GenesisHash,
	}
	for _, walletAddr := range legacyKeyStore.ActiveAddresses() {
		switch addr := walletAddr.(type) {
		case keystore.PubKeyAddress:
			privKey, err := addr.PrivKey()
			if err != nil {
				fmt.Printf("WARN: Failed to obtain private key "+
					"for address %v: %v\n", addr.Address(),
					err)
				continue
			}

			wif, err := dcrutil.NewWIF((chainec.PrivateKey)(privKey),
				netParams, chainec.ECTypeSecp256k1)
			if err != nil {
				fmt.Printf("WARN: Failed to create wallet "+
					"import format for address %v: %v\n",
					addr.Address(), err)
				continue
			}

			_, err = manager.ImportPrivateKey(wif, &blockStamp)
			if err != nil {
				fmt.Printf("WARN: Failed to import private "+
					"key for address %v: %v\n",
					addr.Address(), err)
				continue
			}

		case keystore.ScriptAddress:
			_, err := manager.ImportScript(addr.Script(), &blockStamp)
			if err != nil {
				fmt.Printf("WARN: Failed to import "+
					"pay-to-script-hash script for "+
					"address %v: %v\n", addr.Address(), err)
				continue
			}

		default:
			fmt.Printf("WARN: Skipping unrecognized legacy "+
				"keystore type: %T\n", addr)
			continue
		}
	}

	return nil
}

// createWallet prompts the user for information needed to generate a new wallet
// and generates the wallet accordingly.  The new wallet will reside at the
// provided path. The bool passed back gives whether or not the wallet was
// restored from seed, while the []byte passed is the private password required
// to do the initial sync.
func createWallet(cfg *config) error {
	createWalletError := func(err error) error {
		return err
	}

	dbDir := networkDir(cfg.DataDir, activeNet.Params)
	stakeOptions := &wallet.StakeOptions{
		VoteBits:           cfg.VoteBits,
		StakeMiningEnabled: cfg.EnableStakeMining,
		BalanceToMaintain:  cfg.BalanceToMaintain,
		RollbackTest:       cfg.RollbackTest,
		PruneTickets:       cfg.PruneTickets,
		AddressReuse:       cfg.ReuseAddresses,
		TicketAddress:      cfg.TicketAddress,
		TicketMaxPrice:     cfg.TicketMaxPrice,
	}
	loader := wallet.NewLoader(activeNet.Params, dbDir, stakeOptions,
		cfg.AutomaticRepair, cfg.UnsafeMainNet, cfg.AddrIdxScanLen)

	// When there is a legacy keystore, open it now to ensure any errors
	// don't end up exiting the process after the user has spent time
	// entering a bunch of information.
	netDir := networkDir(cfg.DataDir, activeNet.Params)
	keystorePath := filepath.Join(netDir, keystore.Filename)
	var legacyKeyStore *keystore.Store
	_, err := os.Stat(keystorePath)
	if err != nil && !os.IsNotExist(err) {
		// A stat error not due to a non-existant file should be
		// returned to the caller.
		return createWalletError(err)
	} else if err == nil {
		// Keystore file exists.
		legacyKeyStore, err = keystore.OpenDir(netDir)
		if err != nil {
			return createWalletError(err)
		}
	}

	// Start by prompting for the private passphrase.  When there is an
	// existing keystore, the user will be promped for that passphrase,
	// otherwise they will be prompted for a new one.
	reader := bufio.NewReader(os.Stdin)
	privPass, err := prompt.PrivatePass(reader, legacyKeyStore)
	if err != nil {
		return createWalletError(err)
	}

	// When there exists a legacy keystore, unlock it now and set up a
	// callback to import all keystore keys into the new walletdb
	// wallet
	if legacyKeyStore != nil {
		err = legacyKeyStore.Unlock(privPass)
		if err != nil {
			return createWalletError(err)
		}

		// Import the addresses in the legacy keystore to the new wallet if
		// any exist, locking each wallet again when finished.
		loader.RunAfterLoad(func(w *wallet.Wallet) {
			defer legacyKeyStore.Lock()

			fmt.Println("Importing addresses from existing wallet...")

			err := w.Manager.Unlock(privPass)
			if err != nil {
				fmt.Printf("ERR: Failed to unlock new wallet "+
					"during old wallet key import: %v", err)
				return
			}
			defer w.Manager.Lock()

			err = convertLegacyKeystore(legacyKeyStore, w.Manager)
			if err != nil {
				fmt.Printf("ERR: Failed to import keys from old "+
					"wallet format: %v", err)
				return
			}

			// Remove the legacy key store.
			err = os.Remove(keystorePath)
			if err != nil {
				fmt.Printf("WARN: Failed to remove legacy wallet "+
					"from'%s'\n", keystorePath)
			}
		})
	}

	// Ascertain the public passphrase.  This will either be a value
	// specified by the user or the default hard-coded public passphrase if
	// the user does not want the additional public data encryption.
	pubPass, err := prompt.PublicPass(reader, privPass,
		[]byte(wallet.InsecurePubPassphrase), []byte(cfg.WalletPass))
	if err != nil {
		return createWalletError(err)
	}

	// Ascertain the wallet generation seed.  This will either be an
	// automatically generated value the user has already confirmed or a
	// value the user has entered which has already been validated.
	seed, err := prompt.Seed(reader)
	if err != nil {
		return createWalletError(err)
	}

	fmt.Println("Creating the wallet...")
	_, err = loader.CreateNewWallet(pubPass, privPass, seed)
	if err != nil {
		return createWalletError(err)
	}

	fmt.Println("The wallet has been created successfully.")

	return nil
}

// createSimulationWallet is intended to be called from the rpcclient
// and used to create a wallet for actors involved in simulations.
func createSimulationWallet(cfg *config) error {
	// Simulation wallet password is 'password'.
	privPass := wallet.SimulationPassphrase

	// Public passphrase is the default.
	pubPass := []byte(wallet.InsecurePubPassphrase)

	// Generate a random seed.
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return err
	}

	netDir := networkDir(cfg.DataDir, activeNet.Params)

	// Write the seed to disk, so that we can restore it later
	// if need be, for testing purposes.
	seedStr, err := pgpwordlist.ToStringChecksum(seed)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filepath.Join(netDir, "seed"), []byte(seedStr), 0644)
	if err != nil {
		return err
	}

	// Create the wallet.
	dbPath := filepath.Join(netDir, walletDbName)
	fmt.Println("Creating the wallet...")

	// Create the wallet database backed by bolt db.
	db, err := walletdb.Create("bdb", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Create the wallet.
	err = wallet.Create(db, pubPass, privPass, seed, activeNet.Params, cfg.UnsafeMainNet)
	if err != nil {
		return err
	}

	fmt.Println("The wallet has been created successfully.")
	return nil
}

// promptHDPublicKey prompts the user for an extended public key.
func promptHDPublicKey(reader *bufio.Reader) (string, error) {
	for {
		fmt.Print("Enter HD wallet public key: ")
		keyString, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}

		keyStringTrimmed := strings.TrimSpace(keyString)

		return keyStringTrimmed, nil
	}
}

// createWatchingOnlyWallet creates a watching only wallet using the passed
// extended public key.
func createWatchingOnlyWallet(cfg *config) error {
	// Get the public key.
	reader := bufio.NewReader(os.Stdin)
	pubKeyString, err := promptHDPublicKey(reader)
	if err != nil {
		return err
	}

	// Ask if the user wants to encrypt the wallet with a password.
	pubPass, err := prompt.PublicPass(reader, []byte{},
		[]byte(wallet.InsecurePubPassphrase), []byte(cfg.WalletPass))
	if err != nil {
		return err
	}

	netDir := networkDir(cfg.DataDir, activeNet.Params)

	// Create the wallet.
	dbPath := filepath.Join(netDir, walletDbName)
	fmt.Println("Creating the wallet...")

	// Create the wallet database backed by bolt db.
	db, err := walletdb.Create("bdb", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	err = wallet.CreateWatchOnly(db, pubKeyString, pubPass, activeNet.Params)
	if err != nil {
		return err
	}

	fmt.Println("The watching only wallet has been created successfully.")
	return nil
}

// checkCreateDir checks that the path exists and is a directory.
// If path does not exist, it is created.
func checkCreateDir(path string) error {
	if fi, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// Attempt data directory creation
			if err = os.MkdirAll(path, 0700); err != nil {
				return fmt.Errorf("cannot create directory: %s", err)
			}
		} else {
			return fmt.Errorf("error checking directory: %s", err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("path '%s' is not a directory", path)
		}
	}

	return nil
}
