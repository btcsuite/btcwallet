/*
 * Copyright (c) 2013, 2014 The btcsuite developers
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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/internal/cfgutil"
	"github.com/btcsuite/btcwallet/internal/legacy/keystore"
	"github.com/btcsuite/btcwallet/netparams"
	flags "github.com/btcsuite/go-flags"
)

const (
	defaultCAFilename       = "btcd.cert"
	defaultConfigFilename   = "btcwallet.conf"
	defaultLogLevel         = "info"
	defaultLogDirname       = "logs"
	defaultLogFilename      = "btcwallet.log"
	defaultDisallowFree     = false
	defaultRPCMaxClients    = 10
	defaultRPCMaxWebsockets = 25

	// defaultPubPassphrase is the default public wallet passphrase which is
	// used when the user indicates they do not want additional protection
	// provided by having all public data in the wallet encrypted by a
	// passphrase only known to them.
	defaultPubPassphrase = "public"

	// maxEmptyAccounts is the number of accounts to scan even if they have no
	// transaction history. This is a deviation from BIP044 to make account
	// creation easier by allowing a limited number of empty accounts.
	maxEmptyAccounts = 100

	walletDbName = "wallet.db"
)

var (
	btcdHomeDir        = btcutil.AppDataDir("btcd", false)
	btcwalletHomeDir   = btcutil.AppDataDir("btcwallet", false)
	btcdHomedirCAFile  = filepath.Join(btcdHomeDir, "rpc.cert")
	defaultConfigFile  = filepath.Join(btcwalletHomeDir, defaultConfigFilename)
	defaultDataDir     = btcwalletHomeDir
	defaultRPCKeyFile  = filepath.Join(btcwalletHomeDir, "rpc.key")
	defaultRPCCertFile = filepath.Join(btcwalletHomeDir, "rpc.cert")
	defaultLogDir      = filepath.Join(btcwalletHomeDir, defaultLogDirname)
)

type config struct {
	ShowVersion      bool     `short:"V" long:"version" description:"Display version information and exit"`
	Create           bool     `long:"create" description:"Create the wallet if it does not exist"`
	CreateTemp       bool     `long:"createtemp" description:"Create a temporary simulation wallet (pass=password) in the data directory indicated; must call with --datadir"`
	CAFile           string   `long:"cafile" description:"File containing root certificates to authenticate a TLS connections with btcd"`
	RPCConnect       string   `short:"c" long:"rpcconnect" description:"Hostname/IP and port of btcd RPC server to connect to (default localhost:18334, mainnet: localhost:8334, simnet: localhost:18556)"`
	DebugLevel       string   `short:"d" long:"debuglevel" description:"Logging level {trace, debug, info, warn, error, critical}"`
	ConfigFile       string   `short:"C" long:"configfile" description:"Path to configuration file"`
	SvrListeners     []string `long:"rpclisten" description:"Listen for RPC/websocket connections on this interface/port (default port: 18332, mainnet: 8332, simnet: 18554)"`
	DataDir          string   `short:"D" long:"datadir" description:"Directory to store wallets and transactions"`
	LogDir           string   `long:"logdir" description:"Directory to log output."`
	Username         string   `short:"u" long:"username" description:"Username for client and btcd authorization"`
	Password         string   `short:"P" long:"password" default-mask:"-" description:"Password for client and btcd authorization"`
	BtcdUsername     string   `long:"btcdusername" description:"Alternative username for btcd authorization"`
	BtcdPassword     string   `long:"btcdpassword" default-mask:"-" description:"Alternative password for btcd authorization"`
	WalletPass       string   `long:"walletpass" default-mask:"-" description:"The public wallet password -- Only required if the wallet was created with one"`
	RPCCert          string   `long:"rpccert" description:"File containing the certificate file"`
	RPCKey           string   `long:"rpckey" description:"File containing the certificate key"`
	RPCMaxClients    int64    `long:"rpcmaxclients" description:"Max number of RPC clients for standard connections"`
	RPCMaxWebsockets int64    `long:"rpcmaxwebsockets" description:"Max number of RPC websocket connections"`
	DisableServerTLS bool     `long:"noservertls" description:"Disable TLS for the RPC server -- NOTE: This is only allowed if the RPC server is bound to localhost"`
	DisableClientTLS bool     `long:"noclienttls" description:"Disable TLS for the RPC client -- NOTE: This is only allowed if the RPC client is connecting to localhost"`
	MainNet          bool     `long:"mainnet" description:"Use the main Bitcoin network (default testnet3)"`
	SimNet           bool     `long:"simnet" description:"Use the simulation test network (default testnet3)"`
	KeypoolSize      uint     `short:"k" long:"keypoolsize" description:"DEPRECATED -- Maximum number of addresses in keypool"`
	DisallowFree     bool     `long:"disallowfree" description:"Force transactions to always include a fee"`
	Proxy            string   `long:"proxy" description:"Connect via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	ProxyUser        string   `long:"proxyuser" description:"Username for proxy server"`
	ProxyPass        string   `long:"proxypass" default-mask:"-" description:"Password for proxy server"`
	Profile          string   `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65536"`
}

// cleanAndExpandPath expands environement variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(btcwalletHomeDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but they variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// validLogLevel returns whether or not logLevel is a valid debug log level.
func validLogLevel(logLevel string) bool {
	switch logLevel {
	case "trace":
		fallthrough
	case "debug":
		fallthrough
	case "info":
		fallthrough
	case "warn":
		fallthrough
	case "error":
		fallthrough
	case "critical":
		return true
	}
	return false
}

// supportedSubsystems returns a sorted slice of the supported subsystems for
// logging purposes.
func supportedSubsystems() []string {
	// Convert the subsystemLoggers map keys to a slice.
	subsystems := make([]string, 0, len(subsystemLoggers))
	for subsysID := range subsystemLoggers {
		subsystems = append(subsystems, subsysID)
	}

	// Sort the subsytems for stable display.
	sort.Strings(subsystems)
	return subsystems
}

// parseAndSetDebugLevels attempts to parse the specified debug level and set
// the levels accordingly.  An appropriate error is returned if anything is
// invalid.
func parseAndSetDebugLevels(debugLevel string) error {
	// When the specified string doesn't have any delimters, treat it as
	// the log level for all subsystems.
	if !strings.Contains(debugLevel, ",") && !strings.Contains(debugLevel, "=") {
		// Validate debug log level.
		if !validLogLevel(debugLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, debugLevel)
		}

		// Change the logging level for all subsystems.
		setLogLevels(debugLevel)

		return nil
	}

	// Split the specified string into subsystem/level pairs while detecting
	// issues and update the log levels accordingly.
	for _, logLevelPair := range strings.Split(debugLevel, ",") {
		if !strings.Contains(logLevelPair, "=") {
			str := "The specified debug level contains an invalid " +
				"subsystem/level pair [%v]"
			return fmt.Errorf(str, logLevelPair)
		}

		// Extract the specified subsystem and log level.
		fields := strings.Split(logLevelPair, "=")
		subsysID, logLevel := fields[0], fields[1]

		// Validate subsystem.
		if _, exists := subsystemLoggers[subsysID]; !exists {
			str := "The specified subsystem [%v] is invalid -- " +
				"supported subsytems %v"
			return fmt.Errorf(str, subsysID, supportedSubsystems())
		}

		// Validate log level.
		if !validLogLevel(logLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, logLevel)
		}

		setLogLevel(subsysID, logLevel)
	}

	return nil
}

// loadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
//      1) Start with a default config with sane settings
//      2) Pre-parse the command line to check for an alternative config file
//      3) Load configuration file overwriting defaults with any specified options
//      4) Parse CLI options and overwrite/add any specified options
//
// The above results in btcwallet functioning properly without any config
// settings while still allowing the user to override settings with config files
// and command line options.  Command line options always take precedence.
func loadConfig() (*config, []string, error) {
	// Default config.
	cfg := config{
		DebugLevel:       defaultLogLevel,
		ConfigFile:       defaultConfigFile,
		DataDir:          defaultDataDir,
		LogDir:           defaultLogDir,
		WalletPass:       defaultPubPassphrase,
		RPCKey:           defaultRPCKeyFile,
		RPCCert:          defaultRPCCertFile,
		DisallowFree:     defaultDisallowFree,
		RPCMaxClients:    defaultRPCMaxClients,
		RPCMaxWebsockets: defaultRPCMaxWebsockets,
	}

	// A config file in the current directory takes precedence.
	exists, err := cfgutil.FileExists(defaultConfigFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}
	if exists {
		cfg.ConfigFile = defaultConfigFile
	}

	// Pre-parse the command line options to see if an alternative config
	// file or the version flag was specified.
	preCfg := cfg
	preParser := flags.NewParser(&preCfg, flags.Default)
	_, err = preParser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			preParser.WriteHelp(os.Stderr)
		}
		return nil, nil, err
	}

	// Show the version and exit if the version flag was specified.
	funcName := "loadConfig"
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)
	if preCfg.ShowVersion {
		fmt.Println(appName, "version", version())
		os.Exit(0)
	}

	// Load additional config from file.
	var configFileError error
	parser := flags.NewParser(&cfg, flags.Default)
	err = flags.NewIniParser(parser).ParseFile(preCfg.ConfigFile)
	if err != nil {
		if _, ok := err.(*os.PathError); !ok {
			fmt.Fprintln(os.Stderr, err)
			parser.WriteHelp(os.Stderr)
			return nil, nil, err
		}
		configFileError = err
	}

	// Parse command line options again to ensure they take precedence.
	remainingArgs, err := parser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			parser.WriteHelp(os.Stderr)
		}
		return nil, nil, err
	}

	// Warn about missing config file after the final command line parse
	// succeeds.  This prevents the warning on help messages and invalid
	// options.
	if configFileError != nil {
		log.Warnf("%v", configFileError)
	}

	// If an alternate data directory was specified, and paths with defaults
	// relative to the data dir are unchanged, modify each path to be
	// relative to the new data dir.
	if cfg.DataDir != defaultDataDir {
		if cfg.RPCKey == defaultRPCKeyFile {
			cfg.RPCKey = filepath.Join(cfg.DataDir, "rpc.key")
		}
		if cfg.RPCCert == defaultRPCCertFile {
			cfg.RPCCert = filepath.Join(cfg.DataDir, "rpc.cert")
		}
	}

	// Choose the active network params based on the selected network.
	// Multiple networks can't be selected simultaneously.
	numNets := 0
	if cfg.MainNet {
		activeNet = &netparams.MainNetParams
		numNets++
	}
	if cfg.SimNet {
		activeNet = &netparams.SimNetParams
		numNets++
	}
	if numNets > 1 {
		str := "%s: The mainnet and simnet params can't be used " +
			"together -- choose one"
		err := fmt.Errorf(str, "loadConfig")
		fmt.Fprintln(os.Stderr, err)
		parser.WriteHelp(os.Stderr)
		return nil, nil, err
	}

	// Append the network type to the log directory so it is "namespaced"
	// per network.
	cfg.LogDir = cleanAndExpandPath(cfg.LogDir)
	cfg.LogDir = filepath.Join(cfg.LogDir, activeNet.Params.Name)

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems", supportedSubsystems())
		os.Exit(0)
	}

	// Initialize logging at the default logging level.
	initSeelogLogger(filepath.Join(cfg.LogDir, defaultLogFilename))
	setLogLevels(defaultLogLevel)

	// Parse, validate, and set debug log level(s).
	if err := parseAndSetDebugLevels(cfg.DebugLevel); err != nil {
		err := fmt.Errorf("%s: %v", "loadConfig", err.Error())
		fmt.Fprintln(os.Stderr, err)
		parser.WriteHelp(os.Stderr)
		return nil, nil, err
	}

	// Exit if you try to use a simulation wallet with a standard
	// data directory.
	if cfg.DataDir == defaultDataDir && cfg.CreateTemp {
		fmt.Fprintln(os.Stderr, "Tried to create a temporary simulation "+
			"wallet, but failed to specify data directory!")
		os.Exit(0)
	}

	// Exit if you try to use a simulation wallet on anything other than
	// simnet or testnet3.
	if !cfg.SimNet && cfg.CreateTemp {
		fmt.Fprintln(os.Stderr, "Tried to create a temporary simulation "+
			"wallet for network other than simnet!")
		os.Exit(0)
	}

	// Ensure the wallet exists or create it when the create flag is set.
	netDir := networkDir(cfg.DataDir, activeNet.Params)
	dbPath := filepath.Join(netDir, walletDbName)

	if cfg.CreateTemp && cfg.Create {
		err := fmt.Errorf("The flags --create and --createtemp can not " +
			"be specified together. Use --help for more information.")
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}

	dbFileExists, err := cfgutil.FileExists(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}

	if cfg.CreateTemp {
		tempWalletExists := false

		if dbFileExists {
			str := fmt.Sprintf("The wallet already exists. Loading this " +
				"wallet instead.")
			fmt.Fprintln(os.Stdout, str)
			tempWalletExists = true
		}

		// Ensure the data directory for the network exists.
		if err := checkCreateDir(netDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, err
		}

		if !tempWalletExists {
			// Perform the initial wallet creation wizard.
			if err := createSimulationWallet(&cfg); err != nil {
				fmt.Fprintln(os.Stderr, "Unable to create wallet:", err)
				return nil, nil, err
			}
		}
	} else if cfg.Create {
		// Error if the create flag is set and the wallet already
		// exists.
		if dbFileExists {
			err := fmt.Errorf("The wallet already exists.")
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, err
		}

		// Ensure the data directory for the network exists.
		if err := checkCreateDir(netDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, err
		}

		// Perform the initial wallet creation wizard.
		if err := createWallet(&cfg); err != nil {
			fmt.Fprintln(os.Stderr, "Unable to create wallet:", err)
			return nil, nil, err
		}

		// Created successfully, so exit now with success.
		os.Exit(0)
	} else if !dbFileExists {
		keystorePath := filepath.Join(netDir, keystore.Filename)
		keystoreExists, err := cfgutil.FileExists(keystorePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, err
		}
		if !keystoreExists {
			err = fmt.Errorf("The wallet does not exist.  Run with the " +
				"--create option to initialize and create it.")
		} else {
			err = fmt.Errorf("The wallet is in legacy format.  Run with the " +
				"--create option to import it.")
		}
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}

	if cfg.RPCConnect == "" {
		cfg.RPCConnect = net.JoinHostPort("localhost", activeNet.RPCClientPort)
	}

	// Add default port to connect flag if missing.
	cfg.RPCConnect, err = cfgutil.NormalizeAddress(cfg.RPCConnect,
		activeNet.RPCClientPort)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Invalid rpcconnect network address: %v\n", err)
		return nil, nil, err
	}

	localhostListeners := map[string]struct{}{
		"localhost": struct{}{},
		"127.0.0.1": struct{}{},
		"::1":       struct{}{},
	}
	RPCHost, _, err := net.SplitHostPort(cfg.RPCConnect)
	if err != nil {
		return nil, nil, err
	}
	if cfg.DisableClientTLS {
		if _, ok := localhostListeners[RPCHost]; !ok {
			str := "%s: the --noclienttls option may not be used " +
				"when connecting RPC to non localhost " +
				"addresses: %s"
			err := fmt.Errorf(str, funcName, cfg.RPCConnect)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
	} else {
		// If CAFile is unset, choose either the copy or local btcd cert.
		if cfg.CAFile == "" {
			cfg.CAFile = filepath.Join(cfg.DataDir, defaultCAFilename)

			// If the CA copy does not exist, check if we're connecting to
			// a local btcd and switch to its RPC cert if it exists.
			certExists, err := cfgutil.FileExists(cfg.CAFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return nil, nil, err
			}
			if !certExists {
				if _, ok := localhostListeners[RPCHost]; ok {
					btcdCertExists, err := cfgutil.FileExists(
						btcdHomedirCAFile)
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
						return nil, nil, err
					}
					if btcdCertExists {
						cfg.CAFile = btcdHomedirCAFile
					}
				}
			}
		}
	}

	if len(cfg.SvrListeners) == 0 {
		addrs, err := net.LookupHost("localhost")
		if err != nil {
			return nil, nil, err
		}
		cfg.SvrListeners = make([]string, 0, len(addrs))
		for _, addr := range addrs {
			addr = net.JoinHostPort(addr, activeNet.RPCServerPort)
			cfg.SvrListeners = append(cfg.SvrListeners, addr)
		}
	}

	// Add default port to all rpc listener addresses if needed and remove
	// duplicate addresses.
	cfg.SvrListeners, err = cfgutil.NormalizeAddresses(
		cfg.SvrListeners, activeNet.RPCServerPort)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Invalid network address in RPC listeners: %v\n", err)
		return nil, nil, err
	}

	// Only allow server TLS to be disabled if the RPC is bound to localhost
	// addresses.
	if cfg.DisableServerTLS {
		for _, addr := range cfg.SvrListeners {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				str := "%s: RPC listen interface '%s' is " +
					"invalid: %v"
				err := fmt.Errorf(str, funcName, addr, err)
				fmt.Fprintln(os.Stderr, err)
				fmt.Fprintln(os.Stderr, usageMessage)
				return nil, nil, err
			}
			if _, ok := localhostListeners[host]; !ok {
				str := "%s: the --noservertls option may not be used " +
					"when binding RPC to non localhost " +
					"addresses: %s"
				err := fmt.Errorf(str, funcName, addr)
				fmt.Fprintln(os.Stderr, err)
				fmt.Fprintln(os.Stderr, usageMessage)
				return nil, nil, err
			}
		}
	}

	// Expand environment variable and leading ~ for filepaths.
	cfg.CAFile = cleanAndExpandPath(cfg.CAFile)

	// If the btcd username or password are unset, use the same auth as for
	// the client.  The two settings were previously shared for btcd and
	// client auth, so this avoids breaking backwards compatibility while
	// allowing users to use different auth settings for btcd and wallet.
	if cfg.BtcdUsername == "" {
		cfg.BtcdUsername = cfg.Username
	}
	if cfg.BtcdPassword == "" {
		cfg.BtcdPassword = cfg.Password
	}

	return &cfg, remainingArgs, nil
}
