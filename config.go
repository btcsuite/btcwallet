// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	flags "github.com/btcsuite/go-flags"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/internal/cfgutil"
	"github.com/decred/dcrwallet/internal/legacy/keystore"
	"github.com/decred/dcrwallet/netparams"
	"github.com/decred/dcrwallet/wallet"
)

const (
	defaultCAFilename        = "dcrd.cert"
	defaultConfigFilename    = "dcrwallet.conf"
	defaultLogLevel          = "info"
	defaultLogDirname        = "logs"
	defaultLogFilename       = "dcrwallet.log"
	defaultRPCMaxClients     = 10
	defaultRPCMaxWebsockets  = 25
	defaultEnableStakeMining = false
	defaultVoteBits          = 0x0001
	defaultBalanceToMaintain = 0.0
	defaultReuseAddresses    = false
	defaultRollbackTest      = false
	defaultPruneTickets      = false
	defaultTicketMaxPrice    = 50.0
	defaultAutomaticRepair   = false
	defaultUnsafeMainNet     = false

	walletDbName = "wallet.db"
)

var (
	dcrdHomeDir        = dcrutil.AppDataDir("dcrd", false)
	dcrwalletHomeDir   = dcrutil.AppDataDir("dcrwallet", false)
	dcrdHomedirCAFile  = filepath.Join(dcrdHomeDir, "rpc.cert")
	defaultConfigFile  = filepath.Join(dcrwalletHomeDir, defaultConfigFilename)
	defaultDataDir     = dcrwalletHomeDir
	defaultRPCKeyFile  = filepath.Join(dcrwalletHomeDir, "rpc.key")
	defaultRPCCertFile = filepath.Join(dcrwalletHomeDir, "rpc.cert")
	defaultLogDir      = filepath.Join(dcrwalletHomeDir, defaultLogDirname)
)

type config struct {
	// General application behavior
	ConfigFile         string `short:"C" long:"configfile" description:"Path to configuration file"`
	ShowVersion        bool   `short:"V" long:"version" description:"Display version information and exit"`
	Create             bool   `long:"create" description:"Create the wallet if it does not exist"`
	CreateTemp         bool   `long:"createtemp" description:"Create a temporary simulation wallet (pass=password) in the data directory indicated; must call with --datadir"`
	CreateWatchingOnly bool   `long:"createwatchingonly" description:"Create the wallet and instantiate it as watching only with an HD extended pubkey; must call with --create"`
	DataDir            string `short:"b" long:"datadir" description:"Directory to store wallets and transactions"`
	TestNet            bool   `long:"testnet" description:"Use the test network (default mainnet)"`
	SimNet             bool   `long:"simnet" description:"Use the simulation test network (default mainnet)"`
	NoInitialLoad      bool   `long:"noinitialload" description:"Defer wallet creation/opening on startup and enable loading wallets over RPC"`
	DebugLevel         string `short:"d" long:"debuglevel" description:"Logging level {trace, debug, info, warn, error, critical}"`
	LogDir             string `long:"logdir" description:"Directory to log output."`
	Profile            string `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65536"`
	MemProfile         string `long:"memprofile" description:"Write mem profile to the specified file"`
	RollbackTest       bool   `long:"rollbacktest" description:"Rollback testing is a simnet testing mode that eventually stops wallet and examines wtxmgr database integrity"`
	AutomaticRepair    bool   `long:"automaticrepair" description:"Attempt to repair the wallet automatically if a database inconsistency is found"`
	UnsafeMainNet      bool   `long:"unsafemainnet" description:"Enable storage of master seed in mainnet wallet when calling --create and enable unsafe private information RPC commands"`

	// Wallet options
	WalletPass        string  `long:"walletpass" default-mask:"-" description:"The public wallet password -- Only required if the wallet was created with one"`
	DisallowFree      bool    `long:"disallowfree" description:"Force transactions to always include a fee"`
	EnableStakeMining bool    `long:"enablestakemining" description:"Enable stake mining"`
	VoteBits          uint16  `long:"votebits" description:"Set your stake mining votebits to value (default: 0xFFFF)"`
	BalanceToMaintain float64 `long:"balancetomaintain" description:"Minimum amount of funds to leave in wallet when stake mining (default: 0.0)"`
	ReuseAddresses    bool    `long:"reuseaddresses" description:"Reuse addresses for ticket purchase to cut down on address overuse"`
	PruneTickets      bool    `long:"prunetickets" description:"Prune old tickets from the wallet and restore their inputs"`
	TicketAddress     string  `long:"ticketaddress" description:"Send all ticket outputs to this address (P2PKH or P2SH only)"`
	TicketMaxPrice    float64 `long:"ticketmaxprice" description:"The maximum price the user is willing to spend on buying a ticket"`

	// RPC client options
	RPCConnect       string `short:"c" long:"rpcconnect" description:"Hostname/IP and port of dcrd RPC server to connect to (default localhost:9109, testnet: localhost:19109, simnet: localhost:18556)"`
	CAFile           string `long:"cafile" description:"File containing root certificates to authenticate a TLS connections with dcrd"`
	DisableClientTLS bool   `long:"noclienttls" description:"Disable TLS for the RPC client -- NOTE: This is only allowed if the RPC client is connecting to localhost"`
	DcrdUsername     string `long:"dcrdusername" description:"Username for dcrd authentication"`
	DcrdPassword     string `long:"dcrdpassword" default-mask:"-" description:"Password for dcrd authentication"`
	Proxy            string `long:"proxy" description:"Connect via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	ProxyUser        string `long:"proxyuser" description:"Username for proxy server"`
	ProxyPass        string `long:"proxypass" default-mask:"-" description:"Password for proxy server"`

	// RPC server options
	//
	// The legacy server is still enabled by default (and eventually will be
	// replaced with the experimental server) so prepare for that change by
	// renaming the struct fields (but not the configuration options).
	//
	// Usernames can also be used for the consensus RPC client, so they
	// aren't considered legacy.
	RPCCert                string   `long:"rpccert" description:"File containing the certificate file"`
	RPCKey                 string   `long:"rpckey" description:"File containing the certificate key"`
	OneTimeTLSKey          bool     `long:"onetimetlskey" description:"Generate a new TLS certpair at startup, but only write the certificate to disk"`
	DisableServerTLS       bool     `long:"noservertls" description:"Disable TLS for the RPC server -- NOTE: This is only allowed if the RPC server is bound to localhost"`
	LegacyRPCListeners     []string `long:"rpclisten" description:"Listen for legacy RPC connections on this interface/port (default port: 9110, testnet: 19110, simnet: 18557)"`
	LegacyRPCMaxClients    int64    `long:"rpcmaxclients" description:"Max number of legacy RPC clients for standard connections"`
	LegacyRPCMaxWebsockets int64    `long:"rpcmaxwebsockets" description:"Max number of legacy RPC websocket connections"`
	Username               string   `short:"u" long:"username" description:"Username for legacy RPC and dcrd authentication (if dcrdusername is unset)"`
	Password               string   `short:"P" long:"password" default-mask:"-" description:"Password for legacy RPC and dcrd authentication (if dcrdpassword is unset)"`

	// EXPERIMENTAL RPC server options
	//
	// These options will change (and require changes to config files, etc.)
	// when the new gRPC server is enabled.
	ExperimentalRPCListeners []string `long:"experimentalrpclisten" description:"Listen for RPC connections on this interface/port"`
}

// cleanAndExpandPath expands environement variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(dcrwalletHomeDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows cmd.exe-style
	// %VARIABLE%, but they variables can still be expanded via POSIX-style
	// $VARIABLE.
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
// The above results in dcrwallet functioning properly without any config
// settings while still allowing the user to override settings with config files
// and command line options.  Command line options always take precedence.
func loadConfig() (*config, []string, error) {
	// Default config.
	cfg := config{
		DebugLevel:             defaultLogLevel,
		ConfigFile:             defaultConfigFile,
		DataDir:                defaultDataDir,
		LogDir:                 defaultLogDir,
		WalletPass:             wallet.InsecurePubPassphrase,
		RPCKey:                 defaultRPCKeyFile,
		RPCCert:                defaultRPCCertFile,
		LegacyRPCMaxClients:    defaultRPCMaxClients,
		LegacyRPCMaxWebsockets: defaultRPCMaxWebsockets,
		EnableStakeMining:      defaultEnableStakeMining,
		VoteBits:               defaultVoteBits,
		BalanceToMaintain:      defaultBalanceToMaintain,
		ReuseAddresses:         defaultReuseAddresses,
		RollbackTest:           defaultRollbackTest,
		PruneTickets:           defaultPruneTickets,
		TicketMaxPrice:         defaultTicketMaxPrice,
		AutomaticRepair:        defaultAutomaticRepair,
		UnsafeMainNet:          defaultUnsafeMainNet,
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
	if cfg.TestNet {
		activeNet = &netparams.TestNetParams
		numNets++
	}
	if cfg.SimNet {
		activeNet = &netparams.SimNetParams
		numNets++
	}
	if numNets > 1 {
		str := "%s: The testnet and simnet params can't be used " +
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
	// simnet or testnet.
	if !cfg.SimNet && cfg.CreateTemp {
		fmt.Fprintln(os.Stderr, "Tried to create a temporary simulation "+
			"wallet for network other than simnet!")
		os.Exit(0)
	}

	// Exit if you tried to do rollback testing on a network other than
	// simnet.
	if cfg.RollbackTest && !cfg.SimNet {
		fmt.Fprintln(os.Stderr, "Tried to do rollback testing of "+
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
			err := fmt.Errorf("The wallet database file `%v` "+
				"already exists.", dbPath)
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, err
		}

		// Ensure the data directory for the network exists.
		if err := checkCreateDir(netDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, err
		}

		// Perform the initial wallet creation wizard.
		if !cfg.CreateWatchingOnly {
			if err := createWallet(&cfg); err != nil {
				fmt.Fprintln(os.Stderr, "Unable to create wallet:", err)
				return nil, nil, err
			}
		} else if cfg.CreateWatchingOnly {
			if err := createWatchingOnlyWallet(&cfg); err != nil {
				fmt.Fprintln(os.Stderr, "Unable to create wallet:", err)
				return nil, nil, err
			}
		}

		// Created successfully, so exit now with success.
		os.Exit(0)
	} else if !dbFileExists && !cfg.NoInitialLoad {
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

	if len(cfg.TicketAddress) != 0 {
		_, err := dcrutil.DecodeAddress(cfg.TicketAddress, activeNet.Params)
		if err != nil {
			str := "%s: ticketaddress '%s' failed to decode: %v"
			err := fmt.Errorf(str, funcName, cfg.TicketAddress, err)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
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
		// If CAFile is unset, choose either the copy or local dcrd cert.
		if cfg.CAFile == "" {
			cfg.CAFile = filepath.Join(cfg.DataDir, defaultCAFilename)

			// If the CA copy does not exist, check if we're connecting to
			// a local dcrd and switch to its RPC cert if it exists.
			certExists, err := cfgutil.FileExists(cfg.CAFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return nil, nil, err
			}
			if !certExists {
				if _, ok := localhostListeners[RPCHost]; ok {
					dcrdCertExists, err := cfgutil.FileExists(
						dcrdHomedirCAFile)
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
						return nil, nil, err
					}
					if dcrdCertExists {
						cfg.CAFile = dcrdHomedirCAFile
					}
				}
			}
		}
	}

	// Only set default RPC listeners when there are no listeners set for
	// the experimental RPC server.  This is required to prevent the old RPC
	// server from sharing listen addresses, since it is impossible to
	// remove defaults from go-flags slice options without assigning
	// specific behavior to a particular string.
	if len(cfg.ExperimentalRPCListeners) == 0 && len(cfg.LegacyRPCListeners) == 0 {
		addrs, err := net.LookupHost("localhost")
		if err != nil {
			return nil, nil, err
		}
		cfg.LegacyRPCListeners = make([]string, 0, len(addrs))
		for _, addr := range addrs {
			addr = net.JoinHostPort(addr, activeNet.RPCServerPort)
			cfg.LegacyRPCListeners = append(cfg.LegacyRPCListeners, addr)
		}
	}

	// Add default port to all rpc listener addresses if needed and remove
	// duplicate addresses.
	cfg.LegacyRPCListeners, err = cfgutil.NormalizeAddresses(
		cfg.LegacyRPCListeners, activeNet.RPCServerPort)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Invalid network address in legacy RPC listeners: %v\n", err)
		return nil, nil, err
	}
	cfg.ExperimentalRPCListeners, err = cfgutil.NormalizeAddresses(
		cfg.ExperimentalRPCListeners, activeNet.RPCServerPort)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Invalid network address in RPC listeners: %v\n", err)
		return nil, nil, err
	}

	// Both RPC servers may not listen on the same interface/port.
	if len(cfg.LegacyRPCListeners) > 0 && len(cfg.ExperimentalRPCListeners) > 0 {
		seenAddresses := make(map[string]struct{}, len(cfg.LegacyRPCListeners))
		for _, addr := range cfg.LegacyRPCListeners {
			seenAddresses[addr] = struct{}{}
		}
		for _, addr := range cfg.ExperimentalRPCListeners {
			_, seen := seenAddresses[addr]
			if seen {
				err := fmt.Errorf("Address `%s` may not be "+
					"used as a listener address for both "+
					"RPC servers", addr)
				fmt.Fprintln(os.Stderr, err)
				return nil, nil, err
			}
		}
	}

	// Only allow server TLS to be disabled if the RPC server is bound to
	// localhost addresses.
	if cfg.DisableServerTLS {
		allListeners := append(cfg.LegacyRPCListeners,
			cfg.ExperimentalRPCListeners...)
		for _, addr := range allListeners {
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

	// If the dcrd username or password are unset, use the same auth as for
	// the client.  The two settings were previously shared for dcrd and
	// client auth, so this avoids breaking backwards compatibility while
	// allowing users to use different auth settings for dcrd and wallet.
	if cfg.DcrdUsername == "" {
		cfg.DcrdUsername = cfg.Username
	}
	if cfg.DcrdPassword == "" {
		cfg.DcrdPassword = cfg.Password
	}

	return &cfg, remainingArgs, nil
}
