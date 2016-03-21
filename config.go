// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/btcsuite/btcwallet/internal/cfgutil"
	"github.com/btcsuite/btcwallet/internal/legacy/keystore"
	"github.com/btcsuite/btcwallet/netparams"
	"github.com/btcsuite/btcwallet/resources"
	"github.com/btcsuite/btcwallet/wallet"
	flags "github.com/btcsuite/go-flags"
)

const (
	defaultLogLevel         = "info"
	defaultRPCMaxClients    = 10
	defaultRPCMaxWebsockets = 25
)

type config struct {
	// General application behavior
	ConfigFile    string `short:"C" long:"configfile" description:"Path to configuration file"`
	ShowVersion   bool   `short:"V" long:"version" description:"Display version information and exit"`
	Create        bool   `long:"create" description:"Create the wallet if it does not exist"`
	CreateTemp    bool   `long:"createtemp" description:"Create a temporary simulation wallet (pass=password) in the data directory indicated; must call with --datadir"`
	DataDir       string `short:"b" long:"datadir" description:"Directory to store wallets and transactions"`
	TestNet3      bool   `long:"testnet" description:"Use the test Bitcoin network (version 3) (default mainnet)"`
	SimNet        bool   `long:"simnet" description:"Use the simulation test network (default mainnet)"`
	NoInitialLoad bool   `long:"noinitialload" description:"Defer wallet creation/opening on startup and enable loading wallets over RPC"`
	DebugLevel    string `short:"d" long:"debuglevel" description:"Logging level {trace, debug, info, warn, error, critical}"`
	LogDir        string `long:"logdir" description:"Directory to log output."`
	Profile       string `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65536"`

	// Wallet options
	WalletPass string `long:"walletpass" default-mask:"-" description:"The public wallet password -- Only required if the wallet was created with one"`

	// RPC client options
	RPCConnect       string `short:"c" long:"rpcconnect" description:"Hostname/IP and port of btcd RPC server to connect to (default localhost:8334, testnet: localhost:18334, simnet: localhost:18556)"`
	CAFile           string `long:"cafile" description:"File containing root certificates to authenticate a TLS connections with btcd"`
	DisableClientTLS bool   `long:"noclienttls" description:"Disable TLS for the RPC client -- NOTE: This is only allowed if the RPC client is connecting to localhost"`
	BtcdUsername     string `long:"btcdusername" description:"Username for btcd authentication"`
	BtcdPassword     string `long:"btcdpassword" default-mask:"-" description:"Password for btcd authentication"`
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
	LegacyRPCListeners     []string `long:"rpclisten" description:"Listen for legacy RPC connections on this interface/port (default port: 8332, testnet: 18332, simnet: 18554)"`
	LegacyRPCMaxClients    int64    `long:"rpcmaxclients" description:"Max number of legacy RPC clients for standard connections"`
	LegacyRPCMaxWebsockets int64    `long:"rpcmaxwebsockets" description:"Max number of legacy RPC websocket connections"`
	Username               string   `short:"u" long:"username" description:"Username for legacy RPC and btcd authentication (if btcdusername is unset)"`
	Password               string   `short:"P" long:"password" default-mask:"-" description:"Password for legacy RPC and btcd authentication (if btcdpassword is unset)"`

	// EXPERIMENTAL RPC server options
	//
	// These options will change (and require changes to config files, etc.)
	// when the new gRPC server is enabled.
	ExperimentalRPCListeners []string `long:"experimentalrpclisten" description:"Listen for RPC connections on this interface/port"`
}

var userHomeDirectory string

func init() {
	currentUser, err := user.Current()
	if err == nil {
		userHomeDirectory = currentUser.HomeDir
	}
}

// cleanAndExpandPath expands environement variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if userHomeDirectory != "" && strings.HasPrefix(path, "~") {
		path = strings.Replace(path, "~", userHomeDirectory, 1)
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

func isLocalhostListener(listener string) bool {
	switch listener {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
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
func loadConfig() (*config, []string, *resources.Resources, error) {
	appResources := resources.Defaults()

	// Default config.
	cfg := config{
		DebugLevel:             defaultLogLevel,
		ConfigFile:             appResources.ConfigFilePath(),
		DataDir:                appResources.ApplicationDataDirectory,
		LogDir:                 appResources.DefaultLoggingDirectory(),
		WalletPass:             wallet.InsecurePubPassphrase,
		RPCKey:                 appResources.RPCKeyFilePath(),
		RPCCert:                appResources.RPCCertificateFilePath(),
		LegacyRPCMaxClients:    defaultRPCMaxClients,
		LegacyRPCMaxWebsockets: defaultRPCMaxWebsockets,
	}

	// A config file in the current directory takes precedence.
	defaultConfigFile := appResources.ConfigFilePath()
	exists, err := cfgutil.FileExists(defaultConfigFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, nil, err
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
		return nil, nil, nil, err
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
			return nil, nil, nil, err
		}
		configFileError = err
	}

	// Parse command line options again to ensure they take precedence.
	remainingArgs, err := parser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			parser.WriteHelp(os.Stderr)
		}
		return nil, nil, nil, err
	}

	// Warn about missing config file after the final command line parse
	// succeeds.  This prevents the warning on help messages and invalid
	// options.
	if configFileError != nil {
		log.Warnf("%v", configFileError)
	}

	// Clean and expand all remaining filepaths.
	cfg.DataDir = cleanAndExpandPath(cfg.DataDir)
	cfg.RPCKey = cleanAndExpandPath(cfg.RPCKey)
	cfg.RPCCert = cleanAndExpandPath(cfg.RPCCert)
	cfg.LogDir = cleanAndExpandPath(cfg.LogDir)
	cfg.CAFile = cleanAndExpandPath(cfg.CAFile)

	// If an alternate data directory was specified, update the application
	// data directory in the resources package.  This causes resources'
	// functions to return absolute filepaths with the user-set application
	// data directory.
	//
	// When other files relative to the data directory have not been
	// modified from their defaults, update them to use the new data
	// directory.
	defaultAppDataDir := appResources.ApplicationDataDirectory
	if cfg.DataDir != defaultAppDataDir {
		defaultRPCCertificate := appResources.RPCCertificateFilePath()
		defaultRPCKey := appResources.RPCKeyFilePath()
		defaultLogDir := appResources.DefaultLoggingDirectory()

		appResources.ApplicationDataDirectory = cfg.DataDir

		if cfg.RPCCert == defaultRPCCertificate {
			cfg.RPCCert = appResources.RPCCertificateFilePath()
		}
		if cfg.RPCKey == defaultRPCKey {
			cfg.RPCKey = appResources.RPCKeyFilePath()
		}
		if cfg.LogDir == defaultLogDir {
			cfg.LogDir = appResources.DefaultLoggingDirectory()
		}

		// Consensus certificate file is unset by default, so if
		// explicitly set, use it even if it's in the default
		// application data directory.  Finding the actual cert when
		// unset is handled later.
	}

	// Choose the active network params based on the selected network.
	// Multiple networks can't be selected simultaneously.
	numNets := 0
	if cfg.TestNet3 {
		appResources.ActiveNetwork = &netparams.TestNet3Params
		numNets++
	}
	if cfg.SimNet {
		appResources.ActiveNetwork = &netparams.SimNetParams
		numNets++
	}
	if numNets > 1 {
		str := "%s: The testnet and simnet params can't be used " +
			"together -- choose one"
		err := fmt.Errorf(str, "loadConfig")
		fmt.Fprintln(os.Stderr, err)
		parser.WriteHelp(os.Stderr)
		return nil, nil, nil, err
	}

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems", supportedSubsystems())
		os.Exit(0)
	}

	// Initialize logging at the default logging level.
	initSeelogLogger(appResources.LogFilePath(cfg.LogDir))
	setLogLevels(defaultLogLevel)

	// Parse, validate, and set debug log level(s).
	if err := parseAndSetDebugLevels(cfg.DebugLevel); err != nil {
		err := fmt.Errorf("%s: %v", "loadConfig", err.Error())
		fmt.Fprintln(os.Stderr, err)
		parser.WriteHelp(os.Stderr)
		return nil, nil, nil, err
	}

	// Exit if you try to use a simulation wallet with a standard
	// data directory.
	if cfg.DataDir == defaultAppDataDir && cfg.CreateTemp {
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

	if cfg.CreateTemp && cfg.Create {
		err := fmt.Errorf("The flags --create and --createtemp can not " +
			"be specified together. Use --help for more information.")
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, nil, err
	}

	// Ensure the wallet exists or create it when the create flag is set.
	dbFilePath := appResources.DatabaseFilePath()
	dbFileExists, err := cfgutil.FileExists(dbFilePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, nil, err
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
		err := checkCreateDir(appResources.NetworkDirectory())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, nil, err
		}

		if !tempWalletExists {
			// Perform the initial wallet creation wizard.
			if err := createSimulationWallet(&cfg); err != nil {
				fmt.Fprintln(os.Stderr, "Unable to create wallet:", err)
				return nil, nil, nil, err
			}
		}
	} else if cfg.Create {
		// Error if the create flag is set and the wallet already
		// exists.
		if dbFileExists {
			err := fmt.Errorf("The wallet database file `%v` "+
				"already exists.", dbFilePath)
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, nil, err
		}

		// Ensure the data directory for the network exists.
		err := checkCreateDir(appResources.NetworkDirectory())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, nil, err
		}

		// Perform the initial wallet creation wizard.
		if err := createWallet(&cfg); err != nil {
			fmt.Fprintln(os.Stderr, "Unable to create wallet:", err)
			return nil, nil, nil, err
		}

		// Created successfully, so exit now with success.
		os.Exit(0)
	} else if !dbFileExists && !cfg.NoInitialLoad {
		keystorePath := filepath.Join(appResources.NetworkDirectory(),
			keystore.Filename)
		keystoreExists, err := cfgutil.FileExists(keystorePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, nil, err
		}
		if !keystoreExists {
			err = fmt.Errorf("The wallet does not exist.  Run with the " +
				"--create option to initialize and create it.")
		} else {
			err = fmt.Errorf("The wallet is in legacy format.  Run with the " +
				"--create option to import it.")
		}
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, nil, err
	}

	if cfg.RPCConnect == "" {
		cfg.RPCConnect = net.JoinHostPort("localhost",
			appResources.ActiveNetwork.RPCClientPort)
	}

	// Add default port to connect flag if missing.
	cfg.RPCConnect, err = cfgutil.NormalizeAddress(cfg.RPCConnect,
		appResources.ActiveNetwork.RPCClientPort)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Invalid rpcconnect network address: %v\n", err)
		return nil, nil, nil, err
	}

	RPCHost, _, err := net.SplitHostPort(cfg.RPCConnect)
	if err != nil {
		return nil, nil, nil, err
	}
	if cfg.DisableClientTLS {
		if !isLocalhostListener(RPCHost) {
			str := "%s: the --noclienttls option may not be used " +
				"when connecting RPC to non localhost " +
				"addresses: %s"
			err := fmt.Errorf(str, funcName, cfg.RPCConnect)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, nil, err
		}
	} else if cfg.CAFile == "." {
		// If TLS is enabled but the CAFile is unset, choose either the
		// local copy in the wallet's application data directory, or the
		// btcd certificate from the default btcd application data
		// directory if the copy is not found.
		cfg.CAFile = appResources.ConsensusRPCRemoteCertificateFilePath()

		// If the CA copy does not exist, check if we're connecting to
		// a local btcd and switch to its RPC cert if it exists.
		certExists, err := cfgutil.FileExists(cfg.CAFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, nil, err
		}
		if !certExists {
			if isLocalhostListener(RPCHost) {
				localCert := appResources.ConsensusRPCLocalCertificateFilePath()
				btcdCertExists, err := cfgutil.FileExists(localCert)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					return nil, nil, nil, err
				}
				if btcdCertExists {
					cfg.CAFile = appResources.ConsensusRPCDataDirectory
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
			return nil, nil, nil, err
		}
		cfg.LegacyRPCListeners = make([]string, 0, len(addrs))
		for _, addr := range addrs {
			addr = net.JoinHostPort(addr,
				appResources.ActiveNetwork.RPCServerPort)
			cfg.LegacyRPCListeners = append(cfg.LegacyRPCListeners, addr)
		}
	}

	// Add default port to all rpc listener addresses if needed and remove
	// duplicate addresses.
	cfg.LegacyRPCListeners, err = cfgutil.NormalizeAddresses(
		cfg.LegacyRPCListeners, appResources.ActiveNetwork.RPCServerPort)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Invalid network address in legacy RPC listeners: %v\n", err)
		return nil, nil, nil, err
	}
	cfg.ExperimentalRPCListeners, err = cfgutil.NormalizeAddresses(
		cfg.ExperimentalRPCListeners, appResources.ActiveNetwork.RPCServerPort)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"Invalid network address in RPC listeners: %v\n", err)
		return nil, nil, nil, err
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
				return nil, nil, nil, err
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
				return nil, nil, nil, err
			}
			if !isLocalhostListener(host) {
				str := "%s: the --noservertls option may not be used " +
					"when binding RPC to non localhost " +
					"addresses: %s"
				err := fmt.Errorf(str, funcName, addr)
				fmt.Fprintln(os.Stderr, err)
				fmt.Fprintln(os.Stderr, usageMessage)
				return nil, nil, nil, err
			}
		}
	}

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

	return &cfg, remainingArgs, &appResources, nil
}
