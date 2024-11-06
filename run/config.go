// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package run

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	flags "github.com/jessevdk/go-flags"
	"github.com/lightninglabs/neutrino"
	"github.com/stroomnetwork/btcwallet/cfgutil"
	"github.com/stroomnetwork/btcwallet/netparams"
	"github.com/stroomnetwork/btcwallet/wallet"
)

const (
	defaultCAFilename       = "btcd.cert"
	defaultConfigFilename   = "btcwallet.conf"
	defaultLogLevel         = "info"
	defaultLogDirname       = "logs"
	defaultLogFilename      = "btcwallet.log"
	defaultRPCMaxClients    = 10
	defaultRPCMaxWebsockets = 25
)

var (
	btcdDefaultCAFile  = filepath.Join(btcutil.AppDataDir("btcd", false), "rpc.cert")
	defaultAppDataDir  = btcutil.AppDataDir("btcwallet", false)
	defaultConfigFile  = filepath.Join(defaultAppDataDir, defaultConfigFilename)
	defaultRPCKeyFile  = filepath.Join(defaultAppDataDir, "rpc.key")
	defaultRPCCertFile = filepath.Join(defaultAppDataDir, "rpc.cert")
	defaultLogDir      = filepath.Join(defaultAppDataDir, defaultLogDirname)
)

type Config struct {
	// General application behavior
	ConfigFile      *cfgutil.ExplicitString `short:"C" long:"configfile" description:"Path to configuration file"`
	ShowVersion     bool                    `short:"V" long:"version" description:"Display version information and exit"`
	Create          bool                    `long:"create" description:"Create the wallet if it does not exist"`
	CreateTemp      bool                    `long:"createtemp" description:"Create a temporary simulation wallet (pass=password) in the data directory indicated; must call with --datadir"`
	AppDataDir      *cfgutil.ExplicitString `short:"A" long:"appdata" description:"Application data directory for wallet config, databases and logs"`
	Regtest         bool                    `long:"regtest" description:"Use the test Bitcoin regtest network (default mainnet)"`
	TestNet3        bool                    `long:"testnet" description:"Use the test Bitcoin network (version 3) (default mainnet)"`
	TestNet4        bool                    `long:"testnet4" description:"Use the test Bitcoin network (version 4) (default mainnet)"`
	SimNet          bool                    `long:"simnet" description:"Use the simulation test network (default mainnet)"`
	SigNet          bool                    `long:"signet" description:"Use the signet test network (default mainnet)"`
	SigNetChallenge string                  `long:"signetchallenge" description:"Connect to a custom signet network defined by this challenge instead of using the global default signet test network -- Can be specified multiple times"`
	SigNetSeedNode  []string                `long:"signetseednode" description:"Specify a seed node for the signet network instead of using the global default signet network seed nodes"`
	NoInitialLoad   bool                    `long:"noinitialload" description:"Defer wallet creation/opening on startup and enable loading wallets over RPC"`
	DebugLevel      string                  `short:"d" long:"debuglevel" description:"Logging level {trace, debug, info, warn, error, critical}"`
	LogDir          string                  `long:"logdir" description:"Directory to log output."`
	Profile         string                  `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65536"`
	DBTimeout       time.Duration           `long:"dbtimeout" description:"The timeout value to use when opening the wallet database."`

	// Feature flags used for fallback to the original implementation
	CanConsolePrompt bool `long:"canconsoleprompt" description:"Enable interaction with Stdin, wallet options are obtained from the configuration provided otherwise"`

	// Wallet options
	WalletPrivatePass string `long:"walletprivatepass" default-mask:"-" description:"The private wallet passphrase"`
	WalletPass        string `long:"walletpass" default-mask:"-" description:"The public wallet passphrase -- Only required if the wallet was created with one"`

	// RPC client options
	RPCConnect       string                  `short:"c" long:"rpcconnect" description:"Hostname/IP and port of btcd RPC server to connect to (default localhost:8334, testnet: localhost:18334, simnet: localhost:18556)"`
	CAFile           *cfgutil.ExplicitString `long:"cafile" description:"File containing root certificates to authenticate a TLS connections with btcd"`
	DisableClientTLS bool                    `long:"noclienttls" description:"Disable TLS for the RPC client -- NOTE: This is only allowed if the RPC client is connecting to localhost"`
	BtcdUsername     string                  `long:"btcdusername" description:"Username for btcd authentication"`
	BtcdPassword     string                  `long:"btcdpassword" default-mask:"-" description:"Password for btcd authentication"`
	Proxy            string                  `long:"proxy" description:"Connect via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	ProxyUser        string                  `long:"proxyuser" description:"Username for proxy server"`
	ProxyPass        string                  `long:"proxypass" default-mask:"-" description:"Password for proxy server"`

	// SPV client options
	UseSPV       bool          `long:"usespv" description:"Enables the experimental use of SPV rather than RPC for chain synchronization"`
	AddPeers     []string      `short:"a" long:"addpeer" description:"Add a peer to connect with at startup"`
	ConnectPeers []string      `long:"connect" description:"Connect only to the specified peers at startup"`
	MaxPeers     int           `long:"maxpeers" description:"Max number of inbound and outbound peers"`
	BanDuration  time.Duration `long:"banduration" description:"How long to ban misbehaving peers.  Valid time units are {s, m, h}.  Minimum 1 second"`
	BanThreshold uint32        `long:"banthreshold" description:"Maximum allowed ban score before disconnecting and banning misbehaving peers."`

	// RPC server options
	//
	// The legacy server is still enabled by default (and eventually will be
	// replaced with the experimental server) so prepare for that change by
	// renaming the struct fields (but not the configuration options).
	//
	// Usernames can also be used for the consensus RPC client, so they
	// aren't considered legacy.
	RPCCert                *cfgutil.ExplicitString `long:"rpccert" description:"File containing the certificate file"`
	RPCKey                 *cfgutil.ExplicitString `long:"rpckey" description:"File containing the certificate key"`
	OneTimeTLSKey          bool                    `long:"onetimetlskey" description:"Generate a new TLS certpair at startup, but only write the certificate to disk"`
	DisableServerTLS       bool                    `long:"noservertls" description:"Disable TLS for the RPC server -- NOTE: This is only allowed if the RPC server is bound to localhost"`
	LegacyRPCListeners     []string                `long:"rpclisten" description:"Listen for legacy RPC connections on this interface/port (default port: 8332, testnet: 18332, simnet: 18554)"`
	LegacyRPCMaxClients    int64                   `long:"rpcmaxclients" description:"Max number of legacy RPC clients for standard connections"`
	LegacyRPCMaxWebsockets int64                   `long:"rpcmaxwebsockets" description:"Max number of legacy RPC websocket connections"`
	Username               string                  `short:"u" long:"username" description:"Username for legacy RPC and btcd authentication (if btcdusername is unset)"`
	Password               string                  `short:"P" long:"password" default-mask:"-" description:"Password for legacy RPC and btcd authentication (if btcdpassword is unset)"`

	// EXPERIMENTAL RPC server options
	//
	// These options will change (and require changes to config files, etc.)
	// when the new gRPC server is enabled.
	ExperimentalRPCListeners []string `long:"experimentalrpclisten" description:"Listen for RPC connections on this interface/port"`

	// Deprecated options
	DataDir *cfgutil.ExplicitString `short:"b" long:"datadir" default-mask:"-" description:"DEPRECATED -- use appdata instead"`
}

// cleanAndExpandPath expands environement variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// NOTE: The os.ExpandEnv doesn't work with Windows cmd.exe-style
	// %VARIABLE%, but they variables can still be expanded via POSIX-style
	// $VARIABLE.
	path = os.ExpandEnv(path)

	if !strings.HasPrefix(path, "~") {
		return filepath.Clean(path)
	}

	// Expand initial ~ to the current user's home directory, or ~otheruser
	// to otheruser's home directory.  On Windows, both forward and backward
	// slashes can be used.
	path = path[1:]

	var pathSeparators string
	if runtime.GOOS == "windows" {
		pathSeparators = string(os.PathSeparator) + "/"
	} else {
		pathSeparators = string(os.PathSeparator)
	}

	userName := ""
	if i := strings.IndexAny(path, pathSeparators); i != -1 {
		userName = path[:i]
		path = path[i:]
	}

	homeDir := ""
	var u *user.User
	var err error
	if userName == "" {
		u, err = user.Current()
	} else {
		u, err = user.Lookup(userName)
	}
	if err == nil {
		homeDir = u.HomeDir
	}
	// Fallback to CWD if user lookup fails or user has no home directory.
	if homeDir == "" {
		homeDir = "."
	}

	return filepath.Join(homeDir, path)
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
			str := "the specified debug level [%v] is invalid"
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
			str := "the specified debug level contains an invalid " +
				"subsystem/level pair [%v]"
			return fmt.Errorf(str, logLevelPair)
		}

		// Extract the specified subsystem and log level.
		fields := strings.Split(logLevelPair, "=")
		subsysID, logLevel := fields[0], fields[1]

		// Validate subsystem.
		if _, exists := subsystemLoggers[subsysID]; !exists {
			str := "the specified subsystem [%v] is invalid -- " +
				"supported subsytems %v"
			return fmt.Errorf(str, subsysID, supportedSubsystems())
		}

		// Validate log level.
		if !validLogLevel(logLevel) {
			str := "the specified debug level [%v] is invalid"
			return fmt.Errorf(str, logLevel)
		}

		setLogLevel(subsysID, logLevel)
	}

	return nil
}

func DefaultConfig() *Config {
	return &Config{
		DebugLevel:             defaultLogLevel,
		ConfigFile:             cfgutil.NewExplicitString(defaultConfigFile),
		AppDataDir:             cfgutil.NewExplicitString(defaultAppDataDir),
		LogDir:                 defaultLogDir,
		CanConsolePrompt:       true,
		WalletPass:             wallet.InsecurePubPassphrase,
		CAFile:                 cfgutil.NewExplicitString(""),
		RPCKey:                 cfgutil.NewExplicitString(defaultRPCKeyFile),
		RPCCert:                cfgutil.NewExplicitString(defaultRPCCertFile),
		LegacyRPCMaxClients:    defaultRPCMaxClients,
		LegacyRPCMaxWebsockets: defaultRPCMaxWebsockets,
		DataDir:                cfgutil.NewExplicitString(defaultAppDataDir),
		UseSPV:                 false,
		AddPeers:               []string{},
		ConnectPeers:           []string{},
		MaxPeers:               neutrino.MaxPeers,
		BanDuration:            neutrino.BanDuration,
		BanThreshold:           neutrino.BanThreshold,
		DBTimeout:              wallet.DefaultDBTimeout,
	}
}

// parseAndLoadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
//  1. Start with a default config with sane settings
//  2. Pre-parse the command line to check for an alternative config file
//  3. Load configuration file overwriting defaults with any specified options
//  4. Parse CLI options and overwrite/add any specified options
//
// The above results in btcwallet functioning properly without any config
// settings while still allowing the user to override settings with config files
// and command line options.  Command line options always take precedence.
func parseAndLoadConfig() (*Config, []string, error) {
	cfg := DefaultConfig()

	// Pre-parse the command line options to see if an alternative config
	// file or the version flag was specified.
	preCfg := cfg
	preParser := flags.NewParser(&preCfg, flags.IgnoreUnknown)
	_, err := preParser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			preParser.WriteHelp(os.Stderr)
		}
		return nil, nil, err
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))

	if preCfg.ShowVersion {
		fmt.Println(appName, "version", version())
		os.Exit(0)
	}

	// Load additional config from file.
	var configFileError error
	parser := flags.NewParser(&cfg, flags.IgnoreUnknown)
	configFilePath := preCfg.ConfigFile.Value
	if preCfg.ConfigFile.ExplicitlySet() {
		configFilePath = cleanAndExpandPath(configFilePath)
	} else {
		appDataDir := preCfg.AppDataDir.Value
		if !preCfg.AppDataDir.ExplicitlySet() && preCfg.DataDir.ExplicitlySet() {
			appDataDir = cleanAndExpandPath(preCfg.DataDir.Value)
		}
		if appDataDir != defaultAppDataDir {
			configFilePath = filepath.Join(appDataDir, defaultConfigFilename)
		}
	}
	err = flags.NewIniParser(parser).ParseFile(configFilePath)
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

	err = loadConfig(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}

	// Warn about missing config file after the final command line parse
	// succeeds.  This prevents the warning on help messages and invalid
	// options.
	if configFileError != nil {
		log.Warnf("%v", configFileError)
	}

	return cfg, remainingArgs, nil
}

func loadConfig(cfg *Config) error {
	funcName := "loadConfig"
	// Check deprecated aliases.  The new options receive priority when both
	// are changed from the default.
	if cfg.DataDir.ExplicitlySet() {
		log.Warnf("datadir option has been replaced by " +
			"appdata -- please update your config")
		if !cfg.AppDataDir.ExplicitlySet() {
			cfg.AppDataDir.Value = cfg.DataDir.Value
		}
	}

	// If an alternate data directory was specified, and paths with defaults
	// relative to the data dir are unchanged, modify each path to be
	// relative to the new data dir.
	if cfg.AppDataDir.ExplicitlySet() {
		cfg.AppDataDir.Value = cleanAndExpandPath(cfg.AppDataDir.Value)
		if !cfg.RPCKey.ExplicitlySet() {
			cfg.RPCKey.Value = filepath.Join(cfg.AppDataDir.Value, "rpc.key")
		}
		if !cfg.RPCCert.ExplicitlySet() {
			cfg.RPCCert.Value = filepath.Join(cfg.AppDataDir.Value, "rpc.cert")
		}
	}

	// Choose the active network params based on the selected network.
	// Multiple networks can't be selected simultaneously.
	numNets := 0
	if cfg.Regtest {
		activeNet = &netparams.RegtestParams
		numNets++
	}

	if cfg.TestNet3 {
		activeNet = &netparams.TestNet3Params
		numNets++
	}
	if cfg.TestNet4 {
		activeNet = &netparams.TestNet4Params
		numNets++
	}
	if cfg.SimNet {
		activeNet = &netparams.SimNetParams
		numNets++
	}
	if cfg.SigNet {
		activeNet = &netparams.SigNetParams
		numNets++

		// Let the user overwrite the default signet parameters. The
		// challenge defines the actual signet network to join and the
		// seed nodes are needed for network discovery.
		sigNetChallenge := chaincfg.DefaultSignetChallenge
		sigNetSeeds := chaincfg.DefaultSignetDNSSeeds
		if cfg.SigNetChallenge != "" {
			challenge, err := hex.DecodeString(cfg.SigNetChallenge)
			if err != nil {
				return fmt.Errorf("%s: Invalid signet challenge, hex decode failed: %v", funcName, err)
			}
			sigNetChallenge = challenge
		}

		if len(cfg.SigNetSeedNode) > 0 {
			sigNetSeeds = make(
				[]chaincfg.DNSSeed, len(cfg.SigNetSeedNode),
			)
			for idx, seed := range cfg.SigNetSeedNode {
				sigNetSeeds[idx] = chaincfg.DNSSeed{
					Host:         seed,
					HasFiltering: false,
				}
			}
		}

		chainParams := chaincfg.CustomSignetParams(
			sigNetChallenge, sigNetSeeds,
		)
		activeNet.Params = &chainParams
	}
	if numNets > 1 {
		str := "%s: The testnet, signet and simnet params can't be " +
			"used together -- choose one"
		return fmt.Errorf(str, funcName)
	}

	// Append the network type to the log directory so it is "namespaced"
	// per network.
	cfg.LogDir = cleanAndExpandPath(cfg.LogDir)
	cfg.LogDir = filepath.Join(cfg.LogDir, activeNet.Params.Name)

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		return fmt.Errorf("Supported subsystems: %s", supportedSubsystems())
	}

	// Initialize log rotation.  After log rotation has been initialized, the
	// logger variables may be used.
	initLogRotator(filepath.Join(cfg.LogDir, defaultLogFilename))

	// Parse, validate, and set debug log level(s).
	if err := parseAndSetDebugLevels(cfg.DebugLevel); err != nil {
		return fmt.Errorf("%s: %w", funcName, err)
	}

	// Exit if you try to use a simulation wallet with a standard
	// data directory.
	if !(cfg.AppDataDir.ExplicitlySet() || cfg.DataDir.ExplicitlySet()) && cfg.CreateTemp {
		return fmt.Errorf("Tried to create a temporary simulation " +
			"wallet, but failed to specify data directory!")
	}

	// Exit if you try to use a simulation wallet on anything other than
	// simnet or testnet3.
	if !cfg.SimNet && cfg.CreateTemp {
		return fmt.Errorf("Tried to create a temporary simulation " +
			"wallet for network other than simnet!")
	}

	// Ensure the wallet exists or create it when the create flag is set.
	netDir := networkDir(cfg.AppDataDir.Value, activeNet.Params)
	dbPath := filepath.Join(netDir, wallet.WalletDBName)

	dbFileExists, err := cfgutil.FileExists(dbPath)
	if err != nil {
		return err
	}

	if cfg.CreateTemp { // nolint:gocritic
		tempWalletExists := false

		if dbFileExists {
			str := fmt.Sprintf("The wallet already exists. Loading this " +
				"wallet instead.")
			log.Debug(str)
			tempWalletExists = true
		}

		// Ensure the data directory for the network exists.
		if err := checkCreateDir(netDir); err != nil {
			return err
		}

		if !tempWalletExists {
			// Create the wallet using provided config.
			if err := createSimulationWallet(cfg); err != nil {
				return fmt.Errorf("unable to create wallet: %w", err)
			}
		}
	} else {
		// We consider create flag is always set and create the wallet whenever it does not exist
		if !dbFileExists {
			// Ensure the data directory for the specified network exists.
			if err := checkCreateDir(netDir); err != nil {
				return err
			}

			// Create the wallet using the initial wallet creation wizard or provided config.
			if err := createWallet(cfg); err != nil {
				return fmt.Errorf("unable to create wallet: %w", err)
			}
		}
	}

	localhostListeners := map[string]struct{}{
		"localhost": {},
		"127.0.0.1": {},
		"::1":       {},
	}

	if cfg.UseSPV {
		neutrino.MaxPeers = cfg.MaxPeers
		neutrino.BanDuration = cfg.BanDuration
		neutrino.BanThreshold = cfg.BanThreshold
	} else {
		if cfg.RPCConnect == "" {
			cfg.RPCConnect = net.JoinHostPort("localhost", activeNet.RPCClientPort)
		}

		// Add default port to connect flag if missing.
		cfg.RPCConnect, err = cfgutil.NormalizeAddress(cfg.RPCConnect,
			activeNet.RPCClientPort)
		if err != nil {
			return fmt.Errorf("invalid rpcconnect network address: %w", err)
		}

		RPCHost, _, err := net.SplitHostPort(cfg.RPCConnect)
		if err != nil {
			return err
		}
		if cfg.DisableClientTLS {
			if _, ok := localhostListeners[RPCHost]; !ok {
				str := "%s: the --noclienttls option may not be used " +
					"when connecting RPC to non localhost " +
					"addresses: %s"
				return fmt.Errorf(str, funcName, cfg.RPCConnect)
			}
		} else {
			// If CAFile is unset, choose either the copy or local btcd cert.
			if !cfg.CAFile.ExplicitlySet() {
				cfg.CAFile.Value = filepath.Join(cfg.AppDataDir.Value, defaultCAFilename)

				// If the CA copy does not exist, check if we're connecting to
				// a local btcd and switch to its RPC cert if it exists.
				certExists, err := cfgutil.FileExists(cfg.CAFile.Value)
				if err != nil {
					return err
				}
				if !certExists {
					if _, ok := localhostListeners[RPCHost]; ok {
						btcdCertExists, err := cfgutil.FileExists(
							btcdDefaultCAFile)
						if err != nil {
							return err
						}
						if btcdCertExists {
							cfg.CAFile.Value = btcdDefaultCAFile
						}
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
			return err
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
		return fmt.Errorf("invalid network address in legacy RPC listeners: %w", err)
	}
	cfg.ExperimentalRPCListeners, err = cfgutil.NormalizeAddresses(
		cfg.ExperimentalRPCListeners, activeNet.RPCServerPort)
	if err != nil {
		return fmt.Errorf("invalid network address in RPC listeners: %w", err)
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
				return fmt.Errorf("address `%s` may not be "+
					"used as a listener address for both "+
					"RPC servers", addr)
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
				return fmt.Errorf(str, funcName, addr, err)
			}
			if _, ok := localhostListeners[host]; !ok {
				str := "%s: the --noservertls option may not be used " +
					"when binding RPC to non localhost " +
					"addresses: %s"
				return fmt.Errorf(str, funcName, addr)
			}
		}
	}

	// Expand environment variable and leading ~ for filepaths.
	cfg.CAFile.Value = cleanAndExpandPath(cfg.CAFile.Value)
	cfg.RPCCert.Value = cleanAndExpandPath(cfg.RPCCert.Value)
	cfg.RPCKey.Value = cleanAndExpandPath(cfg.RPCKey.Value)

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

	return nil
}
