/*
 * Copyright (c) 2013 Conformal Systems LLC <info@conformal.com>
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
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	"github.com/conformal/go-flags"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultCAFilename     = "cert.pem"
	defaultConfigFilename = "btcwallet.conf"
	defaultDataDirname    = "data"
	defaultBtcNet         = btcwire.TestNet3
	defaultLogLevel       = "info"
)

var (
	btcwalletHomeDir  = btcutil.AppDataDir("btcwallet", false)
	defaultCAFile     = filepath.Join(btcwalletHomeDir, defaultCAFilename)
	defaultConfigFile = filepath.Join(btcwalletHomeDir, defaultConfigFilename)
	defaultDataDir    = btcwalletHomeDir
)

type config struct {
	ShowVersion bool   `short:"V" long:"version" description:"Display version information and exit"`
	CAFile      string `long:"cafile" description:"File containing root certificates to authenticate a TLS connections with btcd"`
	Connect     string `short:"c" long:"connect" description:"Server and port of btcd instance to connect to"`
	DebugLevel  string `short:"d" long:"debuglevel" description:"Logging level {trace, debug, info, warn, error, critical}"`
	ConfigFile  string `short:"C" long:"configfile" description:"Path to configuration file"`
	SvrPort     string `short:"p" long:"serverport" description:"Port to serve frontend websocket connections on (default: 18332, mainnet: 8332)"`
	DataDir     string `short:"D" long:"datadir" description:"Directory to store wallets and transactions"`
	Username    string `short:"u" long:"username" description:"Username for btcd authorization"`
	Password    string `short:"P" long:"password" description:"Password for btcd authorization"`
	MainNet     bool   `long:"mainnet" description:"*DISABLED* Use the main Bitcoin network (default testnet3)"`
}

// updateConfigWithActiveParams update the passed config with parameters
// from the active net params if the relevant options in the passed config
// object are the default so options specified by the user on the command line
// are not overridden.
func updateConfigWithActiveParams(cfg *config) {
	if cfg.Connect == netParams(defaultBtcNet).connect {
		cfg.Connect = activeNetParams.connect
	}

	if cfg.SvrPort == netParams(defaultBtcNet).svrPort {
		cfg.SvrPort = activeNetParams.svrPort
	}
}

// filesExists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// normalizeAddress returns addr with the passed default port appended if
// there is not already a port specified.
func normalizeAddress(addr, defaultPort string) string {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.JoinHostPort(addr, defaultPort)
	}
	return addr
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
		DebugLevel: defaultLogLevel,
		CAFile:     defaultCAFile,
		ConfigFile: defaultConfigFile,
		Connect:    netParams(defaultBtcNet).connect,
		SvrPort:    netParams(defaultBtcNet).svrPort,
		DataDir:    defaultDataDir,
	}

	// A config file in the current directory takes precedence.
	if fileExists(defaultConfigFilename) {
		cfg.ConfigFile = defaultConfigFile
	}

	// Pre-parse the command line options to see if an alternative config
	// file or the version flag was specified.
	preCfg := cfg
	preParser := flags.NewParser(&preCfg, flags.Default)
	_, err := preParser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			preParser.WriteHelp(os.Stderr)
		}
		return nil, nil, err
	}

	// Show the version and exit if the version flag was specified.
	if preCfg.ShowVersion {
		appName := filepath.Base(os.Args[0])
		appName = strings.TrimSuffix(appName, filepath.Ext(appName))
		fmt.Println(appName, "version", version())
		os.Exit(0)
	}

	// Load additional config from file.
	parser := flags.NewParser(&cfg, flags.Default)
	err = parser.ParseIniFile(preCfg.ConfigFile)
	if err != nil {
		if _, ok := err.(*os.PathError); !ok {
			fmt.Fprintln(os.Stderr, err)
			parser.WriteHelp(os.Stderr)
			return nil, nil, err
		}
		log.Warnf("%v", err)
	}

	// Parse command line options again to ensure they take precedence.
	remainingArgs, err := parser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			parser.WriteHelp(os.Stderr)
		}
		return nil, nil, err
	}

	// TODO(jrick): Enable mainnet support again when ready.
	cfg.MainNet = false

	// Choose the active network params based on the mainnet net flag.
	if cfg.MainNet {
		activeNetParams = netParams(btcwire.MainNet)
	}
	updateConfigWithActiveParams(&cfg)

	// Validate debug log level
	if !validLogLevel(cfg.DebugLevel) {
		str := "%s: The specified debug level [%v] is invalid"
		err := fmt.Errorf(str, "loadConfig", cfg.DebugLevel)
		fmt.Fprintln(os.Stderr, err)
		parser.WriteHelp(os.Stderr)
		return nil, nil, err
	}

	// Add default port to connect flag if missing.
	cfg.Connect = normalizeAddress(cfg.Connect, activeNetParams.btcdPort)

	return &cfg, remainingArgs, nil
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
