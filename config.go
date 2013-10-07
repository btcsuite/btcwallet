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
	"github.com/conformal/go-flags"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultConfigFilename = "btcwallet.conf"
	defaultBtcdPort       = 8334
	defaultLogLevel       = "info"
	defaultServerPort     = 8332
)

var (
	defaultConfigFile = filepath.Join(btcwalletHomeDir(), defaultConfigFilename)
	defaultDataDir    = btcwalletHomeDir()
)

type config struct {
	ShowVersion bool   `short:"V" long:"version" description:"Display version information and exit"`
	BtcdPort    int    `short:"b" long:"btcdport" description:"Port to connect to btcd on"`
	DebugLevel  string `short:"d" long:"debuglevel" description:"Logging level {trace, debug, info, warn, error, critical}"`
	ConfigFile  string `short:"C" long:"configfile" description:"Path to configuration file"`
	SvrPort     int    `short:"p" long:"serverport" description:"Port to serve frontend websocket connections on"`
	DataDir     string `short:"D" long:"datadir" description:"Directory to store wallets and transactions"`
	Username    string `short:"u" long:"username" description:"Username for btcd authorization"`
	Password    string `short:"P" long:"password" description:"Password for btcd authorization"`
	MainNet     bool   `long:"mainnet" description:"Use the main Bitcoin network (default testnet3)"`
}

// btcwalletHomeDir returns an OS appropriate home directory for btcwallet.
func btcwalletHomeDir() string {
	// Search for Windows APPDATA first.  This won't exist on POSIX OSes.
	appData := os.Getenv("APPDATA")
	if appData != "" {
		return filepath.Join(appData, "btcwallet")
	}

	// Fall back to standard HOME directory that works for most POSIX OSes.
	home := os.Getenv("HOME")
	if home != "" {
		return filepath.Join(home, ".btcwallet")
	}

	// In the worst case, use the current directory.
	return "."
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
		ConfigFile: defaultConfigFile,
		BtcdPort:   defaultBtcdPort,
		SvrPort:    defaultServerPort,
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

	return &cfg, remainingArgs, nil
}
