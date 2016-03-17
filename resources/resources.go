// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package resources

import (
	"path/filepath"

	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/netparams"
)

const (
	// ApplicationName is the name of the wallet binary process.
	ApplicationName = "btcwallet"

	// ConsensusRPCApplicationName is the process name of the RPC server
	// used for block and transaction consensus and transaction relaying.
	ConsensusRPCApplicationName = "btcd"

	// ConfigFile is the name of the configuration file.  The wallet process
	// prioritizes configuration files found in the current working
	// directory, but alternative config files may be specified as a command
	// line argument or used if found in the application data directory.
	ConfigFile = ApplicationName + ".conf"

	// RPCCertificateFile is the name of the TLS certificate used by the
	// wallet and the consensus RPC servers.  The full path is relative to
	// the process's application data directory.
	RPCCertificateFile = "rpc.cert"

	// RPCKeyFile is the name of the TLS key used by the wallet's RPC
	// server.  The full path is relative to the application data directory.
	RPCKeyFile = "rpc.key"

	// ConsensusRPCRemoteCertificateFile is the name of a remote consensus
	// RPC server's TLS certificate copy in the application data directory.
	// This is necessary when connecting to a remote consensus RPC server as
	// its application data directory would be unreadable by the wallet
	// process.
	ConsensusRPCRemoteCertificateFile = ConsensusRPCApplicationName + ".cert"

	// DatabaseFile is the filename of the wallet database, containing both
	// wallet keys and transaction history.  The full path is relative to
	// the network directory.
	DatabaseFile = "wallet.db"

	// LogFile is the name of the logging file written to the
	// logging directory.
	LogFile = ApplicationName + ".log"
)

// Resources defines the base directories and data required to calculate the
// location of every resource filepath.
type Resources struct {
	// ApplicationDataDirectory is the data directory used for the wallet
	// database, configuration file, and application logs.
	ApplicationDataDirectory string

	// ConsensusRPCDataDirectory is the data directory used for the
	// consensus RPC server.
	ConsensusRPCDataDirectory string

	// ActiveNetwork is the currency network the wallet process is active
	// on.  While an altcoin wallet implemention will always require a fork,
	// the same currency may run alternate networks besides the production
	// network for testing.
	ActiveNetwork *netparams.Params
}

// Defaults return the default resources for the application.
func Defaults() Resources {
	return Resources{
		ApplicationDataDirectory:  btcutil.AppDataDir(ApplicationName, false),
		ConsensusRPCDataDirectory: btcutil.AppDataDir(ConsensusRPCApplicationName, false),
		ActiveNetwork:             &netparams.MainNetParams,
	}
}

// NetworkDirectoryName is the name of the network directory.
func (r *Resources) NetworkDirectoryName() string {
	networkName := r.ActiveNetwork.Params.Name
	// Use "testnet" instead of a versioned name.  This is only for legacy
	// compatibility and it would be a good idea to migrate this in a later
	// change.
	if r.ActiveNetwork == &netparams.TestNet3Params {
		networkName = "testnet"
	}
	return networkName
}

// NetworkDirectory is the absolute network directory path.
func (r *Resources) NetworkDirectory() string {
	return filepath.Join(r.ApplicationDataDirectory, r.NetworkDirectoryName())
}

// ConfigFilePath is the absolute filepath of the configuration file using
// either the default or an alternative application data directory.
func (r *Resources) ConfigFilePath() string {
	return filepath.Join(r.ApplicationDataDirectory, ConfigFile)
}

// RPCCertificateFilePath is the absolute filepath of the RPC server's TLS
// certificate file using either the default or an alternative application data
// directory.
func (r *Resources) RPCCertificateFilePath() string {
	return filepath.Join(r.ApplicationDataDirectory, RPCCertificateFile)
}

// RPCKeyFilePath is the absolute filepath of the RPC server's TLS key file
// using either the default or an alternative application data directory.
func (r *Resources) RPCKeyFilePath() string {
	return filepath.Join(r.ApplicationDataDirectory, RPCKeyFile)
}

// ConsensusRPCRemoteCertificateFilePath is the filepath of the TLS certificate
// copy of the remote consensus RPC server.  This file is saved in the wallet
// process's application data directory.
//
// This path is given higher priority than the local consensus RPC certificate
// path.
func (r *Resources) ConsensusRPCRemoteCertificateFilePath() string {
	return filepath.Join(r.ApplicationDataDirectory, ConsensusRPCRemoteCertificateFile)
}

// ConsensusRPCLocalCertificateFilePath is the filepath of the TLS certificate
// of a local consensus RPC server.  This file is saved in the consensus RPC
// server's application data directory.
func (r *Resources) ConsensusRPCLocalCertificateFilePath() string {
	return filepath.Join(r.ConsensusRPCDataDirectory, RPCCertificateFile)
}

// DatabaseFilePath is the absolute filepath of the wallet database.  The
// database file is stored in the application's network directory.
func (r *Resources) DatabaseFilePath() string {
	return filepath.Join(r.ApplicationDataDirectory, r.NetworkDirectoryName(), DatabaseFile)
}

// DefaultLoggingDirectory is the default network-agnostic directory that logs
// are saved to.  This directory is suitable for use in a configuration file and
// can be used with any network.  The actual chosen logging directory may differ
// from this default, and the absolute log filepath should be determined using
// LogFilePath.
func (r *Resources) DefaultLoggingDirectory() string {
	return filepath.Join(r.ApplicationDataDirectory, "logs")
}

// LogFilePath is the absolute filepath of the application log file.  This is
// allowed to be outside of the application data directory.
func (r *Resources) LogFilePath(loggingDirectory string) string {
	return filepath.Join(loggingDirectory, r.ActiveNetwork.Name, LogFile)
}
