// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpctest

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/decred/dcrd/wire"

	rpc "github.com/decred/dcrrpcclient"
	"github.com/decred/dcrutil"
)

// nodeConfig contains all the args, and data required to launch a dcrd process
// and connect the rpc client to it.
type nodeConfig struct {
	rpcUser    string
	rpcPass    string
	listen     string
	rpcListen  string
	rpcConnect string
	profile    string
	debugLevel string
	extra      []string
	appDataDir string

	exe          string
	endpoint     string
	certFile     string
	keyFile      string
	certificates []byte
}

// newConfig returns a nodeConfig with default values.
func newConfig(appDataDir, certFile, keyFile string, extra []string) (*nodeConfig, error) {
	// TODO: use defaultP2pPort and defaultRPCPort instead of literals
	a := &nodeConfig{
		listen:     "127.0.0.1:18555",
		rpcListen:  "127.0.0.1:19556",
		rpcUser:    "user",
		rpcPass:    "pass",
		extra:      extra,
		appDataDir: appDataDir,

		exe:      "dcrd",
		endpoint: "ws",
		certFile: certFile,
		keyFile:  keyFile,
	}
	if err := a.setDefaults(); err != nil {
		return nil, err
	}
	return a, nil
}

// setDefaults sets the default values of the config. It also creates the
// temporary data, and log directories which must be cleaned up with a call to
// cleanup().
func (n *nodeConfig) setDefaults() error {
	cert, err := ioutil.ReadFile(n.certFile)
	if err != nil {
		return err
	}
	n.certificates = cert
	return nil
}

// arguments returns an array of arguments that be used to launch the
// dcrd process.
func (n *nodeConfig) arguments() []string {
	args := []string{}
	// --simnet
	args = append(args, fmt.Sprintf("--%s", strings.ToLower(wire.SimNet.String())))
	if n.rpcUser != "" {
		// --rpcuser
		args = append(args, fmt.Sprintf("--rpcuser=%s", n.rpcUser))
	}
	if n.rpcPass != "" {
		// --rpcpass
		args = append(args, fmt.Sprintf("--rpcpass=%s", n.rpcPass))
	}
	if n.listen != "" {
		// --listen
		args = append(args, fmt.Sprintf("--listen=%s", n.listen))
	}
	if n.rpcListen != "" {
		// --rpclisten
		args = append(args, fmt.Sprintf("--rpclisten=%s", n.rpcListen))
	}
	if n.rpcConnect != "" {
		// --rpcconnect
		args = append(args, fmt.Sprintf("--rpcconnect=%s", n.rpcConnect))
	}
	// --rpccert
	args = append(args, fmt.Sprintf("--rpccert=%s", n.certFile))
	// --rpckey
	args = append(args, fmt.Sprintf("--rpckey=%s", n.keyFile))
	args = append(args, fmt.Sprintf("--appdata=%s", n.appDataDir))
	if n.profile != "" {
		// --profile
		args = append(args, fmt.Sprintf("--profile=%s", n.profile))
	}
	if n.debugLevel != "" {
		// --debuglevel
		args = append(args, fmt.Sprintf("--debuglevel=%s", n.debugLevel))
	}
	args = append(args, "--txindex")
	args = append(args, "--addrindex")
	args = append(args, n.extra...)
	return args
}

// command returns the exec.Cmd which will be used to start the dcrd process.
func (n *nodeConfig) command() *exec.Cmd {
	return exec.Command(n.exe, n.arguments()...)
}

// rpcConnConfig returns the rpc connection config that can be used
// to connect to the dcrd process that is launched via Start().
func (n *nodeConfig) rpcConnConfig() rpc.ConnConfig {
	return rpc.ConnConfig{
		Host:                 n.rpcListen,
		Endpoint:             n.endpoint,
		User:                 n.rpcUser,
		Pass:                 n.rpcPass,
		Certificates:         n.certificates,
		DisableAutoReconnect: true,
	}
}

// String returns the string representation of this nodeConfig.
func (n *nodeConfig) String() string {
	return n.appDataDir
}

// cleanup removes the tmp data and log directories.
func (n *nodeConfig) cleanup() error {
	if err := os.RemoveAll(n.appDataDir); err != nil {
		return err
	}
	return nil
}

// node houses the neccessary state required to configure, launch, and manaage
// a dcrd process.
type node struct {
	config *nodeConfig

	cmd     *exec.Cmd
	pidFile string

	dataDir string
}

// newNode creates a new node instance according to the passed config. dataDir
// will be used to hold a file recording the pid of the launched process, and
// as the base for the log and data directories for dcrd.
func newNode(config *nodeConfig, dataDir string) (*node, error) {
	return &node{
		config:  config,
		dataDir: dataDir,
		cmd:     config.command(),
	}, nil
}

// Start creates a new dcrd process, and writes its pid in a file reserved for
// recording the pid of the launched process. This file can ue used to terminate
// the procress in case of a hang, or panic. In the case of a failing test case,
// or panic, it is important that the process be stopped via stop(), otherwise,
// it will persist unless explicitly killed.
func (n *node) Start() error {
	if err := n.cmd.Start(); err != nil {
		return err
	}

	pid, err := os.Create(fmt.Sprintf("%s.pid", n.config))
	if err != nil {
		return err
	}

	n.pidFile = pid.Name()
	if _, err = fmt.Fprintf(pid, "%d\n", n.cmd.Process.Pid); err != nil {
		return err
	}

	if err := pid.Close(); err != nil {
		return err
	}

	return nil
}

// FullCommand returns the full command used to start the node
func (n *node) FullCommand() string {
	args := strings.Join(n.cmd.Args, " ")
	return n.cmd.Path + args
}

// CertFile returns the node RPC's TLS certificate
func (n *node) CertFile() string {
	return n.config.certFile
}

// Stop interrupts the running dcrd process, and waits until it exits properly.
// On windows, interrupt is not supported, so a kill signal is used instead.
func (n *node) Stop() error {
	if n.cmd == nil || n.cmd.Process == nil {
		// return if not properly initialized
		// or error starting the process
		return nil
	}
	defer n.cmd.Wait()
	if runtime.GOOS == "windows" {
		return n.cmd.Process.Signal(os.Kill)
	}
	return n.cmd.Process.Signal(os.Interrupt)
}

// Cleanup cleanups process and args files. The file housing the pid of the
// created process will be deleted, as well as any directories created by the
// process.
func (n *node) Cleanup() error {
	if n.pidFile != "" {
		if err := os.Remove(n.pidFile); err != nil {
			log.Printf("unable to remove file %s: %v", n.pidFile,
				err)
		}
	}

	return n.config.cleanup()
}

// genCertPair generates a key/cert pair to the paths provided.
func genCertPair(certFile, keyFile, certFileWallet, keyFileWallet string) error {
	org := "rpctest autogenerated cert"
	validUntil := time.Now().Add(10 * 365 * 24 * time.Hour)
	cert, key, err := dcrutil.NewTLSCertPair(org, validUntil, nil)
	if err != nil {
		return err
	}
	// Write cert and key files.
	if err = ioutil.WriteFile(certFile, cert, 0666); err != nil {
		return err
	}
	if err = ioutil.WriteFile(keyFile, key, 0600); err != nil {
		os.Remove(certFile)
		return err
	}
	if err = ioutil.WriteFile(certFileWallet, cert, 0666); err != nil {
		return err
	}
	if err = ioutil.WriteFile(keyFileWallet, key, 0600); err != nil {
		os.Remove(certFile)
		return err
	}
	return nil
}
