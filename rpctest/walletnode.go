// Copyright (c) 2016 The decred developers
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

	"github.com/decred/dcrd/wire"

	rpc "github.com/decred/dcrrpcclient"
)

// walletTestConfig contains all the args, and data required to launch a dcrwallet process
// and connect the rpc client to it.
type walletTestConfig struct {
	rpcUser    string
	rpcPass    string
	rpcListen  string
	rpcConnect string
	dataDir    string
	logDir     string
	profile    string
	debugLevel string
	extra      []string
	prefix     string

	exe          string
	endpoint     string
	certFile     string
	caFile       string
	keyFile      string
	certificates []byte
}

// newConfig returns a newConfig with all default values.
func newWalletConfig(prefix, caFile, certFile, keyFile string, extra []string) (*walletTestConfig, error) {
	a := &walletTestConfig{
		rpcConnect: "127.0.0.1:19556",
		rpcListen:  "127.0.0.1:19557",
		rpcUser:    "user",
		rpcPass:    "pass",
		extra:      extra,
		prefix:     prefix,

		exe:      "dcrwallet",
		endpoint: "ws",
		caFile:   caFile,
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
func (n *walletTestConfig) setDefaults() error {
	datadir, err := ioutil.TempDir(n.prefix, "data")
	if err != nil {
		return err
	}
	n.dataDir = datadir
	logdir, err := ioutil.TempDir(n.prefix, "logs")
	if err != nil {
		return err
	}
	n.logDir = logdir
	cert, err := ioutil.ReadFile(n.certFile)
	if err != nil {
		return err
	}
	n.certificates = cert
	return nil
}

// arguments returns an array of arguments that be used to launch the
// dcrwallet process.
func (n *walletTestConfig) arguments() []string {
	args := []string{}
	// --simnet
	args = append(args, fmt.Sprintf("--%s", strings.ToLower(wire.SimNet.String())))
	args = append(args, fmt.Sprintf("--createtemp"))
	args = append(args, fmt.Sprintf("--enablestakemining"))
	args = append(args, fmt.Sprintf("--balancetomaintain=2000000"))
	args = append(args, fmt.Sprintf("--ticketmaxprice=0"))

	if n.rpcUser != "" {
		// --rpcuser
		args = append(args, fmt.Sprintf("--username=%s", n.rpcUser))
	}
	if n.rpcPass != "" {
		// --rpcpass
		args = append(args, fmt.Sprintf("--password=%s", n.rpcPass))
	}
	if n.rpcConnect != "" {
		// --listen
		args = append(args, fmt.Sprintf("--rpcconnect=%s", n.rpcConnect))
	}
	if n.rpcListen != "" {
		// --rpclisten
		args = append(args, fmt.Sprintf("--rpclisten=%s", n.rpcListen))
	}
	// --rpccert
	args = append(args, fmt.Sprintf("--cafile=%s", n.caFile))
	args = append(args, fmt.Sprintf("--rpccert=%s", n.certFile))
	// --rpckey
	args = append(args, fmt.Sprintf("--rpckey=%s", n.keyFile))
	if n.dataDir != "" {
		// --datadir
		args = append(args, fmt.Sprintf("--appdata=%s", n.dataDir))
	}
	if n.logDir != "" {
		// --logdir
		args = append(args, fmt.Sprintf("--logdir=%s", n.logDir))
	}
	if n.debugLevel != "" {
		// --debuglevel
		args = append(args, fmt.Sprintf("--debuglevel=%s", n.debugLevel))
	}
	args = append(args, n.extra...)
	return args
}

// command returns the exec.Cmd which will be used to start the dcrwallet process.
func (n *walletTestConfig) command() *exec.Cmd {
	return exec.Command(n.exe, n.arguments()...)
}

// rpcConnConfig returns the rpc connection config that can be used
// to connect to the dcrwallet process that is launched via Start().
func (n *walletTestConfig) rpcConnConfig() rpc.ConnConfig {
	return rpc.ConnConfig{
		Host:                 n.rpcListen,
		Endpoint:             n.endpoint,
		User:                 n.rpcUser,
		Pass:                 n.rpcPass,
		Certificates:         n.certificates,
		DisableAutoReconnect: true,
	}
}

// String returns the string representation of this walletTestConfig.
func (n *walletTestConfig) String() string {
	return n.prefix
}

// cleanup removes the tmp data and log directories.
func (n *walletTestConfig) cleanup() error {
	dirs := []string{
		n.logDir,
		n.dataDir,
	}
	var err error
	for _, dir := range dirs {
		if err = os.RemoveAll(dir); err != nil {
			log.Printf("Cannot remove dir %s: %v", dir, err)
		}
	}
	return err
}

// walletTest houses the neccessary state required to configure, launch, and manaage
// a dcrwallet process.
type walletTest struct {
	config *walletTestConfig

	cmd     *exec.Cmd
	pidFile string

	dataDir string
}

// newNode creates a new walletTest instance according to the passed config. dataDir
// will be used to hold a file recording the pid of the launched process, and
// as the base for the log and data directories for dcrwallet.
func newWallet(config *walletTestConfig, dataDir string) (*walletTest, error) {
	return &walletTest{
		config:  config,
		dataDir: dataDir,
		cmd:     config.command(),
	}, nil
}

// Start creates a new dcrwallet process, and writes its pid in a file reserved for
// recording the pid of the launched process. This file can ue used to terminate
// the procress in case of a hang, or panic. In the case of a failing test case,
// or panic, it is important that the process be stopped via stop(), otherwise,
// it will persist unless explicitly killed.
func (n *walletTest) Start() error {
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

// Stop interrupts the running dcrwalletTest process process, and waits until it exits
// properly. On windows, interrupt is not supported, so a kill signal is used
// instead
func (n *walletTest) Stop() error {
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
func (n *walletTest) Cleanup() error {
	if n.pidFile != "" {
		if err := os.Remove(n.pidFile); err != nil {
			log.Printf("unable to remove file %s: %v", n.pidFile,
				err)
		}
	}

	return n.config.cleanup()
}

// shutdown terminates the running dcrwallet process, and cleans up all
// file/directories created by walletTest.
func (n *walletTest) Shutdown() error {
	if err := n.Stop(); err != nil {
		return err
	}
	if err := n.Cleanup(); err != nil {
		return err
	}
	return nil
}
