// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpctest

import (
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"

	rpc "github.com/decred/dcrrpcclient"
	"github.com/decred/dcrutil"
)

var (
	// current number of active test nodes.
	numTestInstances = 0

	// defaultP2pPort is the initial p2p port which will be used by the first
	// created rpc harnesses to listen on for incoming p2p connections.
	// Subsequent allocated ports for future rpc harness instances will be
	// monotonically increasing odd numbers calculated as such:
	// defaultP2pPort + (2 * harness.nodeNum).
	defaultP2pPort = 18555

	// defaultRPCPort is the initial rpc port which will be used by the first
	// created rpc harnesses to listen on for incoming rpc connections.
	// Subsequent allocated ports for future rpc harness instances will be
	// monotonically increasing even numbers calculated as such:
	// defaultRPCPort + (2 * harness.nodeNum).
	defaultRPCPort = 19556

	// defaultWalletRPCPort is the initial RPC port similar to defaultRPCPort
	// but used for the wallet RPC.
	defaultWalletRPCPort = 19557

	// testInstances is a private package-level slice used to keep track of
	// all active test harnesses. This global can be used to perform various
	// "joins", shutdown several active harnesses after a test, etc.
	testInstances map[string]*Harness

	// harnessStateMtx is used to protect concurrent access to the variables
	// declared above.
	harnessStateMtx sync.RWMutex
)

// Harness fully encapsulates an active dcrd process, along with an embedded
// dcrwallet to provide a unified platform for creating RPC-driven integration
// tests involving dcrd. The active dcrd node will typically be run in simnet
// mode to allow for easy generation of test blockchains. Additionally, a
// special method is provided which allows one to easily generate coinbase
// spends. The active dcrd process is fully managed by Harness, which handles
// the necessary initialization, and teardown of the process along with any
// temporary directories created as a result. Multiple Harness instances may be
// run concurrently, to allow for testing complex scenarios involving multuple
// nodes.
type Harness struct {
	ActiveNet *chaincfg.Params

	Node      *rpc.Client
	WalletRPC *rpc.Client
	node      *node
	handlers  *rpc.NotificationHandlers

	wallet *walletTest

	testNodeDir    string
	testWalletDir  string
	maxConnRetries int
	nodeNum        int
	miningAddr     dcrutil.Address
}

// NewHarness creates and initializes a new instance of the rpc test harness.
// Optionally, websocket handlers and a specified configuration may be passed.
// In the case that a nil configuration is passed, a default configuration will
// be used.
//
// NOTE: This function is safe for concurrent access.
func NewHarness(activeNet *chaincfg.Params, handlers *rpc.NotificationHandlers,
	extraArgs []string) (*Harness, error) {

	harnessStateMtx.Lock()
	defer harnessStateMtx.Unlock()

	// Create data folders for this Harness instance
	harnessID := strconv.Itoa(int(numTestInstances))
	testDataPath := "rpctest-" + harnessID

	testData, err := ioutil.TempDir("", testDataPath)
	if err != nil {
		return nil, err
	}

	// Subdirectory for daemon data
	nodeTestData, err := ioutil.TempDir(testData, "node")
	if err != nil {
		return nil, err
	}

	// Subdirectory for wallet data
	walletTestData, err := ioutil.TempDir(testData, "wallet")
	if err != nil {
		return nil, err
	}

	certFile := filepath.Join(nodeTestData, "rpc.cert")
	keyFile := filepath.Join(nodeTestData, "rpc.key")
	certFileWallet := filepath.Join(walletTestData, "rpc.cert")
	keyFileWallet := filepath.Join(walletTestData, "rpc.key")

	// Generate the default config if needed.
	if err := genCertPair(certFile, keyFile, certFileWallet, keyFileWallet); err != nil {
		return nil, err
	}

	// Generate p2p+rpc listening addresses.
	p2p, rpcPort, walletRPC := generateListeningAddresses()

	// Create new nodeConfig
	config, err := newConfig(nodeTestData, certFile, keyFile, extraArgs)
	if err != nil {
		return nil, err
	}
	config.listen = p2p
	config.rpcListen = rpcPort

	// Create the testing node bounded to the simnet.
	node, err := newNode(config, nodeTestData)
	if err != nil {
		return nil, err
	}

	// Create new walletTestConfig
	walletConfig, err := newWalletConfig(walletTestData, certFile, certFileWallet, keyFileWallet, nil)
	if err != nil {
		return nil, err
	}
	// Set RPC connect (node) port
	walletConfig.rpcConnect = rpcPort
	// Set RPC listen port
	walletConfig.rpcListen = walletRPC

	// Create the testing wallet
	walletTest, err := newWallet(walletConfig, walletTestData)
	if err != nil {
		return nil, err
	}

	nodeNum := numTestInstances
	numTestInstances++

	h := &Harness{
		handlers:       handlers,
		node:           node,
		wallet:         walletTest,
		maxConnRetries: 20,
		testNodeDir:    nodeTestData,
		testWalletDir:  walletTestData,
		ActiveNet:      activeNet,
		nodeNum:        nodeNum,
	}

	// Track this newly created test instance within the package level
	// global map of all active test instances.
	testInstances[h.testNodeDir] = h

	return h, nil
}

// SetUp initializes the rpc test state. Initialization includes: starting up a
// simnet node, creating a websocket client and connecting to the started node,
// and finally: optionally generating and submitting a testchain with a configurable
// number of mature coinbase outputs coinbase outputs.
func (h *Harness) SetUp(createTestChain bool, numMatureOutputs uint32) error {
	var err error

	// Start the dcrd node itself. This spawns a new process which will be
	// managed
	if err = h.node.Start(); err != nil {
		return err
	}
	time.Sleep(200 * time.Millisecond)
	if err := h.connectRPCClient(); err != nil {
		return err
	}
	fmt.Println("Node RPC client connected.")

	// Start dcrwallet. This spawns a new process which will be managed
	if err = h.wallet.Start(); err != nil {
		return err
	}
	time.Sleep(1 * time.Second)

	// Connect walletClient so we can get the mining address
	var walletClient *rpc.Client
	walletRPCConf := h.wallet.config.rpcConnConfig()
	for i := 0; i < 400; i++ {
		if walletClient, err = rpc.New(&walletRPCConf, nil); err != nil {
			time.Sleep(time.Duration(math.Log(float64(i+3))) * 50 * time.Millisecond)
			continue
		}
		break
	}
	if walletClient == nil {
		return fmt.Errorf("walletClient connection timedout")
	}
	fmt.Println("Wallet RPC client connected.")
	h.WalletRPC = walletClient

	// Get a new address from the wallet to be set with dcrd's --miningaddr
	time.Sleep(5 * time.Second)
	var miningAddr dcrutil.Address
	for i := 0; i < 100; i++ {
		if miningAddr, err = walletClient.GetNewAddress("default"); err != nil {
			time.Sleep(time.Duration(math.Log(float64(i+3))) * 50 * time.Millisecond)
			continue
		}
		break
	}
	if miningAddr == nil {
		return fmt.Errorf("RPC not up for mining addr %v %v", h.testNodeDir,
			h.testWalletDir)
	}
	h.miningAddr = miningAddr

	var extraArgs []string
	miningArg := fmt.Sprintf("--miningaddr=%s", miningAddr)
	extraArgs = append(extraArgs, miningArg)

	// Shutdown node so we can restart it with --miningaddr
	if err := h.node.Shutdown(); err != nil {
		return err
	}

	config, err := newConfig(h.node.config.prefix, h.node.config.certFile,
		h.node.config.keyFile, extraArgs)
	if err != nil {
		return err
	}
	config.listen = h.node.config.listen
	config.rpcListen = h.node.config.rpcListen

	// Create the testing node bounded to the simnet.
	node, err := newNode(config, h.testNodeDir)
	if err != nil {
		return err
	}
	h.node = node

	// Restart node with mining address set
	if err = h.node.Start(); err != nil {
		return err
	}
	time.Sleep(1 * time.Second)
	if err := h.connectRPCClient(); err != nil {
		return err
	}
	fmt.Printf("Node RPC client connected, miningaddr: %v.\n", miningAddr)

	// Create a test chain with the desired number of mature coinbase outputs
	if createTestChain {
		numToGenerate := uint32(h.ActiveNet.CoinbaseMaturity) + numMatureOutputs
		fmt.Printf("Generating %v blocks...\n", numToGenerate)
		_, err := h.Node.Generate(numToGenerate)
		if err != nil {
			return err
		}
		fmt.Println("Block generation complete.")
	}

	// Wait for the wallet to sync up to the current height.
	// TODO: Figure out why this is the longest wait, about 60 sec, when it
	// should be almost immediate.
	fmt.Println("Waiting for wallet to sync to current height.")
	ticker := time.NewTicker(time.Millisecond * 500)
	desiredHeight := int64(numMatureOutputs + uint32(h.ActiveNet.CoinbaseMaturity))
out:
	for {
		select {
		case <-ticker.C:
			count, err := h.WalletRPC.GetBlockCount()
			if err != nil {
				return err
			}
			if count == desiredHeight {
				break out
			}
		}
	}
	ticker.Stop()

	fmt.Println("Wallet sync complete.")

	return nil
}

// TearDown stops the running RPC test instance. All created processes killed,
// and temporary directories removed.
func (h *Harness) TearDown() error {
	if h.Node != nil {
		h.Node.Shutdown()
	}

	if err := h.node.Shutdown(); err != nil {
		return err
	}
	if err := h.wallet.Shutdown(); err != nil {
		return err
	}

	if err := os.RemoveAll(h.testNodeDir); err != nil {
		return err
	}

	if err := os.RemoveAll(h.testWalletDir); err != nil {
		return err
	}

	delete(testInstances, h.testNodeDir)

	return nil
}

// IsUp checks if the harness is still being tracked by rpctest
func (h *Harness) IsUp() bool {
	_, up := testInstances[h.testNodeDir]
	return up
}

// connectRPCClient attempts to establish an RPC connection to the created
// dcrd process belonging to this Harness instance. If the initial connection
// attempt fails, this function will retry h.maxConnRetries times, backing off
// the time between subsequent attempts. If after h.maxConnRetries attempts,
// we're not able to establish a connection, this function returns with an error.
func (h *Harness) connectRPCClient() error {
	var client *rpc.Client
	var err error

	rpcConf := h.node.config.rpcConnConfig()
	for i := 0; i < h.maxConnRetries; i++ {
		if client, err = rpc.New(&rpcConf, h.handlers); err != nil {
			time.Sleep(time.Duration(math.Log(float64(i+3))) * 50 * time.Millisecond)
			continue
		}
		break
	}

	if client == nil {
		return fmt.Errorf("Connection timedout, err: %v\n", err)
	}

	err = client.NotifyBlocks()
	if err != nil {
		return err
	}

	h.Node = client
	return nil
}

// RPCConfig returns the harnesses current rpc configuration. This allows other
// potential RPC clients created within tests to connect to a given test harness
// instance.
func (h *Harness) RPCConfig() rpc.ConnConfig {
	return h.node.config.rpcConnConfig()
}

// RPCWalletConfig returns the harnesses current rpc configuration. This allows other
// potential RPC clients created within tests to connect to a given test harness
// instance.
func (h *Harness) RPCWalletConfig() rpc.ConnConfig {
	return h.wallet.config.rpcConnConfig()
}

// RPCCertFile returns the full path the node RPC's TLS certifiate
func (h *Harness) RPCCertFile() string {
	return h.node.CertFile()
}

// RPCWalletCertFile returns the full path the wallet RPC's TLS certifiate
func (h *Harness) RPCWalletCertFile() string {
	return h.wallet.CertFile()
}

// FullNodeCommand returns the full command line of the node
func (h *Harness) FullNodeCommand() string {
	args := strings.Join(h.node.cmd.Args[1:], " ")
	return h.node.cmd.Path + " " + args
}

// FullWalletCommand returns the full command line of the wallet
func (h *Harness) FullWalletCommand() string {
	args := strings.Join(h.wallet.cmd.Args[1:], " ")
	return h.wallet.cmd.Path + " " + args
}

// generateListeningAddresses returns three strings representing listening
// addresses designated for the current rpc test. If there haven't been any test
// instances created, the default ports are used. Otherwise, in order to support
// multiple test nodes running at once, the p2p and both rpc ports are
// incremented after each initialization.
func generateListeningAddresses() (string, string, string) {
	var p2p, rpc, walletRPC string
	localhost := "127.0.0.1"

	if numTestInstances == 0 {
		p2p = net.JoinHostPort(localhost, strconv.Itoa(defaultP2pPort))
		rpc = net.JoinHostPort(localhost, strconv.Itoa(defaultRPCPort))
		walletRPC = net.JoinHostPort(localhost, strconv.Itoa(defaultWalletRPCPort))
	} else {
		p2p = net.JoinHostPort(localhost,
			strconv.Itoa(defaultP2pPort+(2*numTestInstances)))
		rpc = net.JoinHostPort(localhost,
			strconv.Itoa(defaultRPCPort+(2*numTestInstances)))
		walletRPC = net.JoinHostPort(localhost,
			strconv.Itoa(defaultWalletRPCPort+(2*numTestInstances)))
	}

	return p2p, rpc, walletRPC
}

// GenerateBlock is a helper function to ensure that the chain has actually
// incremented due to FORK blocks after stake voting height that may occur.
func (h *Harness) GenerateBlock(startHeight uint32) ([]*chainhash.Hash, error) {
	blockHashes, err := h.Node.Generate(1)
	if err != nil {
		return nil, fmt.Errorf("unable to generate single block: %v", err)
	}
	block, err := h.Node.GetBlock(blockHashes[0])
	if err != nil {
		return nil, fmt.Errorf("unable to get block: %v", err)
	}
	newHeight := block.MsgBlock().Header.Height
	for newHeight == startHeight {
		blockHashes, err := h.Node.Generate(1)
		if err != nil {
			return nil, fmt.Errorf("unable to generate single block: %v", err)
		}
		block, err := h.Node.GetBlock(blockHashes[0])
		if err != nil {
			return nil, fmt.Errorf("unable to get block: %v", err)
		}
		newHeight = block.MsgBlock().Header.Height
	}
	return blockHashes, nil
}

func init() {
	// Create the testInstances map once the package has been imported.
	testInstances = make(map[string]*Harness)
}
