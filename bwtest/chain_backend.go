// Package bwtest provides the integration test framework for btcwallet.
package bwtest

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/stretchr/testify/require"
)

// ChainBackend defines the interface that all chain backends must implement.
type ChainBackend interface {
	// Start launches the chain backend process.
	Start() error

	// Stop shuts down the chain backend process.
	Stop() error

	// RPCConfig returns the credentials to connect to this backend.
	RPCConfig() rpcclient.ConnConfig

	// P2PAddr returns the P2P address of this node.
	P2PAddr() string

	// ConnectMiner connects this node to the miner.
	ConnectMiner(minerAddr string) error

	// Name returns the name of the backend ("btcd", "bitcoind", "neutrino").
	Name() string
}

// BtcdBackend is a ChainBackend backed by a btcd node (via rpctest).
type BtcdBackend struct {
	// harness is the underlying rpctest harness that manages the btcd process.
	harness *rpctest.Harness
}

// NewBtcdBackend creates a new BtcdBackend.
func NewBtcdBackend(t *testing.T) *BtcdBackend {
	t.Helper()

	btcdBinary, err := GetBtcdBinary()
	require.NoError(t, err, "unable to find btcd binary")

	// Create a separate harness for the chain backend.
	// We use the same regression net params.
	args := []string{
		"--rejectnonstd",          // Reject non-standard txs in tests.
		"--txindex",               // Required for some RPC queries.
		"--nowinservice",          // Avoid Windows service integration.
		"--nobanning",             // Avoid peer banning in local tests.
		"--debuglevel=debug",      // Provide detailed logs for debugging.
		"--trickleinterval=100ms", // Speed up inv relay in regtest.
		"--nostalldetect",         // Avoid stall detection flakiness.
	}

	handlers := &rpcclient.NotificationHandlers{}
	harness, err := rpctest.New(harnessNetParams, handlers, args, btcdBinary)
	require.NoError(t, err, "unable to create btcd backend harness")

	return &BtcdBackend{
		harness: harness,
	}
}

// Start launches the btcd node.
func (b *BtcdBackend) Start() error {
	// SetUp(false, 0) means we don't treat it as a miner
	// (no mining addrs needed immediately) and don't cache block templates.
	err := b.harness.SetUp(false, 0)
	if err != nil {
		return fmt.Errorf("failed to setup btcd harness: %w", err)
	}

	return nil
}

// Stop shuts down the btcd node.
func (b *BtcdBackend) Stop() error {
	err := b.harness.TearDown()
	if err != nil {
		return fmt.Errorf("failed to teardown btcd harness: %w", err)
	}

	return nil
}

// RPCConfig returns the RPC connection config.
func (b *BtcdBackend) RPCConfig() rpcclient.ConnConfig {
	return b.harness.RPCConfig()
}

// P2PAddr returns the P2P address.
func (b *BtcdBackend) P2PAddr() string {
	return b.harness.P2PAddress()
}

// ConnectMiner connects the backend to the miner.
func (b *BtcdBackend) ConnectMiner(minerAddr string) error {
	// We use "add" to make it persistent.
	err := b.harness.Client.AddNode(minerAddr, "add")
	if err != nil {
		return fmt.Errorf("failed to add miner node %s: %w", minerAddr,
			err)
	}

	return nil
}

// Name returns "btcd".
func (b *BtcdBackend) Name() string {
	return "btcd"
}

// Ensure BtcdBackend implements ChainBackend.
var _ ChainBackend = (*BtcdBackend)(nil)

// NewBackend creates a ChainBackend based on the type string.
// Currently only supports "btcd".
func NewBackend(t *testing.T, backendType string) ChainBackend {
	t.Helper()

	switch backendType {
	case "btcd":
		return NewBtcdBackend(t)
	// TODO: Add bitcoind and neutrino support.
	default:
		t.Fatalf("unknown backend type: %s", backendType)
		return nil
	}
}
