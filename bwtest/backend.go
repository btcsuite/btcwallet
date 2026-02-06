package bwtest

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcwallet/chain"
)

const (
	backendBtcd     = "btcd"
	backendBitcoind = "bitcoind"
	backendNeutrino = "neutrino"
)

var (
	errMissingMinerAddr = errors.New("missing miner address")
)

// ChainBackend defines the interface that all chain backends must implement.
//
// A ChainBackend instance is shared across the whole itest suite run.
// Implementations must be safe to reuse across subtests that run serially.
type ChainBackend interface {
	// Name returns the name of the backend ("btcd", "bitcoind", "neutrino").
	Name() string

	// Start launches the chain backend.
	Start() error

	// Stop shuts down the chain backend.
	Stop() error

	// ConnectMiner connects this backend to the miner.
	ConnectMiner(minerAddr string) error

	// NewChainClient creates a new chain.Interface instance backed by this
	// backend.
	//
	// This is expected to be called once for each subtest. The returned cleanup
	// function must stop and release all resources created by the client.
	NewChainClient(ctx context.Context) (chain.Interface, func(), error)

	// LogDir returns the directory where the backend writes its logs (if any).
	LogDir() string
}

// NewBackend creates a ChainBackend based on the type string.
func NewBackend(t *testing.T, backendType, logDir string) ChainBackend {
	t.Helper()

	switch backendType {
	case backendBtcd:
		return NewBtcdBackend(t, logDir)

	case backendBitcoind, backendNeutrino:
		t.Fatalf("chain backend %q is not implemented yet", backendType)
		return nil

	default:
		t.Fatalf("unknown chain backend %q", backendType)
		return nil
	}
}

// validateBackendType validates the chain backend identifier provided by test
// flags before backend construction starts.
func validateBackendType(t *testing.T, backendType string) {
	t.Helper()

	switch backendType {
	case backendBtcd:
		return

	case backendBitcoind, backendNeutrino:
		t.Fatalf("chain backend %q is not implemented yet", backendType)
		return

	default:
		t.Fatalf("unknown chain backend %q", backendType)
	}
}
