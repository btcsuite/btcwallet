package chain

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/stretchr/testify/require"
)

// TestValidateConfig checks the `validate` method on the RPCClientConfig
// behaves as expected.
func TestValidateConfig(t *testing.T) {
	t.Parallel()

	rt := require.New(t)

	// ReconnectAttempts must be positive.
	cfg := &RPCClientConfig{
		ReconnectAttempts: -1,
	}
	rt.ErrorContains(cfg.validate(), "reconnectAttempts")

	// Must specify a chain params.
	cfg = &RPCClientConfig{
		ReconnectAttempts: 1,
	}
	rt.ErrorContains(cfg.validate(), "chain params")

	// Must specify a connection config.
	cfg = &RPCClientConfig{
		ReconnectAttempts: 1,
		Chain:             &chaincfg.Params{},
	}
	rt.ErrorContains(cfg.validate(), "conn config")

	// Must specify a certificate when using TLS.
	cfg = &RPCClientConfig{
		ReconnectAttempts: 1,
		Chain:             &chaincfg.Params{},
		Conn:              &rpcclient.ConnConfig{},
	}
	rt.ErrorContains(cfg.validate(), "certs")

	// Validate config.
	cfg = &RPCClientConfig{
		ReconnectAttempts: 1,
		Chain:             &chaincfg.Params{},
		Conn: &rpcclient.ConnConfig{
			DisableTLS: true,
		},
	}
	rt.NoError(cfg.validate())

	// When a nil config is provided, it should return an error.
	_, err := NewRPCClientWithConfig(nil)
	rt.ErrorContains(err, "missing rpc config")
}
