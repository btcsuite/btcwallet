// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package netparams

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// Params is used to group parameters for various networks such as the main
// network and test networks.
type Params struct {
	*chaincfg.Params
	RPCClientPort string
	RPCServerPort string
}

// MainNetParams contains parameters specific running btcwallet and
// btcd on the main network (wire.MainNet).
var MainNetParams = Params{
	Params:        &chaincfg.MainNetParams,
	RPCClientPort: "8334",
	RPCServerPort: "8332",
}

// TestNet3Params contains parameters specific running btcwallet and
// btcd on the test network (version 3) (wire.TestNet3).
var TestNet3Params = Params{
	Params:        &chaincfg.TestNet3Params,
	RPCClientPort: "18334",
	RPCServerPort: "18332",
}

// SimNetParams contains parameters specific to the simulation test network
// (wire.SimNet).
var SimNetParams = Params{
	Params:        &chaincfg.SimNetParams,
	RPCClientPort: "18556",
	RPCServerPort: "18554",
}

// SigNetParams contains parameters specific to the signet test network
// (wire.SigNet).
var SigNetParams = Params{
	Params:        &chaincfg.SigNetParams,
	RPCClientPort: "38334",
	RPCServerPort: "38332",
}

// SigNetWire is a helper function that either returns the given chain
// parameter's net value if the parameter represents a signet network or 0 if
// it's not. This is necessary because there can be custom signet networks that
// have a different net value.
func SigNetWire(params *chaincfg.Params) wire.BitcoinNet {
	if params.Name == chaincfg.SigNetParams.Name {
		return params.Net
	}

	return 0
}
