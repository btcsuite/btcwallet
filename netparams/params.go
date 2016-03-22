// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package netparams

import "github.com/decred/dcrd/chaincfg"

// Params is used to group parameters for various networks such as the main
// network and test networks.
type Params struct {
	*chaincfg.Params
	RPCClientPort string
	RPCServerPort string
}

// MainNetParams contains parameters specific running dcrwallet and
// dcrd on the main network (wire.MainNet).
var MainNetParams = Params{
	Params:        &chaincfg.MainNetParams,
	RPCClientPort: "9109",
	RPCServerPort: "9110",
}

// TestNetParams contains parameters specific running dcrwallet and
// dcrd on the test network (version 1) (wire.TestNet).
var TestNetParams = Params{
	Params:        &chaincfg.TestNetParams,
	RPCClientPort: "19109",
	RPCServerPort: "19110",
}

// SimNetParams contains parameters specific to the simulation test network
// (wire.SimNet).
var SimNetParams = Params{
	Params:        &chaincfg.SimNetParams,
	RPCClientPort: "19556",
	RPCServerPort: "19557",
}
