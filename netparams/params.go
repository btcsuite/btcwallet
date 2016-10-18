// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package netparams

import "github.com/jadeblaquiere/ctcd/chaincfg"

// Params is used to group parameters for various networks such as the main
// network and test networks.
type Params struct {
	*chaincfg.Params
	RPCClientPort string
	RPCServerPort string
}

// CTIndigoNetParams contains parameters specific to the ciphrtxt indigo network
// (wire.SimNet).
var CTIndigoNetParams = Params{
	Params:        &chaincfg.CTIndigoNetParams,
	RPCClientPort: "7765",
	RPCServerPort: "7766",
}

// CTRedNetParams contains parameters specific to the ciphrtxt red test network
// (wire.SimNet).
var CTRedNetParams = Params{
	Params:        &chaincfg.CTRedNetParams,
	RPCClientPort: "17762",
	RPCServerPort: "17763",
}
