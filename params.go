/*
 * Copyright (c) 2013, 2014 The btcsuite developers
 * Copyright (c) 2015 The Decred developers
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"github.com/decred/dcrd/chaincfg"
)

var activeNet = &testNetParams

// params is used to group parameters for various networks such as the main
// network and test networks.
type params struct {
	*chaincfg.Params
	connect  string
	dcrdPort string
	svrPort  string
}

// mainNetParams contains parameters specific running dcrwallet and
// dcrd on the main network (wire.MainNet).
var mainNetParams = params{
	Params:   &chaincfg.MainNetParams,
	connect:  "localhost:9109",
	dcrdPort: "9109",
	svrPort:  "9110",
}

// testNetParams contains parameters specific running dcrwallet and
// dcrd on the test network (version 0) (wire.TestNet).
var testNetParams = params{
	Params:   &chaincfg.TestNetParams,
	connect:  "localhost:19109",
	dcrdPort: "19109",
	svrPort:  "19110",
}

// simNetParams contains parameters specific to the simulation test network
// (wire.SimNet).
var simNetParams = params{
	Params:   &chaincfg.SimNetParams,
	connect:  "localhost:19556",
	dcrdPort: "19556",
	svrPort:  "19557",
}
