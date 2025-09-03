// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacyrpc

import (
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcwallet/build"
)

var log = btclog.Disabled

func init() {
	UseLogger(build.NewSubLogger("RPCS", nil))
}

// UseLogger sets the package-wide logger.  Any calls to this function must be
// made before a server is created and used (it is not concurrent safe).
func UseLogger(logger btclog.Logger) {
	log = logger
}
