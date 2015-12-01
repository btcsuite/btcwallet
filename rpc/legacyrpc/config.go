// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacyrpc

// Options contains the required options for running the legacy RPC server.
type Options struct {
	Username string
	Password string

	MaxPOSTClients      int64
	MaxWebsocketClients int64
}
