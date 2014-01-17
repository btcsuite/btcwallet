/*
 * Copyright (c) 2013, 2014 Conformal Systems LLC <info@conformal.com>
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

// This file implements the RPC connection interface and functions to
// communicate with a bitcoin RPC server.

package main

import (
	"github.com/conformal/btcjson"
	"github.com/conformal/btcwire"
	"github.com/conformal/btcws"
)

// RPCRequest is a type responsible for handling RPC requests and providing
// a method to access the response.
type RPCRequest struct {
	request  btcjson.Cmd
	result   interface{}
	response chan *RPCResponse
}

// NewRPCRequest creates a new RPCRequest from a btcjson.Cmd.  request may be
// nil to create a new var for the result (with types determined by the
// unmarshaling rules described in the json package), or set to a var with
// an expected type (i.e. *btcjson.BlockResult) to directly unmarshal the
// response's result into a convenient type.
func NewRPCRequest(request btcjson.Cmd, result interface{}) *RPCRequest {
	return &RPCRequest{
		request:  request,
		result:   result,
		response: make(chan *RPCResponse),
	}
}

// RPCResponse holds a response's result and error returned from sending a
// RPCRequest.
type RPCResponse struct {
	// Result will be set to a concrete type (i.e. *btcjson.BlockResult)
	// and may be type asserted to that type if a non-nil result was used
	// to create the originating RPCRequest.  Otherwise, Result will be
	// set to new memory allocated by json.Unmarshal, and the type rules
	// for unmarshaling described in the json package should be followed
	// when type asserting Result.
	Result interface{}

	// Err points to an unmarshaled error, or nil if result is valid.
	Err *btcjson.Error
}

// RPCConn is an interface representing a client connection to a bitcoin RPC
// server.
type RPCConn interface {
	// SendRequest sends a bitcoin RPC request, returning a channel to
	// read the reply.  A channel is used so both synchronous and
	// asynchronous RPC can be supported.
	SendRequest(request *RPCRequest) chan *RPCResponse
}

// GetBestBlockResult holds the result of a getbestblock response.
//
// TODO(jrick): shove this in btcws.
type GetBestBlockResult struct {
	Hash   string `json:"hash"`
	Height int32  `json:"height"`
}

// GetBestBlock gets both the block height and hash of the best block
// in the main chain.
func GetBestBlock(rpc RPCConn) (*GetBestBlockResult, *btcjson.Error) {
	cmd := btcws.NewGetBestBlockCmd(<-NewJSONID)
	request := NewRPCRequest(cmd, new(GetBestBlockResult))
	response := <-rpc.SendRequest(request)
	if response.Err != nil {
		return nil, response.Err
	}
	return response.Result.(*GetBestBlockResult), nil
}

// GetBlock requests details about a block with the given hash.
func GetBlock(rpc RPCConn, blockHash string) (*btcjson.BlockResult, *btcjson.Error) {
	// NewGetBlockCmd cannot fail with no optargs, so omit the check.
	cmd, _ := btcjson.NewGetBlockCmd(<-NewJSONID, blockHash)
	request := NewRPCRequest(cmd, new(btcjson.BlockResult))
	response := <-rpc.SendRequest(request)
	if response.Err != nil {
		return nil, response.Err
	}
	return response.Result.(*btcjson.BlockResult), nil
}

// GetCurrentNet requests the network a bitcoin RPC server is running on.
func GetCurrentNet(rpc RPCConn) (btcwire.BitcoinNet, *btcjson.Error) {
	cmd := btcws.NewGetCurrentNetCmd(<-NewJSONID)
	request := NewRPCRequest(cmd, nil)
	response := <-rpc.SendRequest(request)
	if response.Err != nil {
		return 0, response.Err
	}
	return btcwire.BitcoinNet(uint32(response.Result.(float64))), nil
}

// NotifyBlocks requests blockconnected and blockdisconnected notifications.
func NotifyBlocks(rpc RPCConn) *btcjson.Error {
	cmd := btcws.NewNotifyBlocksCmd(<-NewJSONID)
	request := NewRPCRequest(cmd, nil)
	response := <-rpc.SendRequest(request)
	return response.Err
}

// NotifyNewTXs requests notifications for new transactions that spend
// to any of the addresses in addrs.
func NotifyNewTXs(rpc RPCConn, addrs []string) *btcjson.Error {
	cmd := btcws.NewNotifyNewTXsCmd(<-NewJSONID, addrs)
	request := NewRPCRequest(cmd, nil)
	response := <-rpc.SendRequest(request)
	return response.Err
}

// NotifySpent requests notifications for when a transaction is processed which
// spends op.
func NotifySpent(rpc RPCConn, op *btcwire.OutPoint) *btcjson.Error {
	cmd := btcws.NewNotifySpentCmd(<-NewJSONID, op)
	request := NewRPCRequest(cmd, nil)
	response := <-rpc.SendRequest(request)
	return response.Err
}

// Rescan requests a blockchain rescan for transactions to any number of
// addresses and notifications to inform wallet about such transactions.
func Rescan(rpc RPCConn, beginBlock int32, addrs map[string]struct{}) *btcjson.Error {
	// NewRescanCmd cannot fail with no optargs, so omit the check.
	cmd, _ := btcws.NewRescanCmd(<-NewJSONID, beginBlock, addrs)
	request := NewRPCRequest(cmd, nil)
	response := <-rpc.SendRequest(request)
	return response.Err
}

// SendRawTransaction sends a hex-encoded transaction for relay.
func SendRawTransaction(rpc RPCConn, hextx string) (txid string, error *btcjson.Error) {
	// NewSendRawTransactionCmd cannot fail, so omit the check.
	cmd, _ := btcjson.NewSendRawTransactionCmd(<-NewJSONID, hextx)
	request := NewRPCRequest(cmd, new(string))
	response := <-rpc.SendRequest(request)
	if response.Err != nil {
		return "", response.Err
	}
	return *response.Result.(*string), nil
}
