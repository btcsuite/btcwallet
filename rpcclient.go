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

// This file implements the websocket client connection to a bitcoin RPC
// server.

package main

import (
	"code.google.com/p/go.net/websocket"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	"github.com/conformal/btcws"
	"io"
)

// ServerConn is an interface representing a client connection to a bitcoin RPC
// server.
type ServerConn interface {
	// SendRequest sends a bitcoin RPC request, returning a channel to
	// read the reply.  A channel is used so both synchronous and
	// asynchronous RPC can be supported.
	SendRequest(request *ServerRequest) chan RPCResponse
}

// ErrBtcdDisconnected describes an error where an operation cannot
// successfully complete due to btcwallet not being connected to
// btcd.
var ErrBtcdDisconnected = btcjson.Error{
	Code:    -1,
	Message: "btcd disconnected",
}

// BtcdRPCConn is a type managing a client connection to a btcd RPC server
// over websockets.
type BtcdRPCConn struct {
	ws         *websocket.Conn
	addRequest chan *AddRPCRequest
	closed     chan struct{}
}

// Ensure that BtcdRPCConn can be used as an RPCConn.
var _ ServerConn = &BtcdRPCConn{}

// NewBtcdRPCConn creates a new RPC connection from a btcd websocket
// connection to btcd.
func NewBtcdRPCConn(ws *websocket.Conn) *BtcdRPCConn {
	conn := &BtcdRPCConn{
		ws:         ws,
		addRequest: make(chan *AddRPCRequest),
		closed:     make(chan struct{}),
	}
	return conn
}

// SendRequest sends an RPC request and returns a channel to read the response's
// result and error.  Part of the RPCConn interface.
func (btcd *BtcdRPCConn) SendRequest(request *ServerRequest) chan RPCResponse {
	select {
	case <-btcd.closed:
		// The connection has closed, so instead of adding and sending
		// a request, return a channel that just replies with the
		// error for a disconnected btcd.
		responseChan := make(chan RPCResponse, 1)
		response := &ServerResponse{
			err: &ErrBtcdDisconnected,
		}
		responseChan <- response
		return responseChan

	default:
		addRequest := &AddRPCRequest{
			Request:      request,
			ResponseChan: make(chan chan RPCResponse, 1),
		}
		btcd.addRequest <- addRequest
		return <-addRequest.ResponseChan
	}
}

// Connected returns whether the connection remains established to the RPC
// server.
//
// This function probably should be removed, as any checks for confirming
// the connection are no longer valid after the check and may result in
// races.
func (btcd *BtcdRPCConn) Connected() bool {
	select {
	case <-btcd.closed:
		return false

	default:
		return true
	}
}

// Close forces closing the current btcd connection.
func (btcd *BtcdRPCConn) Close() {
	select {
	case <-btcd.closed:
	default:
		close(btcd.closed)
	}
}

// AddRPCRequest is used to add an RPCRequest to the pool of requests
// being manaaged by a btcd RPC connection.
type AddRPCRequest struct {
	Request      *ServerRequest
	ResponseChan chan chan RPCResponse
}

// send performs the actual send of the marshaled request over the btcd
// websocket connection.
func (btcd *BtcdRPCConn) send(rpcrequest *ServerRequest) error {
	// btcjson.Cmds define their own MarshalJSON which returns an error
	// to satisify the json.Marshaler interface, but will never error.
	mrequest, _ := rpcrequest.request.MarshalJSON()
	return websocket.Message.Send(btcd.ws, mrequest)
}

type receivedResponse struct {
	id    uint64
	raw   string
	reply *btcjson.Reply
}

// Start starts the goroutines required to send RPC requests and listen for
// replies.
func (btcd *BtcdRPCConn) Start() {
	done := btcd.closed
	responses := make(chan *receivedResponse)

	// Maintain a map of JSON IDs to RPCRequests currently being waited on.
	go func() {
		m := make(map[uint64]*ServerRequest)
		for {
			select {
			case addrequest := <-btcd.addRequest:
				rpcrequest := addrequest.Request
				m[rpcrequest.request.Id().(uint64)] = rpcrequest

				if err := btcd.send(rpcrequest); err != nil {
					// Connection lost.
					log.Infof("Cannot complete btcd websocket send: %v",
						err)
					btcd.ws.Close()
					close(done)
				}

				addrequest.ResponseChan <- rpcrequest.response

			case recvResponse, ok := <-responses:
				if !ok {
					responses = nil
					close(done)
					break
				}
				rpcrequest, ok := m[recvResponse.id]
				if !ok {
					log.Warnf("Received unexpected btcd response")
					continue
				}
				delete(m, recvResponse.id)

				// If no result var was set, create and send
				// send the response unmarshaled by the json
				// package.
				if rpcrequest.result == nil {
					response := &ServerResponse{
						result: recvResponse.reply.Result,
						err:    recvResponse.reply.Error,
					}
					rpcrequest.response <- response
					continue
				}

				// A return var was set, so unmarshal again
				// into the var before sending the response.
				r := &btcjson.Reply{
					Result: rpcrequest.result,
				}
				json.Unmarshal([]byte(recvResponse.raw), &r)
				response := &ServerResponse{
					result: r.Result,
					err:    r.Error,
				}
				rpcrequest.response <- response

			case <-done:
				response := &ServerResponse{
					err: &ErrBtcdDisconnected,
				}
				for _, request := range m {
					request.response <- response
				}
				return
			}
		}
	}()

	// Listen for replies/notifications from btcd, and decide how to handle them.
	go func() {
		// Idea: instead of reading btcd messages from just one websocket
		// connection, maybe use two so the same connection isn't used
		// for both notifications and responses?  Should make handling
		// must faster as unnecessary unmarshal attempts could be avoided.

		for {
			var m string
			if err := websocket.Message.Receive(btcd.ws, &m); err != nil {
				// Log warning if btcd did not disconnect.
				if err != io.EOF {
					log.Infof("Cannot receive btcd websocket message: %v",
						err)
				}
				btcd.ws.Close()
				close(responses)
				return
			}

			// Try notifications (requests with nil ids) first.
			n, err := unmarshalNotification(m)
			if err == nil {
				svrNtfns <- n
				continue
			}

			// Must be a response.
			r, err := unmarshalResponse(m)
			if err == nil {
				responses <- r
				continue
			}

			// Not sure what was received but it isn't correct.
			log.Warnf("Received invalid message from btcd")
		}
	}()
}

// unmarshalResponse attempts to unmarshal a marshaled JSON-RPC
// response.
func unmarshalResponse(s string) (*receivedResponse, error) {
	var r btcjson.Reply
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return nil, err
	}

	// Check for a valid ID.
	if r.Id == nil {
		return nil, errors.New("id is nil")
	}
	fid, ok := (*r.Id).(float64)
	if !ok {
		return nil, errors.New("id is not a number")
	}
	response := &receivedResponse{
		id:    uint64(fid),
		raw:   s,
		reply: &r,
	}
	return response, nil
}

// unmarshalNotification attempts to unmarshal a marshaled JSON-RPC
// notification (Request with a nil or no ID).
func unmarshalNotification(s string) (btcjson.Cmd, error) {
	req, err := btcjson.ParseMarshaledCmd([]byte(s))
	if err != nil {
		return nil, err
	}

	if req.Id() != nil {
		return nil, errors.New("id is non-nil")
	}

	return req, nil
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
func GetBestBlock(rpc ServerConn) (*GetBestBlockResult, *btcjson.Error) {
	cmd := btcws.NewGetBestBlockCmd(<-NewJSONID)
	request := NewServerRequest(cmd, new(GetBestBlockResult))
	response := <-rpc.SendRequest(request)
	if response.Error() != nil {
		return nil, response.Error()
	}
	return response.Result().(*GetBestBlockResult), nil
}

// GetBlock requests details about a block with the given hash.
func GetBlock(rpc ServerConn, blockHash string) (*btcjson.BlockResult, *btcjson.Error) {
	// NewGetBlockCmd cannot fail with no optargs, so omit the check.
	cmd, _ := btcjson.NewGetBlockCmd(<-NewJSONID, blockHash)
	request := NewServerRequest(cmd, new(btcjson.BlockResult))
	response := <-rpc.SendRequest(request)
	if response.Error() != nil {
		return nil, response.Error()
	}
	return response.Result().(*btcjson.BlockResult), nil
}

// GetCurrentNet requests the network a bitcoin RPC server is running on.
func GetCurrentNet(rpc ServerConn) (btcwire.BitcoinNet, *btcjson.Error) {
	cmd := btcws.NewGetCurrentNetCmd(<-NewJSONID)
	request := NewServerRequest(cmd, nil)
	response := <-rpc.SendRequest(request)
	if response.Error() != nil {
		return 0, response.Error()
	}
	return btcwire.BitcoinNet(uint32(response.Result().(float64))), nil
}

// NotifyBlocks requests blockconnected and blockdisconnected notifications.
func NotifyBlocks(rpc ServerConn) *btcjson.Error {
	cmd := btcws.NewNotifyBlocksCmd(<-NewJSONID)
	request := NewServerRequest(cmd, nil)
	response := <-rpc.SendRequest(request)
	return response.Error()
}

// NotifyNewTXs requests notifications for new transactions that spend
// to any of the addresses in addrs.
func NotifyNewTXs(rpc ServerConn, addrs []string) *btcjson.Error {
	cmd := btcws.NewNotifyNewTXsCmd(<-NewJSONID, addrs)
	request := NewServerRequest(cmd, nil)
	response := <-rpc.SendRequest(request)
	return response.Error()
}

// NotifySpent requests notifications for when a transaction is processed which
// spends op.
func NotifySpent(rpc ServerConn, op *btcwire.OutPoint) *btcjson.Error {
	cmd := btcws.NewNotifySpentCmd(<-NewJSONID, op)
	request := NewServerRequest(cmd, nil)
	response := <-rpc.SendRequest(request)
	return response.Error()
}

// Rescan requests a blockchain rescan for transactions to any number of
// addresses and notifications to inform wallet about such transactions.
func Rescan(rpc ServerConn, beginBlock int32, addrs map[string]struct{}) *btcjson.Error {
	// NewRescanCmd cannot fail with no optargs, so omit the check.
	cmd, _ := btcws.NewRescanCmd(<-NewJSONID, beginBlock, addrs)
	request := NewServerRequest(cmd, nil)
	response := <-rpc.SendRequest(request)
	return response.Error()
}

// SendRawTransaction sends a hex-encoded transaction for relay.
func SendRawTransaction(rpc ServerConn, hextx string) (txid string, error *btcjson.Error) {
	// NewSendRawTransactionCmd cannot fail, so omit the check.
	cmd, _ := btcjson.NewSendRawTransactionCmd(<-NewJSONID, hextx)
	request := NewServerRequest(cmd, new(string))
	response := <-rpc.SendRequest(request)
	if response.Error() != nil {
		return "", response.Error()
	}
	return *response.Result().(*string), nil
}

// GetRawTransaction sends the non-verbose version of a getrawtransaction
// request to receive the serialized transaction referenced by txsha.  If
// successful, the transaction is decoded and returned as a btcutil.Tx.
func GetRawTransaction(rpc ServerConn, txsha *btcwire.ShaHash) (*btcutil.Tx, *btcjson.Error) {
	// NewGetRawTransactionCmd cannot fail with no optargs.
	cmd, _ := btcjson.NewGetRawTransactionCmd(<-NewJSONID, txsha.String())
	request := NewServerRequest(cmd, new(string))
	response := <-rpc.SendRequest(request)
	if response.Error() != nil {
		return nil, response.Error()
	}
	hextx := *response.Result().(*string)
	serializedTx, err := hex.DecodeString(hextx)
	if err != nil {
		return nil, &btcjson.ErrDecodeHexString
	}
	utx, err := btcutil.NewTxFromBytes(serializedTx)
	if err != nil {
		return nil, &btcjson.ErrDeserialization
	}
	return utx, nil
}

// VerboseGetRawTransaction sends the verbose version of a getrawtransaction
// request to receive details about a transaction.
func VerboseGetRawTransaction(rpc ServerConn, txsha *btcwire.ShaHash) (*btcjson.TxRawResult, *btcjson.Error) {
	// NewGetRawTransactionCmd cannot fail with a single optarg.
	cmd, _ := btcjson.NewGetRawTransactionCmd(<-NewJSONID, txsha.String(), 1)
	request := NewServerRequest(cmd, new(btcjson.TxRawResult))
	response := <-rpc.SendRequest(request)
	if response.Error() != nil {
		return nil, response.Error()
	}
	return response.Result().(*btcjson.TxRawResult), nil
}
