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

package main

import (
	"github.com/conformal/btcjson"
)

// RPCResponse is an interface type covering both server
// (frontend <-> btcwallet) and client (btcwallet <-> btcd) responses.
type RPCResponse interface {
	Result() interface{}
	Error() *btcjson.Error
}

// ClientRequest is a type holding a bitcoin client's request and
// a channel to send the response.
type ClientRequest struct {
	ws       bool
	request  btcjson.Cmd
	response chan RPCResponse
}

// NewClientRequest creates a new ClientRequest from a btcjson.Cmd.
func NewClientRequest(request btcjson.Cmd, ws bool) *ClientRequest {
	return &ClientRequest{
		ws:       ws,
		request:  request,
		response: make(chan RPCResponse),
	}
}

// Handle sends a client request to the RPC gateway for processing,
// and returns the result when handling is finished.
func (r *ClientRequest) Handle() (interface{}, *btcjson.Error) {
	clientRequests <- r
	resp := <-r.response
	return resp.Result(), resp.Error()
}

// ClientResponse holds a result and error returned from handling a
// client's request.
type ClientResponse struct {
	result interface{}
	err    *btcjson.Error
}

// Result returns the result of a response to a client.
func (r *ClientResponse) Result() interface{} {
	return r.result
}

// Error returns the error of a response to a client, or nil if
// there is no error.
func (r *ClientResponse) Error() *btcjson.Error {
	return r.err
}

// ServerRequest is a type responsible for handling requests to a bitcoin
// server and providing a method to access the response.
type ServerRequest struct {
	request  btcjson.Cmd
	result   interface{}
	response chan RPCResponse
}

// NewServerRequest creates a new ServerRequest from a btcjson.Cmd.  request
// may be nil to create a new var for the result (with types determined by
// the unmarshaling rules described in the json package), or set to a var
// with an expected type (i.e. *btcjson.BlockResult) to directly unmarshal
// the response's result into a convenient type.
func NewServerRequest(request btcjson.Cmd, result interface{}) *ServerRequest {
	return &ServerRequest{
		request:  request,
		result:   result,
		response: make(chan RPCResponse, 1),
	}
}

// ServerResponse holds a response's result and error returned from sending a
// ServerRequest.
type ServerResponse struct {
	// Result will be set to a concrete type (i.e. *btcjson.BlockResult)
	// and may be type asserted to that type if a non-nil result was used
	// to create the originating ServerRequest.  Otherwise, Result will be
	// set to new memory allocated by json.Unmarshal, and the type rules
	// for unmarshaling described in the json package should be followed
	// when type asserting Result.
	result interface{}

	// Err points to an unmarshaled error, or nil if result is valid.
	err *btcjson.Error
}

// Result returns the result of a server's RPC response.
func (r *ServerResponse) Result() interface{} {
	return r.result
}

// Result returns the error of a server's RPC response.
func (r *ServerResponse) Error() *btcjson.Error {
	return r.err
}
