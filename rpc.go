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
	"encoding/json"
	"github.com/conformal/btcjson"
)

// RawRPCResponse is a response to a JSON-RPC request with delayed
// unmarshaling.
type RawRPCResponse struct {
	Id     *uint64
	Result *json.RawMessage `json:"result"`
	Error  *json.RawMessage `json:"error"`
}

// FinishUnmarshal unmarshals the result and error of a raw RPC response.
// If v is non-nil, the result is unmarshaled into the variable pointed
// to by the interface rather than using the rules in the encoding/json
// package to allocate a new variable for the result.  The final result
// and JSON-RPC error is returned.
func (r *RawRPCResponse) FinishUnmarshal(v interface{}) (interface{}, *btcjson.Error) {
	// JSON-RPC spec makes this handling easier-ish because both result and
	// error cannot be non-nil.
	var jsonErr *btcjson.Error
	if r.Error != nil {
		if err := json.Unmarshal([]byte(*r.Error), &jsonErr); err != nil {
			return nil, &btcjson.Error{
				Code:    btcjson.ErrParse.Code,
				Message: err.Error(),
			}
		}
		return nil, jsonErr
	}
	if r.Result != nil {
		if err := json.Unmarshal([]byte(*r.Result), &v); err != nil {
			return nil, &btcjson.Error{
				Code:    btcjson.ErrParse.Code,
				Message: err.Error(),
			}
		}
		return v, nil
	}
	return nil, nil
}

// ClientRequest is a type holding a bitcoin client's request and
// a channel to send the response.
type ClientRequest struct {
	ws       bool
	request  btcjson.Cmd
	response chan RawRPCResponse
}

// NewClientRequest creates a new ClientRequest from a btcjson.Cmd.
func NewClientRequest(request btcjson.Cmd, ws bool) *ClientRequest {
	return &ClientRequest{
		ws:       ws,
		request:  request,
		response: make(chan RawRPCResponse),
	}
}

// Handle sends a client request to the RPC gateway for processing,
// and returns the result when handling is finished.
func (r *ClientRequest) Handle() RawRPCResponse {
	clientRequests <- r
	return <-r.response
}

// ServerRequest is a type responsible for handling requests to a bitcoin
// server and providing a method to access the response.
type ServerRequest struct {
	request  btcjson.Cmd
	response chan RawRPCResponse
}

// NewServerRequest creates a new ServerRequest from a btcjson.Cmd.
func NewServerRequest(request btcjson.Cmd) *ServerRequest {
	return &ServerRequest{
		request:  request,
		response: make(chan RawRPCResponse, 1),
	}
}
