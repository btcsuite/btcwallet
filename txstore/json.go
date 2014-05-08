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

package txstore

import (
	"github.com/conformal/btcchain"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
)

// ToJSON returns a slice of btcjson listtransaction result types for all credits
// and debits of this transaction.
func (t *TxRecord) ToJSON(account string, chainHeight int32,
	net btcwire.BitcoinNet) ([]btcjson.ListTransactionsResult, error) {

	var results []btcjson.ListTransactionsResult
	if d := t.Debits(); d != nil {
		r, err := d.ToJSON(account, chainHeight, net)
		if err != nil {
			return nil, err
		}
		results = r
	}
	for _, c := range t.Credits() {
		r, err := c.ToJSON(account, chainHeight, net)
		if err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, nil
}

// ToJSON returns a slice of objects that may be marshaled as a JSON array
// of JSON objects for a listtransactions RPC reply.
func (d *Debits) ToJSON(account string, chainHeight int32,
	net btcwire.BitcoinNet) ([]btcjson.ListTransactionsResult, error) {

	msgTx := d.Tx().MsgTx()
	reply := make([]btcjson.ListTransactionsResult, 0, len(msgTx.TxOut))

	for _, txOut := range msgTx.TxOut {
		address := ""
		_, addrs, _, _ := btcscript.ExtractPkScriptAddrs(txOut.PkScript, net)
		if len(addrs) == 1 {
			address = addrs[0].EncodeAddress()
		}

		result := btcjson.ListTransactionsResult{
			Account:         account,
			Address:         address,
			Category:        "send",
			Amount:          btcutil.Amount(-txOut.Value).ToUnit(btcutil.AmountBTC),
			Fee:             d.Fee().ToUnit(btcutil.AmountBTC),
			TxID:            d.Tx().Sha().String(),
			Time:            d.txRecord.received.Unix(),
			TimeReceived:    d.txRecord.received.Unix(),
			WalletConflicts: []string{},
		}
		if d.BlockHeight != -1 {
			b, err := d.s.lookupBlock(d.BlockHeight)
			if err != nil {
				return nil, err
			}

			result.BlockHash = b.Hash.String()
			result.BlockIndex = int64(d.Tx().Index())
			result.BlockTime = b.Time.Unix()
			result.Confirmations = int64(d.Confirmations(chainHeight))
		}
		reply = append(reply, result)
	}

	return reply, nil
}

// ToJSON returns a slice of objects that may be marshaled as a JSON array
// of JSON objects for a listtransactions RPC reply.
func (c *Credit) ToJSON(account string, chainHeight int32,
	net btcwire.BitcoinNet) (btcjson.ListTransactionsResult, error) {

	msgTx := c.Tx().MsgTx()
	txout := msgTx.TxOut[c.OutputIndex]

	var address string
	_, addrs, _, _ := btcscript.ExtractPkScriptAddrs(txout.PkScript, net)
	if len(addrs) == 1 {
		address = addrs[0].EncodeAddress()
	}

	var category string
	switch {
	case c.IsCoinbase():
		if c.Confirmed(btcchain.CoinbaseMaturity, chainHeight) {
			category = "generate"
		} else {
			category = "immature"
		}
	default:
		category = "receive"
	}

	result := btcjson.ListTransactionsResult{
		Account:         account,
		Category:        category,
		Address:         address,
		Amount:          btcutil.Amount(txout.Value).ToUnit(btcutil.AmountBTC),
		TxID:            c.Tx().Sha().String(),
		Time:            c.received.Unix(),
		TimeReceived:    c.received.Unix(),
		WalletConflicts: []string{},
	}
	if c.BlockHeight != -1 {
		b, err := c.s.lookupBlock(c.BlockHeight)
		if err != nil {
			return btcjson.ListTransactionsResult{}, err
		}

		result.BlockHash = b.Hash.String()
		result.BlockIndex = int64(c.Tx().Index())
		result.BlockTime = b.Time.Unix()
		result.Confirmations = int64(c.Confirmations(chainHeight))
	}

	return result, nil
}
