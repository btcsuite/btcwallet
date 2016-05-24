/*
 * Copyright (c) 2016 The Decred developers
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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"sort"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
)

// params is the global representing the chain parameters. It is assigned
// in main.
var params *chaincfg.Params

// configJSON is a configuration file used for transaction generation.
type configJSON struct {
	TxFee         int64  `json:"txfee"`
	SendToAddress string `json:"sendtoaddress"`
	Network       string `json:"network"`
	DcrctlArgs    string `json:"dcrctlargs"`
}

// extendedOutPoint is a UTXO with an amount.
type extendedOutPoint struct {
	op       *wire.OutPoint
	amt      int64
	pkScript []byte
}

// extendedOutPoints is an extendedOutPoint used for sorting by UTXO amount.
type extendedOutPoints struct {
	eops []*extendedOutPoint
}

func (e extendedOutPoints) Len() int { return len(e.eops) }
func (e extendedOutPoints) Less(i, j int) bool {
	return e.eops[i].amt < e.eops[j].amt
}
func (e extendedOutPoints) Swap(i, j int) {
	e.eops[i], e.eops[j] = e.eops[j], e.eops[i]
}

// convertJSONUnspentToOutPoints converts a JSON raw dump from listunspent to
// a set of UTXOs.
func convertJSONUnspentToOutPoints(
	utxos []dcrjson.ListUnspentResult) []*extendedOutPoint {
	var eops []*extendedOutPoint
	for _, utxo := range utxos {
		if utxo.TxType == 1 && utxo.Vout == 0 {
			continue
		}

		op := new(wire.OutPoint)
		hash, _ := chainhash.NewHashFromStr(utxo.TxID)
		op.Hash = *hash
		op.Index = uint32(utxo.Vout)
		op.Tree = int8(utxo.Tree)

		pks, err := hex.DecodeString(utxo.ScriptPubKey)
		if err != nil {
			fmt.Println("failure decoding pkscript from unspent list")
			os.Exit(1)
		}

		eop := new(extendedOutPoint)
		eop.op = op
		amtCast, _ := dcrutil.NewAmount(utxo.Amount)
		eop.amt = int64(amtCast)
		eop.pkScript = pks

		eops = append(eops, eop)
	}

	return eops
}

func main() {
	// 1. Load the UTXOs ----------------------------------------------------------
	unspentFile, err := os.Open("unspent.json")
	if err != nil {
		fmt.Println("error opening unspent file unspent.json", err.Error())
	}

	var utxos []dcrjson.ListUnspentResult

	jsonParser := json.NewDecoder(unspentFile)
	if err = jsonParser.Decode(&utxos); err != nil {
		fmt.Println("error parsing unspent file", err.Error())
	}

	// Sort the inputs so that the largest one is first.
	inputs := extendedOutPoints{convertJSONUnspentToOutPoints(utxos)}
	sort.Sort(sort.Reverse(inputs))

	// 2. Load the config ---------------------------------------------------------
	configFile, err := os.Open("config.json")
	if err != nil {
		fmt.Println("error opening config file config.json", err.Error())
	}

	cfg := new(configJSON)

	jsonParser = json.NewDecoder(configFile)
	if err = jsonParser.Decode(cfg); err != nil {
		fmt.Println("error parsing config file", err.Error())
	}

	// 3. Check the config and parse ----------------------------------------------
	switch cfg.Network {
	case "testnet":
		params = &chaincfg.TestNetParams
	case "mainnet":
		params = &chaincfg.MainNetParams
	case "simnet":
		params = &chaincfg.SimNetParams
	default:
		fmt.Println("Failed to parse a correct network")
		return
	}

	maxTxSize = params.MaximumBlockSize - 75000

	sendToAddress, err := dcrutil.DecodeAddress(cfg.SendToAddress, params)
	if err != nil {
		fmt.Println("Failed to parse tx address: ", err.Error())
	}

	// 4. Create the transaction --------------------------------------------------
	// First get how much we're sending.
	allInAmts := int64(0)
	var utxosToUse []*extendedOutPoint
	for _, utxo := range inputs.eops {
		utxosToUse = append(utxosToUse, utxo)
		allInAmts += utxo.amt
	}

	// Convert to KB.
	sz := float64(estimateTxSize(len(utxosToUse), 1)) / 1000
	feeEst := int64(math.Ceil(sz * float64(cfg.TxFee)))

	tx, err := makeTx(params, utxosToUse, sendToAddress, feeEst)
	if err != nil {
		fmt.Println("Couldn't produce tx: ", err.Error())
		return
	}

	if tx.SerializeSize() > maxTxSize {
		fmt.Printf("tx too big: got %v, max %v", tx.SerializeSize(),
			maxTxSize)
		return
	}

	// 5. Write the transactions to files in raw form with the proper command
	// required to sign them.
	txB, err := tx.Bytes()
	if err != nil {
		fmt.Println("Failed to serialize tx: ", err.Error())
		return
	}

	// The command to sign the transaction.
	var buf bytes.Buffer
	buf.WriteString("dcrctl ")
	buf.WriteString(cfg.DcrctlArgs)
	buf.WriteString(" signrawtransaction ")
	buf.WriteString(hex.EncodeToString(txB))
	buf.WriteString(" '[")
	last := len(utxosToUse) - 1
	for i, utxo := range utxosToUse {
		buf.WriteString("{\"txid\":\"")
		buf.WriteString(utxo.op.Hash.String())
		buf.WriteString("\",\"vout\":")
		buf.WriteString(fmt.Sprintf("%v", utxo.op.Index))
		buf.WriteString(",\"tree\":")
		buf.WriteString(fmt.Sprintf("%v", utxo.op.Tree))
		buf.WriteString(",\"scriptpubkey\":\"")
		buf.WriteString(hex.EncodeToString(utxo.pkScript))
		buf.WriteString("\",\"redeemscript\":\"\"}")
		if i != last {
			buf.WriteString(",")
		}
	}
	buf.WriteString("]' ")
	buf.WriteString("| jq -r .hex")
	err = ioutil.WriteFile("sign.sh", []byte(buf.String()), 0755)
	if err != nil {
		fmt.Println("Failed to write signing script: ", err.Error())
		return
	}

	fmt.Println("Successfully wrote transaction to sign script.")
}
