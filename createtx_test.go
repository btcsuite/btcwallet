package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/conformal/btcjson"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"testing"
)

func TestFakeTxs(t *testing.T) {
	// First we need a wallet.
	w, err := wallet.NewWallet("banana wallet", "", []byte("banana"), btcwire.MainNet)
	if err != nil {
		t.Errorf("Can not create encrypted wallet: %s", err)
		return
	}
	btcw := &BtcWallet{
		Wallet: w,
	}

	w.Unlock([]byte("banana"))

	// Create and add a fake Utxo so we have some funds to spend.
	//
	// This will pass validation because btcscript is unaware of invalid
	// tx inputs, however, this example would fail in btcd.
	utxo := &tx.Utxo{}
	addr, err := w.NextUnusedAddress()
	if err != nil {
		t.Errorf("Cannot get next address: %s", err)
		return
	}
	addr160, _, err := btcutil.DecodeAddress(addr)
	if err != nil {
		t.Errorf("Cannot decode address: %s", err)
		return
	}
	copy(utxo.AddrHash[:], addr160)
	ophash := (btcwire.ShaHash)([...]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
		28, 29, 30, 31, 32})
	out := btcwire.NewOutPoint(&ophash, 0)
	utxo.Out = tx.OutPoint(*out)
	ss, err := btcscript.PayToPubKeyHashScript(addr160)
	if err != nil {
		t.Errorf("Could not create utxo PkScript: %s", err)
		return
	}
	utxo.Subscript = tx.PkScript(ss)
	utxo.Amt = 10000
	utxo.Height = 12345
	btcw.UtxoStore.s = append(btcw.UtxoStore.s, utxo)

	// Fake our current block height so btcd doesn't need to be queried.
	curHeight.h = 12346

	// Create the transaction.
	pairs := map[string]uint64{
		"17XhEvq9Nahdj7Xe1nv6oRe1tEmaHUuynH": 5000,
	}
	rawtx, err := btcw.txToPairs(pairs, 100, 0)
	if err != nil {
		t.Errorf("Tx creation failed: %s", err)
		return
	}

	msg := btcjson.Message{
		Jsonrpc: "1.0",
		Id:      "test",
		Method:  "sendrawtransaction",
		Params: []interface{}{
			hex.EncodeToString(rawtx),
		},
	}
	m, _ := json.Marshal(msg)
	_ = m
	_ = fmt.Println

	// Uncomment to print out json to send raw transaction
	// fmt.Println(string(m))
}
