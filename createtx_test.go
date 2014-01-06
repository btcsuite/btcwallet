package main

import (
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwallet/wallet"
	"github.com/conformal/btcwire"
	"testing"
)

type allowFreeTest struct {
	name      string
	inputs    []*tx.Utxo
	curHeight int32
	txSize    int
	free      bool
}

var allowFreeTests = []allowFreeTest{
	allowFreeTest{
		name: "priority < 57,600,000",
		inputs: []*tx.Utxo{
			&tx.Utxo{
				Amt:    uint64(btcutil.SatoshiPerBitcoin),
				Height: 0,
			},
		},
		curHeight: 142, // 143 confirmations
		txSize:    250,
		free:      false,
	},
	allowFreeTest{
		name: "priority == 57,600,000",
		inputs: []*tx.Utxo{
			&tx.Utxo{
				Amt:    uint64(btcutil.SatoshiPerBitcoin),
				Height: 0,
			},
		},
		curHeight: 143, // 144 confirmations
		txSize:    250,
		free:      false,
	},
	allowFreeTest{
		name: "priority > 57,600,000",
		inputs: []*tx.Utxo{
			&tx.Utxo{
				Amt:    uint64(btcutil.SatoshiPerBitcoin),
				Height: 0,
			},
		},
		curHeight: 144, // 145 confirmations
		txSize:    250,
		free:      true,
	},
}

func TestAllowFree(t *testing.T) {
	for _, test := range allowFreeTests {
		calcFree := allowFree(test.curHeight, test.inputs, test.txSize)
		if calcFree != test.free {
			t.Errorf("Allow free test '%v' failed.", test.name)
		}
	}
}

func TestFakeTxs(t *testing.T) {
	// First we need a wallet.
	w, err := wallet.NewWallet("banana wallet", "", []byte("banana"),
		btcwire.MainNet, &wallet.BlockStamp{})
	if err != nil {
		t.Errorf("Can not create encrypted wallet: %s", err)
		return
	}
	a := &Account{
		Wallet: w,
	}

	w.Unlock([]byte("banana"))

	// Create and add a fake Utxo so we have some funds to spend.
	//
	// This will pass validation because btcscript is unaware of invalid
	// tx inputs, however, this example would fail in btcd.
	utxo := &tx.Utxo{}
	addr, err := w.NextChainedAddress(&wallet.BlockStamp{})
	if err != nil {
		t.Errorf("Cannot get next address: %s", err)
		return
	}
	copy(utxo.AddrHash[:], addr.ScriptAddress())
	ophash := (btcwire.ShaHash)([...]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
		28, 29, 30, 31, 32})
	out := btcwire.NewOutPoint(&ophash, 0)
	utxo.Out = tx.OutPoint(*out)
	ss, err := btcscript.PayToAddrScript(addr)
	if err != nil {
		t.Errorf("Could not create utxo PkScript: %s", err)
		return
	}
	utxo.Subscript = tx.PkScript(ss)
	utxo.Amt = 1000000
	utxo.Height = 12345
	a.UtxoStore.s = append(a.UtxoStore.s, utxo)

	// Fake our current block height so btcd doesn't need to be queried.
	curBlock.BlockStamp.Height = 12346

	// Create the transaction.
	pairs := map[string]int64{
		"17XhEvq9Nahdj7Xe1nv6oRe1tEmaHUuynH": 5000,
	}
	_, err = a.txToPairs(pairs, 0)
	if err != nil {
		t.Errorf("Tx creation failed: %s", err)
		return
	}
}
