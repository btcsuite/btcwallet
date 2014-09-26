package main

import (
	"encoding/hex"
	"reflect"
	"sort"
	"testing"

	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/keystore"
	"github.com/conformal/btcwallet/txstore"
	"github.com/conformal/btcwire"
	"github.com/davecgh/go-spew/spew"
)

var (
	recvSerializedTx, _ = hex.DecodeString("010000000114d9ff358894c486b4ae11c2a8cf7851b1df64c53d2e511278eff17c22fb7373000000008c493046022100995447baec31ee9f6d4ec0e05cb2a44f6b817a99d5f6de167d1c75354a946410022100c9ffc23b64d770b0e01e7ff4d25fbc2f1ca8091053078a247905c39fce3760b601410458b8e267add3c1e374cf40f1de02b59213a82e1d84c2b94096e22e2f09387009c96debe1d0bcb2356ffdcf65d2a83d4b34e72c62eccd8490dbf2110167783b2bffffffff0280969800000000001976a914479ed307831d0ac19ebc5f63de7d5f1a430ddb9d88ac38bfaa00000000001976a914dadf9e3484f28b385ddeaa6c575c0c0d18e9788a88ac00000000")
	recvTx, _           = btcutil.NewTxFromBytes(recvSerializedTx)
	changeAddr, _       = btcutil.DecodeAddress("muqW4gcixv58tVbSKRC5q6CRKy8RmyLgZ5", activeNet.Params)
	outAddr1, _         = btcutil.DecodeAddress("1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX", activeNet.Params)
	outAddr2, _         = btcutil.DecodeAddress("12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG", activeNet.Params)
)

func Test_addOutputs(t *testing.T) {
	msgtx := btcwire.NewMsgTx()
	pairs := map[string]btcutil.Amount{outAddr1.String(): 10, outAddr2.String(): 1}
	if err := addOutputs(msgtx, pairs); err != nil {
		t.Fatal(err)
	}
	if len(msgtx.TxOut) != 2 {
		t.Fatalf("Expected 2 outputs, found only %d", len(msgtx.TxOut))
	}
	values := []int{int(msgtx.TxOut[0].Value), int(msgtx.TxOut[1].Value)}
	sort.Ints(values)
	if !reflect.DeepEqual(values, []int{1, 10}) {
		t.Fatalf("Expected values to be [1, 10], got: %v", values)
	}
}

func TestSelectInputs(t *testing.T) {
	credit := newTxCredit(t, recvTx)
	eligible := []txstore.Credit{credit}

	// The requested amount+fee is small enough so selectInputs() should return
	// just the first item.
	selected, amount, err := selectInputs(eligible, 1e4, 1)

	if err != nil {
		t.Fatal("Unexpected error: ", err)
	}
	wantAmount := btcutil.Amount(recvTx.MsgTx().TxOut[0].Value)
	if amount != wantAmount {
		t.Errorf("Unexpected amount; got %s, want %s ", amount, wantAmount)
	}
	if len(selected) != 1 {
		t.Fatalf("Unexpected number of selected inputs; got %d, want 1", len(selected))
	}
	if selected[0] != credit {
		t.Errorf("Unexpected selected input; got %v, want %v", selected[0], credit)
	}
}

func TestSelectInputsInsufficientFunds(t *testing.T) {
	eligible := []txstore.Credit{newTxCredit(t, recvTx)}

	_, _, err := selectInputs(eligible, 1e7, 1)

	if err == nil {
		t.Error("Expected InsufficientFunds, got no error")
	} else if _, ok := err.(InsufficientFunds); !ok {
		t.Errorf("Unexpected error, got %v, want InsufficientFunds", err)
	}
}

func TestCreateTx(t *testing.T) {
	cfg = &config{DisallowFree: false}
	outputs := map[string]btcutil.Amount{outAddr1.String(): 10, outAddr2.String(): 1}
	eligible := []txstore.Credit{newTxCredit(t, recvTx)}
	bs := &keystore.BlockStamp{Height: 11111}

	tx, err := createTx(
		eligible, outputs, bs, defaultFeeIncrement, TstChangeAddress, TstAddInputs)

	if err != nil {
		t.Error(err)
	}
	if tx.changeAddr.String() != changeAddr.String() {
		t.Errorf("Unexpected change address; got %v, want %v",
			tx.changeAddr.String(), changeAddr.String())
	}
	msgTx := tx.tx.MsgTx()
	if len(msgTx.TxOut) != 3 {
		t.Errorf("Unexpected number of outputs; got %d, want 3", len(msgTx.TxOut))
	}
	expectedOutputs := map[btcutil.Address]int64{changeAddr: 9989989, outAddr2: 1, outAddr1: 10}
	for addr, v := range expectedOutputs {
		pkScript, err := btcscript.PayToAddrScript(addr)
		if err != nil {
			t.Fatalf("Cannot create pkScript: %v", err)
		}
		found := false
		for _, txout := range msgTx.TxOut {
			if reflect.DeepEqual(txout.PkScript, pkScript) && txout.Value == v {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("PkScript %v not found in msgTx.TxOut: %v", pkScript, spew.Sdump(msgTx.TxOut))
		}
	}
}

func newTxCredit(t *testing.T, tx *btcutil.Tx) txstore.Credit {
	s := txstore.New("/tmp/tx.bin")
	r, err := s.InsertTx(tx, nil)
	if err != nil {
		t.Fatal(err)
	}
	credit, err := r.AddCredit(0, false)
	if err != nil {
		t.Fatal(err)
	}
	return credit
}

func TstChangeAddress(bs *keystore.BlockStamp) (btcutil.Address, error) {
	return changeAddr, nil
}

func TstAddInputs(msgtx *btcwire.MsgTx, inputs []txstore.Credit) error {
	return nil
}
