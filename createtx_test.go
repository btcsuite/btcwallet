package main

import (
	"encoding/hex"
	"reflect"
	"sort"
	"testing"

	"github.com/conformal/btcutil"
	"github.com/conformal/btcwallet/keystore"
	"github.com/conformal/btcwallet/txstore"
	"github.com/conformal/btcwire"
	"github.com/davecgh/go-spew/spew"
)

var (
	recvSerializedTx, _ = hex.DecodeString("010000000114d9ff358894c486b4ae11c2a8cf7851b1df64c53d2e511278eff17c22fb7373000000008c493046022100995447baec31ee9f6d4ec0e05cb2a44f6b817a99d5f6de167d1c75354a946410022100c9ffc23b64d770b0e01e7ff4d25fbc2f1ca8091053078a247905c39fce3760b601410458b8e267add3c1e374cf40f1de02b59213a82e1d84c2b94096e22e2f09387009c96debe1d0bcb2356ffdcf65d2a83d4b34e72c62eccd8490dbf2110167783b2bffffffff0280969800000000001976a914479ed307831d0ac19ebc5f63de7d5f1a430ddb9d88ac38bfaa00000000001976a914dadf9e3484f28b385ddeaa6c575c0c0d18e9788a88ac00000000")
	recvTx, _           = btcutil.NewTxFromBytes(recvSerializedTx)
)

func Test_addOutputs(t *testing.T) {
	msgtx := btcwire.NewMsgTx()
	pairs := map[string]btcutil.Amount{
		"1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX": 10,
		"12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG": 1,
	}
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

func Test_createTx(t *testing.T) {
	cfg = &config{DisallowFree: false}
	pairs := map[string]btcutil.Amount{
		"1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX": 10,
		"12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG": 1,
	}

	s := txstore.New("/tmp/tx.bin")
	r, err := s.InsertTx(recvTx, nil)
	if err != nil {
		t.Error(err)
	}
	credit, err := r.AddCredit(0, false)
	if err != nil {
		t.Error(err)
	}
	eligible := []txstore.Credit{credit}

	bs := &keystore.BlockStamp{Height: 11111}
	minconf := 5

	tx, err := createTx(
		eligible, pairs, bs, minconf, defaultFeeIncrement, changeAddress, addInputs)

	if err != nil {
		t.Error(err)
	}
	spew.Dump(tx)
}

func changeAddress(bs *keystore.BlockStamp) (btcutil.Address, error) {
	keys, err := keystore.New("/tmp/keys.bin", "Test keystore", []byte{0}, activeNet.Params, bs)
	if err != nil {
		return nil, err
	}
	return keys.NextChainedAddress(bs)
}

func addInputs(msgtx *btcwire.MsgTx, inputs []txstore.Credit) error {
	return nil
}
