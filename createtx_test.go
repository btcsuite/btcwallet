package main

import (
	"encoding/hex"
	"reflect"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/keystore"
	"github.com/btcsuite/btcwallet/txstore"
	"github.com/btcsuite/btcwire"
)

// This is a tx that transfers funds (0.371 BTC) to addresses of known privKeys.
// It contains 6 outputs, in this order, with the following values/addresses:
// {0: 0.2283 (addr: myVT6o4GfR57Cfw7pP3vayfHZzMHh2BxXJ - change),
//  1: 0.03   (addr: mjqnv9JoxdYyQK7NMZGCKLxNWHfA6XFVC7),
//  2: 0.09   (addr: mqi4izJxVr9wRJmoHe3CUjdb7YDzpJmTwr),
//  3: 0.1    (addr: mu7q5vxiGCXYKXEtvspP77bYxjnsEobJGv),
//  4: 0.15   (addr: mw66YGmegSNv3yfS4brrtj6ZfAZ4DMmhQN),
//  5: 0.001  (addr: mgLBkENLdGXXMfu5RZYPuhJdC88UgvsAxY)}
var txInfo = struct {
	hex      string
	amount   btcutil.Amount
	privKeys []string
}{
	hex:    "010000000113918955c6ba3c7a2e8ec02ca3e91a2571cb11ade7d5c3e9c1a73b3ac8309d74000000006b483045022100a6f33d4ad476d126ee45e19e43190971e148a1e940abe4165bc686d22ac847e502200936efa4da4225787d4b7e11e8f3389dba626817d7ece0cab38b4f456b0880d6012103ccb8b1038ad6af10a15f68e8d5e347c08befa6cc2ab1718a37e3ea0e38102b92ffffffff06b05b5c01000000001976a914c5297a660cef8088b8472755f4827df7577c612988acc0c62d00000000001976a9142f7094083d750bdfc1f2fad814779e2dde35ce2088ac40548900000000001976a9146fcb336a187619ca20b84af9eac9fbff68d1061d88ac80969800000000001976a91495322d12e18345f4855cbe863d4a8ebcc0e95e0188acc0e1e400000000001976a914aace7f06f94fa298685f6e58769543993fa5fae888aca0860100000000001976a91408eec7602655fdb2531f71070cca4c363c3a15ab88ac00000000",
	amount: btcutil.Amount(3e6 + 9e6 + 1e7 + 1.5e7 + 1e5),
	privKeys: []string{
		"cSYUVdPL6pkabu7Fxp4PaKqYjJFz2Aopw5ygunFbek9HAimLYxp4",
		"cVnNzZm3DiwkN1Ghs4W8cwcJC9f6TynCCcqzYt8n1c4hwjN2PfTw",
		"cUgo8PrKj7NzttKRMKwgF3ahXNrLA253pqjWkPGS7Z9iZcKT8EKG",
		"cSosEHx1freK7B1B6QicPcrH1h5VqReSHew6ZYhv6ntiUJRhowRc",
		"cR9ApAZ3FLtRMfqRBEr3niD9Mmmvfh3V8Uh56qfJ5b4bFH8ibDkA"}}

var (
	outAddr1 = "1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX"
	outAddr2 = "12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG"
)

func Test_addOutputs(t *testing.T) {
	msgtx := btcwire.NewMsgTx()
	pairs := map[string]btcutil.Amount{outAddr1: 10, outAddr2: 1}
	if _, err := addOutputs(msgtx, pairs); err != nil {
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

func TestCreateTx(t *testing.T) {
	cfg = &config{DisallowFree: false}
	bs := &keystore.BlockStamp{Height: 11111}
	keys := newKeyStore(t, txInfo.privKeys, bs)
	changeAddr, _ := btcutil.DecodeAddress("muqW4gcixv58tVbSKRC5q6CRKy8RmyLgZ5", activeNet.Params)
	var tstChangeAddress = func(bs *keystore.BlockStamp) (btcutil.Address, error) {
		return changeAddr, nil
	}

	// Pick all utxos from txInfo as eligible input.
	eligible := eligibleInputsFromTx(t, txInfo.hex, []uint32{1, 2, 3, 4, 5})
	// Now create a new TX sending 25e6 satoshis to the following addresses:
	outputs := map[string]btcutil.Amount{outAddr1: 15e6, outAddr2: 10e6}
	tx, err := createTx(eligible, outputs, bs, defaultFeeIncrement, keys, tstChangeAddress)
	if err != nil {
		t.Fatal(err)
	}

	if tx.changeAddr.String() != changeAddr.String() {
		t.Fatalf("Unexpected change address; got %v, want %v",
			tx.changeAddr.String(), changeAddr.String())
	}

	msgTx := tx.tx.MsgTx()
	if len(msgTx.TxOut) != 3 {
		t.Fatalf("Unexpected number of outputs; got %d, want 3", len(msgTx.TxOut))
	}

	// The outputs in our new TX amount to 25e6 satoshis, so to fulfil that
	// createTx should have picked the utxos with indices 4, 3 and 5, which
	// total 25.1e6.
	if len(msgTx.TxIn) != 3 {
		t.Fatalf("Unexpected number of inputs; got %d, want 3", len(msgTx.TxIn))
	}

	// Given the input (15e6 + 10e6 + 1e7) and requested output (15e6 + 10e6)
	// amounts in the new TX, we should have a change output with 8.99e6, which
	// implies a fee of 1e3 satoshis.
	expectedChange := btcutil.Amount(8.999e6)

	outputs[changeAddr.String()] = expectedChange
	checkOutputsMatch(t, msgTx, outputs)

	minFee := feeForSize(defaultFeeIncrement, msgTx.SerializeSize())
	actualFee := btcutil.Amount(1e3)
	if minFee > actualFee {
		t.Fatalf("Requested fee (%v) for tx size higher than actual fee (%v)", minFee, actualFee)
	}
}

func TestCreateTxInsufficientFundsError(t *testing.T) {
	cfg = &config{DisallowFree: false}
	outputs := map[string]btcutil.Amount{outAddr1: 10, outAddr2: 1e9}
	eligible := eligibleInputsFromTx(t, txInfo.hex, []uint32{1})
	bs := &keystore.BlockStamp{Height: 11111}
	changeAddr, _ := btcutil.DecodeAddress("muqW4gcixv58tVbSKRC5q6CRKy8RmyLgZ5", activeNet.Params)
	var tstChangeAddress = func(bs *keystore.BlockStamp) (btcutil.Address, error) {
		return changeAddr, nil
	}

	_, err := createTx(eligible, outputs, bs, defaultFeeIncrement, nil, tstChangeAddress)

	if err == nil {
		t.Error("Expected InsufficientFundsError, got no error")
	} else if _, ok := err.(InsufficientFundsError); !ok {
		t.Errorf("Unexpected error, got %v, want InsufficientFundsError", err)
	}
}

// checkOutputsMatch checks that the outputs in the tx match the expected ones.
func checkOutputsMatch(t *testing.T, msgtx *btcwire.MsgTx, expected map[string]btcutil.Amount) {
	// This is a bit convoluted because the index of the change output is randomized.
	for addrStr, v := range expected {
		addr, err := btcutil.DecodeAddress(addrStr, activeNet.Params)
		if err != nil {
			t.Fatalf("Cannot decode address: %v", err)
		}
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			t.Fatalf("Cannot create pkScript: %v", err)
		}
		found := false
		for _, txout := range msgtx.TxOut {
			if reflect.DeepEqual(txout.PkScript, pkScript) && txout.Value == int64(v) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("PkScript %v not found in msgtx.TxOut: %v", pkScript, msgtx.TxOut)
		}
	}
}

// newKeyStore creates a new keystore and imports the given privKey into it.
func newKeyStore(t *testing.T, privKeys []string, bs *keystore.BlockStamp) *keystore.Store {
	passphrase := []byte{0, 1}
	keys, err := keystore.New("/tmp/keys.bin", "Default acccount", passphrase,
		activeNet.Params, bs)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range privKeys {
		wif, err := btcutil.DecodeWIF(key)
		if err != nil {
			t.Fatal(err)
		}
		if err = keys.Unlock(passphrase); err != nil {
			t.Fatal(err)
		}
		_, err = keys.ImportPrivateKey(wif, bs)
		if err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// eligibleInputsFromTx decodes the given txHex and returns the outputs with
// the given indices as eligible inputs.
func eligibleInputsFromTx(t *testing.T, txHex string, indices []uint32) []txstore.Credit {
	serialized, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := btcutil.NewTxFromBytes(serialized)
	if err != nil {
		t.Fatal(err)
	}
	s := txstore.New("/tmp/tx.bin")
	r, err := s.InsertTx(tx, nil)
	if err != nil {
		t.Fatal(err)
	}
	eligible := make([]txstore.Credit, len(indices))
	for i, idx := range indices {
		credit, err := r.AddCredit(idx, false)
		if err != nil {
			t.Fatal(err)
		}
		eligible[i] = credit
	}
	return eligible
}
