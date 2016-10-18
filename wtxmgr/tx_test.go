// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr_test

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jadeblaquiere/ctcd/chaincfg"
	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcd/wire"
	"github.com/jadeblaquiere/ctcutil"
	"github.com/jadeblaquiere/ctcwallet/walletdb"
	_ "github.com/jadeblaquiere/ctcwallet/walletdb/bdb"
	. "github.com/jadeblaquiere/ctcwallet/wtxmgr"
)

// Received transaction output for mainnet outpoint
// 61d3696de4c888730cbe06b0ad8ecb6d72d6108e893895aa9bc067bd7eba3fad:0
var (
	TstRecvSerializedTx, _          = hex.DecodeString("010000000114d9ff358894c486b4ae11c2a8cf7851b1df64c53d2e511278eff17c22fb7373000000008c493046022100995447baec31ee9f6d4ec0e05cb2a44f6b817a99d5f6de167d1c75354a946410022100c9ffc23b64d770b0e01e7ff4d25fbc2f1ca8091053078a247905c39fce3760b601410458b8e267add3c1e374cf40f1de02b59213a82e1d84c2b94096e22e2f09387009c96debe1d0bcb2356ffdcf65d2a83d4b34e72c62eccd8490dbf2110167783b2bffffffff0280969800000000001976a914479ed307831d0ac19ebc5f63de7d5f1a430ddb9d88ac38bfaa00000000001976a914dadf9e3484f28b385ddeaa6c575c0c0d18e9788a88ac00000000")
	TstRecvTx, _                    = btcutil.NewTxFromBytes(TstRecvSerializedTx)
	TstRecvTxSpendingTxBlockHash, _ = chainhash.NewHashFromStr("00000000000000017188b968a371bab95aa43522665353b646e41865abae02a4")
	TstRecvAmt                      = int64(10000000)
	TstRecvTxBlockDetails           = &BlockMeta{
		Block: Block{Hash: *TstRecvTxSpendingTxBlockHash, Height: 276425},
		Time:  time.Unix(1387737310, 0),
	}

	TstRecvCurrentHeight = int32(284498) // mainnet blockchain height at time of writing
	TstRecvTxOutConfirms = 8074          // hardcoded number of confirmations given the above block height

	TstSpendingSerializedTx, _ = hex.DecodeString("0100000003ad3fba7ebd67c09baa9538898e10d6726dcb8eadb006be0c7388c8e46d69d361000000006b4830450220702c4fbde5532575fed44f8d6e8c3432a2a9bd8cff2f966c3a79b2245a7c88db02210095d6505a57e350720cb52b89a9b56243c15ddfcea0596aedc1ba55d9fb7d5aa0012103cccb5c48a699d3efcca6dae277fee6b82e0229ed754b742659c3acdfed2651f9ffffffffdbd36173f5610e34de5c00ed092174603761595d90190f790e79cda3e5b45bc2010000006b483045022000fa20735e5875e64d05bed43d81b867f3bd8745008d3ff4331ef1617eac7c44022100ad82261fc57faac67fc482a37b6bf18158da0971e300abf5fe2f9fd39e107f58012102d4e1caf3e022757512c204bf09ff56a9981df483aba3c74bb60d3612077c9206ffffffff65536c9d964b6f89b8ef17e83c6666641bc495cb27bab60052f76cd4556ccd0d040000006a473044022068e3886e0299ffa69a1c3ee40f8b6700f5f6d463a9cf9dbf22c055a131fc4abc02202b58957fe19ff1be7a84c458d08016c53fbddec7184ac5e633f2b282ae3420ae012103b4e411b81d32a69fb81178a8ea1abaa12f613336923ee920ffbb1b313af1f4d2ffffffff02ab233200000000001976a91418808b2fbd8d2c6d022aed5cd61f0ce6c0a4cbb688ac4741f011000000001976a914f081088a300c80ce36b717a9914ab5ec8a7d283988ac00000000")
	TstSpendingTx, _           = btcutil.NewTxFromBytes(TstSpendingSerializedTx)
	TstSpendingTxBlockHeight   = int32(279143)
	TstSignedTxBlockHash, _    = chainhash.NewHashFromStr("00000000000000017188b968a371bab95aa43522665353b646e41865abae02a4")
	TstSignedTxBlockDetails    = &BlockMeta{
		Block: Block{Hash: *TstSignedTxBlockHash, Height: TstSpendingTxBlockHeight},
		Time:  time.Unix(1389114091, 0),
	}
)

func testDB() (walletdb.DB, func(), error) {
	tmpDir, err := ioutil.TempDir("", "wtxmgr_test")
	if err != nil {
		return nil, func() {}, err
	}
	db, err := walletdb.Create("bdb", filepath.Join(tmpDir, "db"))
	return db, func() { os.RemoveAll(tmpDir) }, err
}

func testStore() (*Store, func(), error) {
	tmpDir, err := ioutil.TempDir("", "wtxmgr_test")
	if err != nil {
		return nil, func() {}, err
	}
	db, err := walletdb.Create("bdb", filepath.Join(tmpDir, "db"))
	if err != nil {
		teardown := func() {
			os.RemoveAll(tmpDir)
		}
		return nil, teardown, err
	}
	teardown := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}
	ns, err := db.Namespace([]byte("txstore"))
	if err != nil {
		return nil, teardown, err
	}
	err = Create(ns)
	if err != nil {
		return nil, teardown, err
	}
	s, err := Open(ns, &chaincfg.TestNet3Params)
	return s, teardown, err
}

func serializeTx(tx *btcutil.Tx) []byte {
	var buf bytes.Buffer
	err := tx.MsgTx().Serialize(&buf)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func TestInsertsCreditsDebitsRollbacks(t *testing.T) {
	t.Parallel()

	// Create a double spend of the received blockchain transaction.
	dupRecvTx, _ := btcutil.NewTxFromBytes(TstRecvSerializedTx)
	// Switch txout amount to 1 BTC.  Transaction store doesn't
	// validate txs, so this is fine for testing a double spend
	// removal.
	TstDupRecvAmount := int64(1e8)
	newDupMsgTx := dupRecvTx.MsgTx()
	newDupMsgTx.TxOut[0].Value = TstDupRecvAmount
	TstDoubleSpendTx := btcutil.NewTx(newDupMsgTx)
	TstDoubleSpendSerializedTx := serializeTx(TstDoubleSpendTx)

	// Create a "signed" (with invalid sigs) tx that spends output 0 of
	// the double spend.
	spendingTx := wire.NewMsgTx()
	spendingTxIn := wire.NewTxIn(wire.NewOutPoint(TstDoubleSpendTx.Hash(), 0), []byte{0, 1, 2, 3, 4})
	spendingTx.AddTxIn(spendingTxIn)
	spendingTxOut1 := wire.NewTxOut(1e7, []byte{5, 6, 7, 8, 9})
	spendingTxOut2 := wire.NewTxOut(9e7, []byte{10, 11, 12, 13, 14})
	spendingTx.AddTxOut(spendingTxOut1)
	spendingTx.AddTxOut(spendingTxOut2)
	TstSpendingTx := btcutil.NewTx(spendingTx)
	TstSpendingSerializedTx := serializeTx(TstSpendingTx)
	var _ = TstSpendingTx

	tests := []struct {
		name     string
		f        func(*Store) (*Store, error)
		bal, unc btcutil.Amount
		unspents map[wire.OutPoint]struct{}
		unmined  map[chainhash.Hash]struct{}
	}{
		{
			name: "new store",
			f: func(s *Store) (*Store, error) {
				return s, nil
			},
			bal:      0,
			unc:      0,
			unspents: map[wire.OutPoint]struct{}{},
			unmined:  map[chainhash.Hash]struct{}{},
		},
		{
			name: "txout insert",
			f: func(s *Store) (*Store, error) {
				rec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(rec, nil)
				if err != nil {
					return nil, err
				}

				err = s.AddCredit(rec, nil, 0, false)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				wire.OutPoint{
					Hash:  *TstRecvTx.Hash(),
					Index: 0,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{
				*TstRecvTx.Hash(): {},
			},
		},
		{
			name: "insert duplicate unconfirmed",
			f: func(s *Store) (*Store, error) {
				rec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(rec, nil)
				if err != nil {
					return nil, err
				}

				err = s.AddCredit(rec, nil, 0, false)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				wire.OutPoint{
					Hash:  *TstRecvTx.Hash(),
					Index: 0,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{
				*TstRecvTx.Hash(): {},
			},
		},
		{
			name: "confirmed txout insert",
			f: func(s *Store) (*Store, error) {
				rec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(rec, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				err = s.AddCredit(rec, TstRecvTxBlockDetails, 0, false)
				return s, err
			},
			bal: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				wire.OutPoint{
					Hash:  *TstRecvTx.Hash(),
					Index: 0,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{},
		},
		{
			name: "insert duplicate confirmed",
			f: func(s *Store) (*Store, error) {
				rec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(rec, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				err = s.AddCredit(rec, TstRecvTxBlockDetails, 0, false)
				return s, err
			},
			bal: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				wire.OutPoint{
					Hash:  *TstRecvTx.Hash(),
					Index: 0,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{},
		},
		{
			name: "rollback confirmed credit",
			f: func(s *Store) (*Store, error) {
				err := s.Rollback(TstRecvTxBlockDetails.Height)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				wire.OutPoint{
					Hash:  *TstRecvTx.Hash(),
					Index: 0,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{
				*TstRecvTx.Hash(): {},
			},
		},
		{
			name: "insert confirmed double spend",
			f: func(s *Store) (*Store, error) {
				rec, err := NewTxRecord(TstDoubleSpendSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(rec, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				err = s.AddCredit(rec, TstRecvTxBlockDetails, 0, false)
				return s, err
			},
			bal: btcutil.Amount(TstDoubleSpendTx.MsgTx().TxOut[0].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				wire.OutPoint{
					Hash:  *TstDoubleSpendTx.Hash(),
					Index: 0,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{},
		},
		{
			name: "insert unconfirmed debit",
			f: func(s *Store) (*Store, error) {
				rec, err := NewTxRecord(TstSpendingSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(rec, nil)
				return s, err
			},
			bal:      0,
			unc:      0,
			unspents: map[wire.OutPoint]struct{}{},
			unmined: map[chainhash.Hash]struct{}{
				*TstSpendingTx.Hash(): {},
			},
		},
		{
			name: "insert unconfirmed debit again",
			f: func(s *Store) (*Store, error) {
				rec, err := NewTxRecord(TstDoubleSpendSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(rec, TstRecvTxBlockDetails)
				return s, err
			},
			bal:      0,
			unc:      0,
			unspents: map[wire.OutPoint]struct{}{},
			unmined: map[chainhash.Hash]struct{}{
				*TstSpendingTx.Hash(): {},
			},
		},
		{
			name: "insert change (index 0)",
			f: func(s *Store) (*Store, error) {
				rec, err := NewTxRecord(TstSpendingSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(rec, nil)
				if err != nil {
					return nil, err
				}

				err = s.AddCredit(rec, nil, 0, true)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				wire.OutPoint{
					Hash:  *TstSpendingTx.Hash(),
					Index: 0,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{
				*TstSpendingTx.Hash(): {},
			},
		},
		{
			name: "insert output back to this own wallet (index 1)",
			f: func(s *Store) (*Store, error) {
				rec, err := NewTxRecord(TstSpendingSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(rec, nil)
				if err != nil {
					return nil, err
				}
				err = s.AddCredit(rec, nil, 1, true)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unspents: map[wire.OutPoint]struct{}{
				wire.OutPoint{
					Hash:  *TstSpendingTx.Hash(),
					Index: 0,
				}: {},
				wire.OutPoint{
					Hash:  *TstSpendingTx.Hash(),
					Index: 1,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{
				*TstSpendingTx.Hash(): {},
			},
		},
		{
			name: "confirm signed tx",
			f: func(s *Store) (*Store, error) {
				rec, err := NewTxRecord(TstSpendingSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(rec, TstSignedTxBlockDetails)
				return s, err
			},
			bal: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				wire.OutPoint{
					Hash:  *TstSpendingTx.Hash(),
					Index: 0,
				}: {},
				wire.OutPoint{
					Hash:  *TstSpendingTx.Hash(),
					Index: 1,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{},
		},
		{
			name: "rollback after spending tx",
			f: func(s *Store) (*Store, error) {
				err := s.Rollback(TstSignedTxBlockDetails.Height + 1)
				return s, err
			},
			bal: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				wire.OutPoint{
					Hash:  *TstSpendingTx.Hash(),
					Index: 0,
				}: {},
				wire.OutPoint{
					Hash:  *TstSpendingTx.Hash(),
					Index: 1,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{},
		},
		{
			name: "rollback spending tx block",
			f: func(s *Store) (*Store, error) {
				err := s.Rollback(TstSignedTxBlockDetails.Height)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unspents: map[wire.OutPoint]struct{}{
				wire.OutPoint{
					Hash:  *TstSpendingTx.Hash(),
					Index: 0,
				}: {},
				wire.OutPoint{
					Hash:  *TstSpendingTx.Hash(),
					Index: 1,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{
				*TstSpendingTx.Hash(): {},
			},
		},
		{
			name: "rollback double spend tx block",
			f: func(s *Store) (*Store, error) {
				err := s.Rollback(TstRecvTxBlockDetails.Height)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstSpendingTx.Hash(), 0): {},
				*wire.NewOutPoint(TstSpendingTx.Hash(), 1): {},
			},
			unmined: map[chainhash.Hash]struct{}{
				*TstDoubleSpendTx.Hash(): {},
				*TstSpendingTx.Hash():    {},
			},
		},
		{
			name: "insert original recv txout",
			f: func(s *Store) (*Store, error) {
				rec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(rec, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}
				err = s.AddCredit(rec, TstRecvTxBlockDetails, 0, false)
				return s, err
			},
			bal: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstRecvTx.Hash(), 0): {},
			},
			unmined: map[chainhash.Hash]struct{}{},
		},
	}

	s, teardown, err := testStore()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		tmpStore, err := test.f(s)
		if err != nil {
			t.Fatalf("%s: got error: %v", test.name, err)
		}
		s = tmpStore
		bal, err := s.Balance(1, TstRecvCurrentHeight)
		if err != nil {
			t.Fatalf("%s: Confirmed Balance failed: %v", test.name, err)
		}
		if bal != test.bal {
			t.Fatalf("%s: balance mismatch: expected: %d, got: %d", test.name, test.bal, bal)
		}
		unc, err := s.Balance(0, TstRecvCurrentHeight)
		if err != nil {
			t.Fatalf("%s: Unconfirmed Balance failed: %v", test.name, err)
		}
		unc -= bal
		if unc != test.unc {
			t.Fatalf("%s: unconfirmed balance mismatch: expected %d, got %d", test.name, test.unc, unc)
		}

		// Check that unspent outputs match expected.
		unspent, err := s.UnspentOutputs()
		if err != nil {
			t.Fatalf("%s: failed to fetch unspent outputs: %v", test.name, err)
		}
		for _, cred := range unspent {
			if _, ok := test.unspents[cred.OutPoint]; !ok {
				t.Errorf("%s: unexpected unspent output: %v", test.name, cred.OutPoint)
			}
			delete(test.unspents, cred.OutPoint)
		}
		if len(test.unspents) != 0 {
			t.Fatalf("%s: missing expected unspent output(s)", test.name)
		}

		// Check that unmined txs match expected.
		unmined, err := s.UnminedTxs()
		if err != nil {
			t.Fatalf("%s: cannot load unmined transactions: %v", test.name, err)
		}
		for _, tx := range unmined {
			txHash := tx.TxHash()
			if _, ok := test.unmined[txHash]; !ok {
				t.Fatalf("%s: unexpected unmined tx: %v", test.name, txHash)
			}
			delete(test.unmined, txHash)
		}
		if len(test.unmined) != 0 {
			t.Fatalf("%s: missing expected unmined tx(s)", test.name)
		}

	}
}

func TestFindingSpentCredits(t *testing.T) {
	t.Parallel()

	s, teardown, err := testStore()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}

	// Insert transaction and credit which will be spent.
	recvRec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	err = s.InsertTx(recvRec, TstRecvTxBlockDetails)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(recvRec, TstRecvTxBlockDetails, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	// Insert confirmed transaction which spends the above credit.
	spendingRec, err := NewTxRecord(TstSpendingSerializedTx, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	err = s.InsertTx(spendingRec, TstSignedTxBlockDetails)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(spendingRec, TstSignedTxBlockDetails, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	bal, err := s.Balance(1, TstSignedTxBlockDetails.Height)
	if err != nil {
		t.Fatal(err)
	}
	expectedBal := btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value)
	if bal != expectedBal {
		t.Fatalf("bad balance: %v != %v", bal, expectedBal)
	}
	unspents, err := s.UnspentOutputs()
	if err != nil {
		t.Fatal(err)
	}
	op := wire.NewOutPoint(TstSpendingTx.Hash(), 0)
	if unspents[0].OutPoint != *op {
		t.Fatal("unspent outpoint doesn't match expected")
	}
	if len(unspents) > 1 {
		t.Fatal("has more than one unspent credit")
	}
}

func newCoinBase(outputValues ...int64) *wire.MsgTx {
	tx := wire.MsgTx{
		TxIn: []*wire.TxIn{
			&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{Index: ^uint32(0)},
			},
		},
	}
	for _, val := range outputValues {
		tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: val})
	}
	return &tx
}

func spendOutput(txHash *chainhash.Hash, index uint32, outputValues ...int64) *wire.MsgTx {
	tx := wire.MsgTx{
		TxIn: []*wire.TxIn{
			&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{Hash: *txHash, Index: index},
			},
		},
	}
	for _, val := range outputValues {
		tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: val})
	}
	return &tx
}

func TestCoinbases(t *testing.T) {
	t.Parallel()

	s, teardown, err := testStore()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}

	b100 := BlockMeta{
		Block: Block{Height: 100},
		Time:  time.Now(),
	}

	cb := newCoinBase(20e8, 10e8, 30e8)
	cbRec, err := NewTxRecordFromMsgTx(cb, b100.Time)
	if err != nil {
		t.Fatal(err)
	}

	// Insert coinbase and mark outputs 0 and 2 as credits.
	err = s.InsertTx(cbRec, &b100)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(cbRec, &b100, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(cbRec, &b100, 2, false)
	if err != nil {
		t.Fatal(err)
	}

	coinbaseMaturity := int32(chaincfg.TestNet3Params.CoinbaseMaturity)

	// Balance should be 0 if the coinbase is immature, 50 BTC at and beyond
	// maturity.
	//
	// Outputs when depth is below maturity are never included, no matter
	// the required number of confirmations.  Matured outputs which have
	// greater depth than minConf are still excluded.
	type balTest struct {
		height  int32
		minConf int32
		bal     btcutil.Amount
	}
	balTests := []balTest{
		// Next block it is still immature
		{
			height:  b100.Height + coinbaseMaturity - 2,
			minConf: 0,
			bal:     0,
		},
		{
			height:  b100.Height + coinbaseMaturity - 2,
			minConf: coinbaseMaturity,
			bal:     0,
		},

		// Next block it matures
		{
			height:  b100.Height + coinbaseMaturity - 1,
			minConf: 0,
			bal:     50e8,
		},
		{
			height:  b100.Height + coinbaseMaturity - 1,
			minConf: 1,
			bal:     50e8,
		},
		{
			height:  b100.Height + coinbaseMaturity - 1,
			minConf: coinbaseMaturity - 1,
			bal:     50e8,
		},
		{
			height:  b100.Height + coinbaseMaturity - 1,
			minConf: coinbaseMaturity,
			bal:     50e8,
		},
		{
			height:  b100.Height + coinbaseMaturity - 1,
			minConf: coinbaseMaturity + 1,
			bal:     0,
		},

		// Matures at this block
		{
			height:  b100.Height + coinbaseMaturity,
			minConf: 0,
			bal:     50e8,
		},
		{
			height:  b100.Height + coinbaseMaturity,
			minConf: 1,
			bal:     50e8,
		},
		{
			height:  b100.Height + coinbaseMaturity,
			minConf: coinbaseMaturity,
			bal:     50e8,
		},
		{
			height:  b100.Height + coinbaseMaturity,
			minConf: coinbaseMaturity + 1,
			bal:     50e8,
		},
		{
			height:  b100.Height + coinbaseMaturity,
			minConf: coinbaseMaturity + 2,
			bal:     0,
		},
	}
	for i, tst := range balTests {
		bal, err := s.Balance(tst.minConf, tst.height)
		if err != nil {
			t.Fatalf("Balance test %d: Store.Balance failed: %v", i, err)
		}
		if bal != tst.bal {
			t.Errorf("Balance test %d: Got %v Expected %v", i, bal, tst.bal)
		}
	}
	if t.Failed() {
		t.Fatal("Failed balance checks after inserting coinbase")
	}

	// Spend an output from the coinbase tx in an unmined transaction when
	// the next block will mature the coinbase.
	spenderATime := time.Now()
	spenderA := spendOutput(&cbRec.Hash, 0, 5e8, 15e8)
	spenderARec, err := NewTxRecordFromMsgTx(spenderA, spenderATime)
	if err != nil {
		t.Fatal(err)
	}
	err = s.InsertTx(spenderARec, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(spenderARec, nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	balTests = []balTest{
		// Next block it matures
		{
			height:  b100.Height + coinbaseMaturity - 1,
			minConf: 0,
			bal:     35e8,
		},
		{
			height:  b100.Height + coinbaseMaturity - 1,
			minConf: 1,
			bal:     30e8,
		},
		{
			height:  b100.Height + coinbaseMaturity - 1,
			minConf: coinbaseMaturity,
			bal:     30e8,
		},
		{
			height:  b100.Height + coinbaseMaturity - 1,
			minConf: coinbaseMaturity + 1,
			bal:     0,
		},

		// Matures at this block
		{
			height:  b100.Height + coinbaseMaturity,
			minConf: 0,
			bal:     35e8,
		},
		{
			height:  b100.Height + coinbaseMaturity,
			minConf: 1,
			bal:     30e8,
		},
		{
			height:  b100.Height + coinbaseMaturity,
			minConf: coinbaseMaturity,
			bal:     30e8,
		},
		{
			height:  b100.Height + coinbaseMaturity,
			minConf: coinbaseMaturity + 1,
			bal:     30e8,
		},
		{
			height:  b100.Height + coinbaseMaturity,
			minConf: coinbaseMaturity + 2,
			bal:     0,
		},
	}
	balTestsBeforeMaturity := balTests
	for i, tst := range balTests {
		bal, err := s.Balance(tst.minConf, tst.height)
		if err != nil {
			t.Fatalf("Balance test %d: Store.Balance failed: %v", i, err)
		}
		if bal != tst.bal {
			t.Errorf("Balance test %d: Got %v Expected %v", i, bal, tst.bal)
		}
	}
	if t.Failed() {
		t.Fatal("Failed balance checks after spending coinbase with unmined transaction")
	}

	// Mine the spending transaction in the block the coinbase matures.
	bMaturity := BlockMeta{
		Block: Block{Height: b100.Height + coinbaseMaturity},
		Time:  time.Now(),
	}
	err = s.InsertTx(spenderARec, &bMaturity)
	if err != nil {
		t.Fatal(err)
	}

	balTests = []balTest{
		// Maturity height
		{
			height:  bMaturity.Height,
			minConf: 0,
			bal:     35e8,
		},
		{
			height:  bMaturity.Height,
			minConf: 1,
			bal:     35e8,
		},
		{
			height:  bMaturity.Height,
			minConf: 2,
			bal:     30e8,
		},
		{
			height:  bMaturity.Height,
			minConf: coinbaseMaturity,
			bal:     30e8,
		},
		{
			height:  bMaturity.Height,
			minConf: coinbaseMaturity + 1,
			bal:     30e8,
		},
		{
			height:  bMaturity.Height,
			minConf: coinbaseMaturity + 2,
			bal:     0,
		},

		// Next block after maturity height
		{
			height:  bMaturity.Height + 1,
			minConf: 0,
			bal:     35e8,
		},
		{
			height:  bMaturity.Height + 1,
			minConf: 2,
			bal:     35e8,
		},
		{
			height:  bMaturity.Height + 1,
			minConf: 3,
			bal:     30e8,
		},
		{
			height:  bMaturity.Height + 1,
			minConf: coinbaseMaturity + 2,
			bal:     30e8,
		},
		{
			height:  bMaturity.Height + 1,
			minConf: coinbaseMaturity + 3,
			bal:     0,
		},
	}
	for i, tst := range balTests {
		bal, err := s.Balance(tst.minConf, tst.height)
		if err != nil {
			t.Fatalf("Balance test %d: Store.Balance failed: %v", i, err)
		}
		if bal != tst.bal {
			t.Errorf("Balance test %d: Got %v Expected %v", i, bal, tst.bal)
		}
	}
	if t.Failed() {
		t.Fatal("Failed balance checks mining coinbase spending transaction")
	}

	// Create another spending transaction which spends the credit from the
	// first spender.  This will be used to test removing the entire
	// conflict chain when the coinbase is later reorged out.
	//
	// Use the same output amount as spender A and mark it as a credit.
	// This will mean the balance tests should report identical results.
	spenderBTime := time.Now()
	spenderB := spendOutput(&spenderARec.Hash, 0, 5e8)
	spenderBRec, err := NewTxRecordFromMsgTx(spenderB, spenderBTime)
	if err != nil {
		t.Fatal(err)
	}
	err = s.InsertTx(spenderBRec, &bMaturity)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(spenderBRec, &bMaturity, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	for i, tst := range balTests {
		bal, err := s.Balance(tst.minConf, tst.height)
		if err != nil {
			t.Fatalf("Balance test %d: Store.Balance failed: %v", i, err)
		}
		if bal != tst.bal {
			t.Errorf("Balance test %d: Got %v Expected %v", i, bal, tst.bal)
		}
	}
	if t.Failed() {
		t.Fatal("Failed balance checks mining second spending transaction")
	}

	// Reorg out the block that matured the coinbase and check balances
	// again.
	err = s.Rollback(bMaturity.Height)
	if err != nil {
		t.Fatal(err)
	}
	balTests = balTestsBeforeMaturity
	for i, tst := range balTests {
		bal, err := s.Balance(tst.minConf, tst.height)
		if err != nil {
			t.Fatalf("Balance test %d: Store.Balance failed: %v", i, err)
		}
		if bal != tst.bal {
			t.Errorf("Balance test %d: Got %v Expected %v", i, bal, tst.bal)
		}
	}
	if t.Failed() {
		t.Fatal("Failed balance checks after reorging maturity block")
	}

	// Reorg out the block which contained the coinbase.  There should be no
	// more transactions in the store (since the previous outputs referenced
	// by the spending tx no longer exist), and the balance will always be
	// zero.
	err = s.Rollback(b100.Height)
	if err != nil {
		t.Fatal(err)
	}
	balTests = []balTest{
		// Current height
		{
			height:  b100.Height - 1,
			minConf: 0,
			bal:     0,
		},
		{
			height:  b100.Height - 1,
			minConf: 1,
			bal:     0,
		},

		// Next height
		{
			height:  b100.Height,
			minConf: 0,
			bal:     0,
		},
		{
			height:  b100.Height,
			minConf: 1,
			bal:     0,
		},
	}
	for i, tst := range balTests {
		bal, err := s.Balance(tst.minConf, tst.height)
		if err != nil {
			t.Fatalf("Balance test %d: Store.Balance failed: %v", i, err)
		}
		if bal != tst.bal {
			t.Errorf("Balance test %d: Got %v Expected %v", i, bal, tst.bal)
		}
	}
	if t.Failed() {
		t.Fatal("Failed balance checks after reorging coinbase block")
	}
	unminedTxs, err := s.UnminedTxs()
	if err != nil {
		t.Fatal(err)
	}
	if len(unminedTxs) != 0 {
		t.Fatalf("Should have no unmined transactions after coinbase reorg, found %d", len(unminedTxs))
	}
}

// Test moving multiple transactions from unmined buckets to the same block.
func TestMoveMultipleToSameBlock(t *testing.T) {
	t.Parallel()

	s, teardown, err := testStore()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}

	b100 := BlockMeta{
		Block: Block{Height: 100},
		Time:  time.Now(),
	}

	cb := newCoinBase(20e8, 30e8)
	cbRec, err := NewTxRecordFromMsgTx(cb, b100.Time)
	if err != nil {
		t.Fatal(err)
	}

	// Insert coinbase and mark both outputs as credits.
	err = s.InsertTx(cbRec, &b100)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(cbRec, &b100, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(cbRec, &b100, 1, false)
	if err != nil {
		t.Fatal(err)
	}

	// Create and insert two unmined transactions which spend both coinbase
	// outputs.
	spenderATime := time.Now()
	spenderA := spendOutput(&cbRec.Hash, 0, 1e8, 2e8, 18e8)
	spenderARec, err := NewTxRecordFromMsgTx(spenderA, spenderATime)
	if err != nil {
		t.Fatal(err)
	}
	err = s.InsertTx(spenderARec, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(spenderARec, nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(spenderARec, nil, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	spenderBTime := time.Now()
	spenderB := spendOutput(&cbRec.Hash, 1, 4e8, 8e8, 18e8)
	spenderBRec, err := NewTxRecordFromMsgTx(spenderB, spenderBTime)
	if err != nil {
		t.Fatal(err)
	}
	err = s.InsertTx(spenderBRec, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(spenderBRec, nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(spenderBRec, nil, 1, false)
	if err != nil {
		t.Fatal(err)
	}

	coinbaseMaturity := int32(chaincfg.TestNet3Params.CoinbaseMaturity)

	// Mine both transactions in the block that matures the coinbase.
	bMaturity := BlockMeta{
		Block: Block{Height: b100.Height + coinbaseMaturity},
		Time:  time.Now(),
	}
	err = s.InsertTx(spenderARec, &bMaturity)
	if err != nil {
		t.Fatal(err)
	}
	err = s.InsertTx(spenderBRec, &bMaturity)
	if err != nil {
		t.Fatal(err)
	}

	// Check that both transactions can be queried at the maturity block.
	detailsA, err := s.UniqueTxDetails(&spenderARec.Hash, &bMaturity.Block)
	if err != nil {
		t.Fatal(err)
	}
	if detailsA == nil {
		t.Fatal("No details found for first spender")
	}
	detailsB, err := s.UniqueTxDetails(&spenderBRec.Hash, &bMaturity.Block)
	if err != nil {
		t.Fatal(err)
	}
	if detailsB == nil {
		t.Fatal("No details found for second spender")
	}

	// Verify that the balance was correctly updated on the block record
	// append and that no unmined transactions remain.
	balTests := []struct {
		height  int32
		minConf int32
		bal     btcutil.Amount
	}{
		// Maturity height
		{
			height:  bMaturity.Height,
			minConf: 0,
			bal:     15e8,
		},
		{
			height:  bMaturity.Height,
			minConf: 1,
			bal:     15e8,
		},
		{
			height:  bMaturity.Height,
			minConf: 2,
			bal:     0,
		},

		// Next block after maturity height
		{
			height:  bMaturity.Height + 1,
			minConf: 0,
			bal:     15e8,
		},
		{
			height:  bMaturity.Height + 1,
			minConf: 2,
			bal:     15e8,
		},
		{
			height:  bMaturity.Height + 1,
			minConf: 3,
			bal:     0,
		},
	}
	for i, tst := range balTests {
		bal, err := s.Balance(tst.minConf, tst.height)
		if err != nil {
			t.Fatalf("Balance test %d: Store.Balance failed: %v", i, err)
		}
		if bal != tst.bal {
			t.Errorf("Balance test %d: Got %v Expected %v", i, bal, tst.bal)
		}
	}
	if t.Failed() {
		t.Fatal("Failed balance checks after moving both coinbase spenders")
	}
	unminedTxs, err := s.UnminedTxs()
	if err != nil {
		t.Fatal(err)
	}
	if len(unminedTxs) != 0 {
		t.Fatalf("Should have no unmined transactions mining both, found %d", len(unminedTxs))
	}
}

// Test the optional-ness of the serialized transaction in a TxRecord.
// NewTxRecord and NewTxRecordFromMsgTx both save the serialized transaction, so
// manually strip it out to test this code path.
func TestInsertUnserializedTx(t *testing.T) {
	t.Parallel()

	s, teardown, err := testStore()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}

	tx := newCoinBase(50e8)
	rec, err := NewTxRecordFromMsgTx(tx, timeNow())
	if err != nil {
		t.Fatal(err)
	}
	b100 := makeBlockMeta(100)
	err = s.InsertTx(stripSerializedTx(rec), &b100)
	if err != nil {
		t.Fatalf("Insert for stripped TxRecord failed: %v", err)
	}

	// Ensure it can be retreived successfully.
	details, err := s.UniqueTxDetails(&rec.Hash, &b100.Block)
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := NewTxRecordFromMsgTx(&details.MsgTx, rec.Received)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.SerializedTx, rec2.SerializedTx) {
		t.Fatal("Serialized txs for coinbase do not match")
	}

	// Now test that path with an unmined transaction.
	tx = spendOutput(&rec.Hash, 0, 50e8)
	rec, err = NewTxRecordFromMsgTx(tx, timeNow())
	if err != nil {
		t.Fatal(err)
	}
	err = s.InsertTx(rec, nil)
	if err != nil {
		t.Fatal(err)
	}
	details, err = s.UniqueTxDetails(&rec.Hash, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec2, err = NewTxRecordFromMsgTx(&details.MsgTx, rec.Received)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.SerializedTx, rec2.SerializedTx) {
		t.Fatal("Serialized txs for coinbase spender do not match")
	}
}
