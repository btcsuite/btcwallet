// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/lightningnetwork/lnd/clock"
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

	// defaultDBTimeout specifies the timeout value when opening the wallet
	// database.
	defaultDBTimeout = 10 * time.Second
)

func testDB() (walletdb.DB, func(), error) {
	tmpDir, err := os.MkdirTemp("", "wtxmgr_test")
	if err != nil {
		return nil, func() {}, err
	}
	db, err := walletdb.Create(
		"bdb", filepath.Join(tmpDir, "db"), true, defaultDBTimeout,
	)
	return db, func() { os.RemoveAll(tmpDir) }, err
}

var namespaceKey = []byte("txstore")

func testStore() (*Store, walletdb.DB, func(), error) {
	tmpDir, err := os.MkdirTemp("", "wtxmgr_test")
	if err != nil {
		return nil, nil, func() {}, err
	}

	db, err := walletdb.Create(
		"bdb", filepath.Join(tmpDir, "db"), true, defaultDBTimeout,
	)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, nil, nil, err
	}

	teardown := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	var s *Store
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(namespaceKey)
		if err != nil {
			return err
		}
		err = Create(ns)
		if err != nil {
			return err
		}
		s, err = Open(ns, &chaincfg.TestNet3Params)
		return err
	})

	return s, db, teardown, err
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
	spendingTx := wire.NewMsgTx(wire.TxVersion)
	spendingTxIn := wire.NewTxIn(wire.NewOutPoint(TstDoubleSpendTx.Hash(), 0), []byte{0, 1, 2, 3, 4}, nil)
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
		f        func(*Store, walletdb.ReadWriteBucket) (*Store, error)
		bal, unc btcutil.Amount
		unspents map[wire.OutPoint]struct{}
		unmined  map[chainhash.Hash]struct{}
	}{
		{
			name: "new store",
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				return s, nil
			},
			bal:      0,
			unc:      0,
			unspents: map[wire.OutPoint]struct{}{},
			unmined:  map[chainhash.Hash]struct{}{},
		},
		{
			name: "txout insert",
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				rec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(ns, rec, nil)
				if err != nil {
					return nil, err
				}

				err = s.AddCredit(ns, rec, nil, 0, false)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				{
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
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				rec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(ns, rec, nil)
				if err != nil {
					return nil, err
				}

				// Check that the duplicate transaction is found.
				if exists, _ := s.InsertTxCheckIfExists(ns, rec, nil); !exists {
					return nil, fmt.Errorf(
						"duplicate transaction was not found as already recorded",
					)
				}

				err = s.AddCredit(ns, rec, nil, 0, false)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				{
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
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				rec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(ns, rec, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				err = s.AddCredit(ns, rec, TstRecvTxBlockDetails, 0, false)
				return s, err
			},
			bal: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				{
					Hash:  *TstRecvTx.Hash(),
					Index: 0,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{},
		},
		{
			name: "insert duplicate confirmed",
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				rec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(ns, rec, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				// Make sure the duplicate transaction is found.
				if exists, _ := s.InsertTxCheckIfExists(ns, rec, TstRecvTxBlockDetails); !exists {
					return nil, fmt.Errorf(
						"duplicate transaction was not found as already recorded",
					)
				}

				err = s.AddCredit(ns, rec, TstRecvTxBlockDetails, 0, false)
				return s, err
			},
			bal: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				{
					Hash:  *TstRecvTx.Hash(),
					Index: 0,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{},
		},
		{
			name: "rollback confirmed credit",
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				err := s.Rollback(ns, TstRecvTxBlockDetails.Height)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				{
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
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				rec, err := NewTxRecord(TstDoubleSpendSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(ns, rec, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				err = s.AddCredit(ns, rec, TstRecvTxBlockDetails, 0, false)
				return s, err
			},
			bal: btcutil.Amount(TstDoubleSpendTx.MsgTx().TxOut[0].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				{
					Hash:  *TstDoubleSpendTx.Hash(),
					Index: 0,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{},
		},
		{
			name: "insert unconfirmed debit",
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				rec, err := NewTxRecord(TstSpendingSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(ns, rec, nil)
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
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				rec, err := NewTxRecord(TstDoubleSpendSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(ns, rec, TstRecvTxBlockDetails)
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
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				rec, err := NewTxRecord(TstSpendingSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(ns, rec, nil)
				if err != nil {
					return nil, err
				}

				err = s.AddCredit(ns, rec, nil, 0, true)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				{
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
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				rec, err := NewTxRecord(TstSpendingSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(ns, rec, nil)
				if err != nil {
					return nil, err
				}
				err = s.AddCredit(ns, rec, nil, 1, true)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unspents: map[wire.OutPoint]struct{}{
				{
					Hash:  *TstSpendingTx.Hash(),
					Index: 0,
				}: {},
				{
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
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				rec, err := NewTxRecord(TstSpendingSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(ns, rec, TstSignedTxBlockDetails)
				return s, err
			},
			bal: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				{
					Hash:  *TstSpendingTx.Hash(),
					Index: 0,
				}: {},
				{
					Hash:  *TstSpendingTx.Hash(),
					Index: 1,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{},
		},
		{
			name: "rollback after spending tx",
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				err := s.Rollback(ns, TstSignedTxBlockDetails.Height+1)
				return s, err
			},
			bal: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				{
					Hash:  *TstSpendingTx.Hash(),
					Index: 0,
				}: {},
				{
					Hash:  *TstSpendingTx.Hash(),
					Index: 1,
				}: {},
			},
			unmined: map[chainhash.Hash]struct{}{},
		},
		{
			name: "rollback spending tx block",
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				err := s.Rollback(ns, TstSignedTxBlockDetails.Height)
				return s, err
			},
			bal: 0,
			unc: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unspents: map[wire.OutPoint]struct{}{
				{
					Hash:  *TstSpendingTx.Hash(),
					Index: 0,
				}: {},
				{
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
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				err := s.Rollback(ns, TstRecvTxBlockDetails.Height)
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
			f: func(s *Store, ns walletdb.ReadWriteBucket) (*Store, error) {
				rec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
				if err != nil {
					return nil, err
				}
				err = s.InsertTx(ns, rec, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}
				err = s.AddCredit(ns, rec, TstRecvTxBlockDetails, 0, false)
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

	s, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	for _, test := range tests {
		err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(namespaceKey)
			tmpStore, err := test.f(s, ns)
			if err != nil {
				t.Fatalf("%s: got error: %v", test.name, err)
			}
			s = tmpStore
			bal, err := s.Balance(ns, 1, TstRecvCurrentHeight)
			if err != nil {
				t.Fatalf("%s: Confirmed Balance failed: %v", test.name, err)
			}
			if bal != test.bal {
				t.Fatalf("%s: balance mismatch: expected: %d, got: %d", test.name, test.bal, bal)
			}
			unc, err := s.Balance(ns, 0, TstRecvCurrentHeight)
			if err != nil {
				t.Fatalf("%s: Unconfirmed Balance failed: %v", test.name, err)
			}
			unc -= bal
			if unc != test.unc {
				t.Fatalf("%s: unconfirmed balance mismatch: expected %d, got %d", test.name, test.unc, unc)
			}

			// Check that unspent outputs match expected.
			unspent, err := s.UnspentOutputs(ns)
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
			unmined, err := s.UnminedTxs(ns)
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
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestFindingSpentCredits(t *testing.T) {
	t.Parallel()

	s, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	dbtx, err := db.BeginReadWriteTx()
	if err != nil {
		t.Fatal(err)
	}
	defer dbtx.Commit()
	ns := dbtx.ReadWriteBucket(namespaceKey)

	// Insert transaction and credit which will be spent.
	recvRec, err := NewTxRecord(TstRecvSerializedTx, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	err = s.InsertTx(ns, recvRec, TstRecvTxBlockDetails)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, recvRec, TstRecvTxBlockDetails, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	// Insert confirmed transaction which spends the above credit.
	spendingRec, err := NewTxRecord(TstSpendingSerializedTx, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	err = s.InsertTx(ns, spendingRec, TstSignedTxBlockDetails)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, spendingRec, TstSignedTxBlockDetails, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	bal, err := s.Balance(ns, 1, TstSignedTxBlockDetails.Height)
	if err != nil {
		t.Fatal(err)
	}
	expectedBal := btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value)
	if bal != expectedBal {
		t.Fatalf("bad balance: %v != %v", bal, expectedBal)
	}
	unspents, err := s.UnspentOutputs(ns)
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
			{
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
			{
				PreviousOutPoint: wire.OutPoint{Hash: *txHash, Index: index},
			},
		},
	}
	for _, val := range outputValues {
		tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: val})
	}
	return &tx
}

func spendOutputs(outputs []wire.OutPoint, outputValues ...int64) *wire.MsgTx {
	tx := &wire.MsgTx{}
	for _, output := range outputs {
		tx.TxIn = append(tx.TxIn, &wire.TxIn{PreviousOutPoint: output})
	}
	for _, value := range outputValues {
		tx.TxOut = append(tx.TxOut, &wire.TxOut{Value: value})
	}

	return tx
}

func TestCoinbases(t *testing.T) {
	t.Parallel()

	s, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	dbtx, err := db.BeginReadWriteTx()
	if err != nil {
		t.Fatal(err)
	}
	defer dbtx.Commit()
	ns := dbtx.ReadWriteBucket(namespaceKey)

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
	err = s.InsertTx(ns, cbRec, &b100)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, cbRec, &b100, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, cbRec, &b100, 2, false)
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
		bal, err := s.Balance(ns, tst.minConf, tst.height)
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
	err = s.InsertTx(ns, spenderARec, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, spenderARec, nil, 0, false)
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
		bal, err := s.Balance(ns, tst.minConf, tst.height)
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
	err = s.InsertTx(ns, spenderARec, &bMaturity)
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
		bal, err := s.Balance(ns, tst.minConf, tst.height)
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
	err = s.InsertTx(ns, spenderBRec, &bMaturity)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, spenderBRec, &bMaturity, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	for i, tst := range balTests {
		bal, err := s.Balance(ns, tst.minConf, tst.height)
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
	err = s.Rollback(ns, bMaturity.Height)
	if err != nil {
		t.Fatal(err)
	}
	balTests = balTestsBeforeMaturity
	for i, tst := range balTests {
		bal, err := s.Balance(ns, tst.minConf, tst.height)
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
	err = s.Rollback(ns, b100.Height)
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
		bal, err := s.Balance(ns, tst.minConf, tst.height)
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
	unminedTxs, err := s.UnminedTxs(ns)
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

	s, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	dbtx, err := db.BeginReadWriteTx()
	if err != nil {
		t.Fatal(err)
	}
	defer dbtx.Commit()
	ns := dbtx.ReadWriteBucket(namespaceKey)

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
	err = s.InsertTx(ns, cbRec, &b100)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, cbRec, &b100, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, cbRec, &b100, 1, false)
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
	err = s.InsertTx(ns, spenderARec, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, spenderARec, nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, spenderARec, nil, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	spenderBTime := time.Now()
	spenderB := spendOutput(&cbRec.Hash, 1, 4e8, 8e8, 18e8)
	spenderBRec, err := NewTxRecordFromMsgTx(spenderB, spenderBTime)
	if err != nil {
		t.Fatal(err)
	}
	err = s.InsertTx(ns, spenderBRec, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, spenderBRec, nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddCredit(ns, spenderBRec, nil, 1, false)
	if err != nil {
		t.Fatal(err)
	}

	coinbaseMaturity := int32(chaincfg.TestNet3Params.CoinbaseMaturity)

	// Mine both transactions in the block that matures the coinbase.
	bMaturity := BlockMeta{
		Block: Block{Height: b100.Height + coinbaseMaturity},
		Time:  time.Now(),
	}
	err = s.InsertTx(ns, spenderARec, &bMaturity)
	if err != nil {
		t.Fatal(err)
	}
	err = s.InsertTx(ns, spenderBRec, &bMaturity)
	if err != nil {
		t.Fatal(err)
	}

	// Check that both transactions can be queried at the maturity block.
	detailsA, err := s.UniqueTxDetails(ns, &spenderARec.Hash, &bMaturity.Block)
	if err != nil {
		t.Fatal(err)
	}
	if detailsA == nil {
		t.Fatal("No details found for first spender")
	}
	detailsB, err := s.UniqueTxDetails(ns, &spenderBRec.Hash, &bMaturity.Block)
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
		bal, err := s.Balance(ns, tst.minConf, tst.height)
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
	unminedTxs, err := s.UnminedTxs(ns)
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

	s, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	dbtx, err := db.BeginReadWriteTx()
	if err != nil {
		t.Fatal(err)
	}
	defer dbtx.Commit()
	ns := dbtx.ReadWriteBucket(namespaceKey)

	tx := newCoinBase(50e8)
	rec, err := NewTxRecordFromMsgTx(tx, timeNow())
	if err != nil {
		t.Fatal(err)
	}
	b100 := makeBlockMeta(100)
	err = s.InsertTx(ns, stripSerializedTx(rec), &b100)
	if err != nil {
		t.Fatalf("Insert for stripped TxRecord failed: %v", err)
	}

	// Ensure it can be retreived successfully.
	details, err := s.UniqueTxDetails(ns, &rec.Hash, &b100.Block)
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
	err = s.InsertTx(ns, rec, nil)
	if err != nil {
		t.Fatal(err)
	}
	details, err = s.UniqueTxDetails(ns, &rec.Hash, nil)
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

// TestRemoveUnminedTx tests that if we add an umined transaction, then we're
// able to remove that unmined transaction later along with any of its
// descendants. Any balance modifications due to the unmined transaction should
// be revered.
func TestRemoveUnminedTx(t *testing.T) {
	t.Parallel()

	store, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	// In order to reproduce real-world scenarios, we'll use a new database
	// transaction for each interaction with the wallet.
	//
	// We'll start off the test by creating a new coinbase output at height
	// 100 and inserting it into the store.
	b100 := &BlockMeta{
		Block: Block{Height: 100},
		Time:  time.Now(),
	}
	initialBalance := int64(1e8)
	cb := newCoinBase(initialBalance)
	cbRec, err := NewTxRecordFromMsgTx(cb, b100.Time)
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, cbRec, b100); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, cbRec, b100, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// Determine the maturity height for the coinbase output created.
	coinbaseMaturity := int32(chaincfg.TestNet3Params.CoinbaseMaturity)
	maturityHeight := b100.Block.Height + coinbaseMaturity

	// checkBalance is a helper function that compares the balance of the
	// store with the expected value. The includeUnconfirmed boolean can be
	// used to include the unconfirmed balance as a part of the total
	// balance.
	checkBalance := func(expectedBalance btcutil.Amount,
		includeUnconfirmed bool) {

		t.Helper()

		minConfs := int32(1)
		if includeUnconfirmed {
			minConfs = 0
		}

		commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
			t.Helper()

			b, err := store.Balance(ns, minConfs, maturityHeight)
			if err != nil {
				t.Fatalf("unable to retrieve balance: %v", err)
			}
			if b != expectedBalance {
				t.Fatalf("expected balance of %d, got %d",
					expectedBalance, b)
			}
		})
	}

	// Since we don't have any unconfirmed transactions within the store,
	// the total balance reflecting confirmed and unconfirmed outputs should
	// match the initial balance.
	checkBalance(btcutil.Amount(initialBalance), false)
	checkBalance(btcutil.Amount(initialBalance), true)

	// Then, we'll create an unconfirmed spend for the coinbase output and
	// insert it into the store.
	b101 := &BlockMeta{
		Block: Block{Height: 201},
		Time:  time.Now(),
	}
	changeAmount := int64(4e7)
	spendTx := spendOutput(&cbRec.Hash, 0, 5e7, changeAmount)
	spendTxRec, err := NewTxRecordFromMsgTx(spendTx, b101.Time)
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, spendTxRec, nil); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, spendTxRec, nil, 1, true)
		if err != nil {
			t.Fatal(err)
		}
	})

	// With the unconfirmed spend inserted into the store, we'll query it
	// for its unconfirmed tranasctions to ensure it was properly added.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		unminedTxs, err := store.UnminedTxs(ns)
		if err != nil {
			t.Fatalf("unable to query for unmined txs: %v", err)
		}
		if len(unminedTxs) != 1 {
			t.Fatalf("expected 1 mined tx, instead got %v",
				len(unminedTxs))
		}
		unminedTxHash := unminedTxs[0].TxHash()
		spendTxHash := spendTx.TxHash()
		if !unminedTxHash.IsEqual(&spendTxHash) {
			t.Fatalf("mismatch tx hashes: expected %v, got %v",
				spendTxHash, unminedTxHash)
		}
	})

	// Now that an unconfirmed spend exists, there should no longer be any
	// confirmed balance. The total balance should now all be unconfirmed
	// and it should match the change amount of the unconfirmed spend
	// tranasction.
	checkBalance(0, false)
	checkBalance(btcutil.Amount(changeAmount), true)

	// Now, we'll remove the unconfirmed spend tranaction from the store.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.RemoveUnminedTx(ns, spendTxRec); err != nil {
			t.Fatal(err)
		}
	})

	// We'll query the store one last time for its unconfirmed transactions
	// to ensure the unconfirmed spend was properly removed above.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		unminedTxs, err := store.UnminedTxs(ns)
		if err != nil {
			t.Fatalf("unable to query for unmined txs: %v", err)
		}
		if len(unminedTxs) != 0 {
			t.Fatalf("expected 0 mined txs, instead got %v",
				len(unminedTxs))
		}
	})

	// Finally, the total balance (including confirmed and unconfirmed)
	// should once again match the initial balance, as the uncofirmed spend
	// has already been removed.
	checkBalance(btcutil.Amount(initialBalance), false)
	checkBalance(btcutil.Amount(initialBalance), true)
}

// TestInsertMempoolTxAlreadyConfirmed ensures that transactions that already
// exist within the store as confirmed cannot be added as unconfirmed.
func TestInsertMempoolTxAlreadyConfirmed(t *testing.T) {
	t.Parallel()

	store, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	// In order to reproduce real-world scenarios, we'll use a new database
	// transaction for each interaction with the wallet.
	//
	// We'll start off the test by creating a new coinbase output at height
	// 100 and inserting it into the store.
	b100 := &BlockMeta{
		Block: Block{Height: 100},
		Time:  time.Now(),
	}
	tx := newCoinBase(1e8)
	txRec, err := NewTxRecordFromMsgTx(tx, b100.Time)
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, txRec, b100); err != nil {
			t.Fatal(err)
		}
	})

	// checkStore is a helper we'll use to ensure the transaction only
	// exists within the store's confirmed bucket.
	checkStore := func() {
		t.Helper()
		commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
			if existsRawUnmined(ns, txRec.Hash[:]) != nil {
				t.Fatalf("expected transaction to not exist " +
					"in unconfirmed bucket")
			}
			_, v := existsTxRecord(ns, &txRec.Hash, &b100.Block)
			if v == nil {
				t.Fatalf("expected transaction to exist in " +
					"confirmed bucket")
			}
		})
	}

	checkStore()

	// Inserting the transaction again as unconfirmed should result in a
	// NOP, i.e., no error should be returned and no disk modifications are
	// needed.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, txRec, nil); err != nil {
			t.Fatal(err)
		}
	})

	checkStore()
}

// TestInsertMempoolTxAfterSpentOutput ensures that transactions that were
// both confirmed and spent cannot be added as unconfirmed.
func TestInsertMempoolTxAfterSpentOutput(t *testing.T) {
	t.Parallel()

	store, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	// First we add a confirmed transaction to the wallet.
	b100 := BlockMeta{
		Block: Block{Height: 100},
		Time:  time.Now(),
	}
	cb := newCoinBase(1e8)
	cbRec, err := NewTxRecordFromMsgTx(cb, b100.Time)
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, cbRec, &b100); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, cbRec, &b100, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// Then create a transaction that spends the previous tx output.
	b101 := BlockMeta{
		Block: Block{Height: 101},
		Time:  time.Now(),
	}
	amt := int64(1e7)
	spend := spendOutput(&cbRec.Hash, 0, amt)
	spendRec, err := NewTxRecordFromMsgTx(spend, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		// We add the spending tx to the wallet as confirmed.
		err := store.InsertTx(ns, spendRec, &b101)
		if err != nil {
			t.Fatal(err)
		}
		err = store.AddCredit(ns, spendRec, &b101, 0, false)
		if err != nil {
			t.Fatal(err)
		}

		// We now adding the original transaction as mempool to simulate
		// a real case where trying to broadcast a tx after it has been
		// confirmed and spent.
		if err := store.InsertTx(ns, cbRec, nil); err != nil {
			t.Fatal(err)
		}
		err = store.AddCredit(ns, cbRec, nil, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// now we check that there no unminedCredit exists for the original tx.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		k := canonicalOutPoint(&cbRec.Hash, 0)
		if existsRawUnminedCredit(ns, k) != nil {
			t.Fatalf("expected output to not exist " +
				"in unmined credit bucket")
		}
	})
}

// TestOutputsAfterRemoveDoubleSpend ensures that when we remove a transaction
// that double spends an existing output within the wallet, it doesn't remove
// any other spending transactions of the same output.
func TestOutputsAfterRemoveDoubleSpend(t *testing.T) {
	t.Parallel()

	store, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	// In order to reproduce real-world scenarios, we'll use a new database
	// transaction for each interaction with the wallet.
	//
	// We'll start off the test by creating a new coinbase output at height
	// 100 and inserting it into the store.
	b100 := BlockMeta{
		Block: Block{Height: 100},
		Time:  time.Now(),
	}
	cb := newCoinBase(1e8)
	cbRec, err := NewTxRecordFromMsgTx(cb, b100.Time)
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, cbRec, &b100); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, cbRec, nil, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// We'll create three spending transactions for the same output and add
	// them to the store.
	const numSpendRecs = 3
	spendRecs := make([]*TxRecord, 0, numSpendRecs)
	for i := 0; i < numSpendRecs; i++ {
		amt := int64((i + 1) * 1e7)
		spend := spendOutput(&cbRec.Hash, 0, amt)
		spendRec, err := NewTxRecordFromMsgTx(spend, time.Now())
		if err != nil {
			t.Fatal(err)
		}

		commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
			err := store.InsertTx(ns, spendRec, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = store.AddCredit(ns, spendRec, nil, 0, false)
			if err != nil {
				t.Fatal(err)
			}
		})

		spendRecs = append(spendRecs, spendRec)
	}

	// checkOutputs is a helper closure we'll use to ensure none of the
	// other outputs from spending transactions have been removed from the
	// store just because we removed one of the spending transactions.
	checkOutputs := func(txs ...*TxRecord) {
		t.Helper()

		ops := make(map[wire.OutPoint]struct{})
		for _, tx := range txs {
			for i := range tx.MsgTx.TxOut {
				ops[wire.OutPoint{
					Hash:  tx.Hash,
					Index: uint32(i),
				}] = struct{}{}
			}
		}

		commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
			t.Helper()

			outputs, err := store.UnspentOutputs(ns)
			if err != nil {
				t.Fatalf("unable to get unspent outputs: %v", err)
			}
			if len(outputs) != len(ops) {
				t.Fatalf("expected %d outputs, got %d", len(ops),
					len(outputs))
			}
			for _, output := range outputs {
				op := output.OutPoint
				if _, ok := ops[op]; !ok {
					t.Fatalf("found unexpected output %v", op)
				}
			}
		})
	}

	// All of the outputs of our spending transactions should exist.
	checkOutputs(spendRecs...)

	// We'll then remove the last transaction we crafted from the store and
	// check our outputs again to ensure they still exist.
	spendToRemove := spendRecs[numSpendRecs-1]
	spendRecs = spendRecs[:numSpendRecs-1]
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.RemoveUnminedTx(ns, spendToRemove); err != nil {
			t.Fatalf("unable to remove unmined transaction: %v", err)
		}
	})

	checkOutputs(spendRecs...)
}

// commitDBTx is a helper function that allows us to perform multiple operations
// on a specific database's bucket as a single atomic operation.
func commitDBTx(t *testing.T, store *Store, db walletdb.DB,
	f func(walletdb.ReadWriteBucket)) {

	t.Helper()

	dbTx, err := db.BeginReadWriteTx()
	if err != nil {
		t.Fatal(err)
	}
	defer dbTx.Commit()

	ns := dbTx.ReadWriteBucket(namespaceKey)

	f(ns)
}

// testInsertDoubleSpendTx is a helper test which double spends an output. The
// boolean parameter indicates whether the first spending transaction should be
// the one confirmed. This test ensures that when a double spend occurs and both
// spending transactions are present in the mempool, if one of them confirms,
// then the remaining conflicting transactions within the mempool should be
// removed from the wallet's store.
func testInsertMempoolDoubleSpendTx(t *testing.T, first bool) {
	store, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	// In order to reproduce real-world scenarios, we'll use a new database
	// transaction for each interaction with the wallet.
	//
	// We'll start off the test by creating a new coinbase output at height
	// 100 and inserting it into the store.
	b100 := BlockMeta{
		Block: Block{Height: 100},
		Time:  time.Now(),
	}
	cb := newCoinBase(1e8)
	cbRec, err := NewTxRecordFromMsgTx(cb, b100.Time)
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, cbRec, &b100); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, cbRec, &b100, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// Then, we'll create two spends from the same coinbase output, in order
	// to replicate a double spend scenario.
	firstSpend := spendOutput(&cbRec.Hash, 0, 5e7, 5e7)
	firstSpendRec, err := NewTxRecordFromMsgTx(firstSpend, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	secondSpend := spendOutput(&cbRec.Hash, 0, 4e7, 6e7)
	secondSpendRec, err := NewTxRecordFromMsgTx(secondSpend, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// We'll insert both of them into the store without confirming them.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, firstSpendRec, nil); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, firstSpendRec, nil, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, secondSpendRec, nil); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, secondSpendRec, nil, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// Ensure that both spends are found within the unconfirmed transactions
	// in the wallet's store.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		unminedTxs, err := store.UnminedTxs(ns)
		if err != nil {
			t.Fatal(err)
		}
		if len(unminedTxs) != 2 {
			t.Fatalf("expected 2 unmined txs, got %v",
				len(unminedTxs))
		}
	})

	// Then, we'll confirm either the first or second spend, depending on
	// the boolean passed, with a height deep enough that allows us to
	// succesfully spend the coinbase output.
	coinbaseMaturity := int32(chaincfg.TestNet3Params.CoinbaseMaturity)
	bMaturity := BlockMeta{
		Block: Block{Height: b100.Height + coinbaseMaturity},
		Time:  time.Now(),
	}

	var confirmedSpendRec *TxRecord
	if first {
		confirmedSpendRec = firstSpendRec
	} else {
		confirmedSpendRec = secondSpendRec
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		err := store.InsertTx(ns, confirmedSpendRec, &bMaturity)
		if err != nil {
			t.Fatal(err)
		}
		err = store.AddCredit(
			ns, confirmedSpendRec, &bMaturity, 0, false,
		)
		if err != nil {
			t.Fatal(err)
		}
	})

	// This should now trigger the store to remove any other pending double
	// spends for this coinbase output, as we've already seen the confirmed
	// one. Therefore, we shouldn't see any other unconfirmed transactions
	// within it. We also ensure that the transaction that confirmed and is
	// now listed as a UTXO within the wallet is the correct one.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		unminedTxs, err := store.UnminedTxs(ns)
		if err != nil {
			t.Fatal(err)
		}
		if len(unminedTxs) != 0 {
			t.Fatalf("expected 0 unmined txs, got %v",
				len(unminedTxs))
		}

		minedTxs, err := store.UnspentOutputs(ns)
		if err != nil {
			t.Fatal(err)
		}
		if len(minedTxs) != 1 {
			t.Fatalf("expected 1 mined tx, got %v", len(minedTxs))
		}
		if !minedTxs[0].Hash.IsEqual(&confirmedSpendRec.Hash) {
			t.Fatalf("expected confirmed tx hash %v, got %v",
				confirmedSpendRec.Hash, minedTxs[0].Hash)
		}
	})
}

// TestInsertMempoolDoubleSpendConfirmedFirstTx ensures that when a double spend
// occurs and both spending transactions are present in the mempool, if the
// first spend seen is confirmed, then the second spend transaction within the
// mempool should be removed from the wallet's store.
func TestInsertMempoolDoubleSpendConfirmedFirstTx(t *testing.T) {
	t.Parallel()
	testInsertMempoolDoubleSpendTx(t, true)
}

// TestInsertMempoolDoubleSpendConfirmedFirstTx ensures that when a double spend
// occurs and both spending transactions are present in the mempool, if the
// second spend seen is confirmed, then the first spend transaction within the
// mempool should be removed from the wallet's store.
func TestInsertMempoolDoubleSpendConfirmSecondTx(t *testing.T) {
	t.Parallel()
	testInsertMempoolDoubleSpendTx(t, false)
}

// TestInsertConfirmedDoubleSpendTx tests that when one or more double spends
// occur and a spending transaction confirms that was not known to the wallet,
// then the unconfirmed double spends within the mempool should be removed from
// the wallet's store.
func TestInsertConfirmedDoubleSpendTx(t *testing.T) {
	t.Parallel()

	store, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	// In order to reproduce real-world scenarios, we'll use a new database
	// transaction for each interaction with the wallet.
	//
	// We'll start off the test by creating a new coinbase output at height
	// 100 and inserting it into the store.
	b100 := BlockMeta{
		Block: Block{Height: 100},
		Time:  time.Now(),
	}
	cb1 := newCoinBase(1e8)
	cbRec1, err := NewTxRecordFromMsgTx(cb1, b100.Time)
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, cbRec1, &b100); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, cbRec1, &b100, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// Then, we'll create three spends from the same coinbase output. The
	// first two will remain unconfirmed, while the last should confirm and
	// remove the remaining unconfirmed from the wallet's store.
	firstSpend1 := spendOutput(&cbRec1.Hash, 0, 5e7)
	firstSpendRec1, err := NewTxRecordFromMsgTx(firstSpend1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, firstSpendRec1, nil); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, firstSpendRec1, nil, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	secondSpend1 := spendOutput(&cbRec1.Hash, 0, 4e7)
	secondSpendRec1, err := NewTxRecordFromMsgTx(secondSpend1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, secondSpendRec1, nil); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, secondSpendRec1, nil, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// We'll also create another output and have one unconfirmed and one
	// confirmed spending transaction also spend it.
	cb2 := newCoinBase(2e8)
	cbRec2, err := NewTxRecordFromMsgTx(cb2, b100.Time)
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, cbRec2, &b100); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, cbRec2, &b100, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	firstSpend2 := spendOutput(&cbRec2.Hash, 0, 5e7)
	firstSpendRec2, err := NewTxRecordFromMsgTx(firstSpend2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, firstSpendRec2, nil); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, firstSpendRec2, nil, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// At this point, we should see all unconfirmed transactions within the
	// store.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		unminedTxs, err := store.UnminedTxs(ns)
		if err != nil {
			t.Fatal(err)
		}
		if len(unminedTxs) != 3 {
			t.Fatalf("expected 3 unmined txs, got %d",
				len(unminedTxs))
		}
	})

	// Then, we'll insert the confirmed spend at a height deep enough that
	// allows us to successfully spend the coinbase outputs.
	coinbaseMaturity := int32(chaincfg.TestNet3Params.CoinbaseMaturity)
	bMaturity := BlockMeta{
		Block: Block{Height: b100.Height + coinbaseMaturity},
		Time:  time.Now(),
	}
	outputsToSpend := []wire.OutPoint{
		{Hash: cbRec1.Hash, Index: 0},
		{Hash: cbRec2.Hash, Index: 0},
	}
	confirmedSpend := spendOutputs(outputsToSpend, 3e7)
	confirmedSpendRec, err := NewTxRecordFromMsgTx(
		confirmedSpend, bMaturity.Time,
	)
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		err := store.InsertTx(ns, confirmedSpendRec, &bMaturity)
		if err != nil {
			t.Fatal(err)
		}
		err = store.AddCredit(
			ns, confirmedSpendRec, &bMaturity, 0, false,
		)
		if err != nil {
			t.Fatal(err)
		}
	})

	// Now that the confirmed spend exists within the store, we should no
	// longer see the unconfirmed spends within it. We also ensure that the
	// transaction that confirmed and is now listed as a UTXO within the
	// wallet is the correct one.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		unminedTxs, err := store.UnminedTxs(ns)
		if err != nil {
			t.Fatal(err)
		}
		if len(unminedTxs) != 0 {
			t.Fatalf("expected 0 unmined txs, got %v",
				len(unminedTxs))
		}

		minedTxs, err := store.UnspentOutputs(ns)
		if err != nil {
			t.Fatal(err)
		}
		if len(minedTxs) != 1 {
			t.Fatalf("expected 1 mined tx, got %v", len(minedTxs))
		}
		if !minedTxs[0].Hash.IsEqual(&confirmedSpendRec.Hash) {
			t.Fatalf("expected confirmed tx hash %v, got %v",
				confirmedSpend, minedTxs[0].Hash)
		}
	})
}

// TestAddDuplicateCreditAfterConfirm aims to test the case where a duplicate
// unconfirmed credit is added to the store after the intial credit has already
// confirmed. This can lead to outputs being duplicated in the store, which can
// lead to creating double spends when querying the wallet's UTXO set.
func TestAddDuplicateCreditAfterConfirm(t *testing.T) {
	t.Parallel()

	store, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	// In order to reproduce real-world scenarios, we'll use a new database
	// transaction for each interaction with the wallet.
	//
	// We'll start off the test by creating a new coinbase output at height
	// 100 and inserting it into the store.
	b100 := &BlockMeta{
		Block: Block{Height: 100},
		Time:  time.Now(),
	}
	cb := newCoinBase(1e8)
	cbRec, err := NewTxRecordFromMsgTx(cb, b100.Time)
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, cbRec, b100); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, cbRec, b100, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// We'll confirm that there is one unspent output in the store, which
	// should be the coinbase output created above.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		minedTxs, err := store.UnspentOutputs(ns)
		if err != nil {
			t.Fatal(err)
		}
		if len(minedTxs) != 1 {
			t.Fatalf("expected 1 mined tx, got %v", len(minedTxs))
		}
		if !minedTxs[0].Hash.IsEqual(&cbRec.Hash) {
			t.Fatalf("expected tx hash %v, got %v", cbRec.Hash,
				minedTxs[0].Hash)
		}
	})

	// Then, we'll create an unconfirmed spend for the coinbase output.
	b101 := &BlockMeta{
		Block: Block{Height: 101},
		Time:  time.Now(),
	}
	spendTx := spendOutput(&cbRec.Hash, 0, 5e7, 4e7)
	spendTxRec, err := NewTxRecordFromMsgTx(spendTx, b101.Time)
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, spendTxRec, nil); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, spendTxRec, nil, 1, true)
		if err != nil {
			t.Fatal(err)
		}
	})

	// Confirm the spending transaction at the next height.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, spendTxRec, b101); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, spendTxRec, b101, 1, true)
		if err != nil {
			t.Fatal(err)
		}
	})

	// We should see one unspent output within the store once again, this
	// time being the change output of the spending transaction.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		minedTxs, err := store.UnspentOutputs(ns)
		if err != nil {
			t.Fatal(err)
		}
		if len(minedTxs) != 1 {
			t.Fatalf("expected 1 mined txs, got %v", len(minedTxs))
		}
		if !minedTxs[0].Hash.IsEqual(&spendTxRec.Hash) {
			t.Fatalf("expected tx hash %v, got %v", spendTxRec.Hash,
				minedTxs[0].Hash)
		}
	})

	// Now, we'll insert the spending transaction once again, this time as
	// unconfirmed. This can happen if the backend happens to forward an
	// unconfirmed chain.RelevantTx notification to the client even after it
	// has confirmed, which results in us adding it to the store once again.
	//
	// TODO(wilmer): ideally this shouldn't happen, so we should identify
	// the real reason for this.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, spendTxRec, nil); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, spendTxRec, nil, 1, true)
		if err != nil {
			t.Fatal(err)
		}
	})

	// Finally, we'll ensure the change output is still the only unspent
	// output within the store.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		minedTxs, err := store.UnspentOutputs(ns)
		if err != nil {
			t.Fatal(err)
		}
		if len(minedTxs) != 1 {
			t.Fatalf("expected 1 mined txs, got %v", len(minedTxs))
		}
		if !minedTxs[0].Hash.IsEqual(&spendTxRec.Hash) {
			t.Fatalf("expected tx hash %v, got %v", spendTxRec.Hash,
				minedTxs[0].Hash)
		}
	})
}

// TestInsertMempoolTxAndConfirm ensures that there aren't any lingering
// unconfirmed records for a transaction that existed within the store as
// unconfirmed before becoming confirmed.
func TestInsertMempoolTxAndConfirm(t *testing.T) {
	t.Parallel()

	store, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	// Create a transaction which we'll insert into the store as
	// unconfirmed.
	tx := newCoinBase(1e8)
	txRec, err := NewTxRecordFromMsgTx(tx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		if err := store.InsertTx(ns, txRec, nil); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, txRec, nil, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// Then, proceed to confirm it.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		block := &BlockMeta{
			Block: Block{Height: 1337},
			Time:  time.Now(),
		}
		if err := store.InsertTx(ns, txRec, block); err != nil {
			t.Fatal(err)
		}
		err := store.AddCredit(ns, txRec, block, 0, false)
		if err != nil {
			t.Fatal(err)
		}
	})

	// We should not see any lingering unconfirmed records for it once it's
	// been confirmed.
	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		for _, input := range tx.TxIn {
			prevOut := input.PreviousOutPoint
			k := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
			if existsRawUnminedInput(ns, k) != nil {
				t.Fatalf("found transaction input %v as "+
					"unconfirmed", prevOut)
			}
		}
		if existsRawUnmined(ns, txRec.Hash[:]) != nil {
			t.Fatal("found transaction as unconfirmed")
		}
		for i := range tx.TxOut {
			k := canonicalOutPoint(&txRec.Hash, uint32(i))
			if existsRawUnminedCredit(ns, k) != nil {
				t.Fatalf("found transaction output %v as "+
					"unconfirmed", i)
			}
		}
	})
}

// TestTxLabel tests reading and writing of transaction labels.
func TestTxLabel(t *testing.T) {
	t.Parallel()

	store, db, teardown, err := testStore()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	// txid is the transaction hash we will use to write and get labels for.
	txid := &chainhash.Hash{1}

	// txidNotFound is distinct from txid, and will not have a label written
	// to disk.
	txidNotFound := &chainhash.Hash{2}

	// getBucket gets the top level bucket, and fails the test if it is
	// not found.
	getBucket := func(tx walletdb.ReadWriteTx) walletdb.ReadWriteBucket {
		testBucket := tx.ReadWriteBucket(namespaceKey)
		if testBucket == nil {
			t.Fatalf("could not get bucket: %v", err)
		}

		return testBucket
	}

	// tryPutLabel attempts to write a label to disk.
	tryPutLabel := func(label string) error {
		return walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			// Try to write the label to disk.
			return store.PutTxLabel(getBucket(tx), *txid, label)
		})
	}

	// tryReadLabel attempts to retrieve a label for a given txid.
	tryReadLabel := func(labelTx chainhash.Hash) (string, error) {
		var label string

		err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
			var err error
			label, err = FetchTxLabel(getBucket(tx), labelTx)
			return err
		})

		return label, err
	}

	// First, try to lookup a label when the labels bucket does not exist
	// yet.
	_, err = tryReadLabel(*txid)
	if err != ErrNoLabelBucket {
		t.Fatalf("expected: %v, got: %v", ErrNoLabelBucket, err)
	}

	// Now try to write an empty label, which should fail.
	err = tryPutLabel("")
	if err != ErrEmptyLabel {
		t.Fatalf("expected: %v, got: %v", ErrEmptyLabel, err)
	}

	// Create a label which exceeds the length limit.
	longLabel := make([]byte, TxLabelLimit+1)
	err = tryPutLabel(string(longLabel))
	if err != ErrLabelTooLong {
		t.Fatalf("expected: %v, got: %v", ErrLabelTooLong, err)
	}

	// Write an acceptable length label to disk, this should succeed.
	testLabel := "test label"
	err = tryPutLabel(testLabel)
	if err != nil {
		t.Fatalf("expected: no error, got: %v", err)
	}

	diskLabel, err := tryReadLabel(*txid)
	if err != nil {
		t.Fatalf("expected: no error, got: %v", err)
	}
	if diskLabel != testLabel {
		t.Fatalf("expected: %v, got: %v", testLabel, diskLabel)
	}

	// Finally, try to read a label for a transaction which does not have
	// one.
	_, err = tryReadLabel(*txidNotFound)
	if err != ErrTxLabelNotFound {
		t.Fatalf("expected: %v, got: %v", ErrTxLabelNotFound, err)
	}
}

func assertBalance(t *testing.T, s *Store, ns walletdb.ReadWriteBucket,
	confirmed bool, blockHeight int32, exp btcutil.Amount) {

	t.Helper()

	minConf := int32(0)
	if confirmed {
		minConf = 1
	}
	balance, err := s.Balance(ns, minConf, blockHeight)
	if err != nil {
		t.Fatal(err)
	}
	if balance != exp {
		t.Fatalf("expected balance %v, got %v", exp, balance)
	}
}

func assertUtxos(t *testing.T, s *Store, ns walletdb.ReadWriteBucket,
	exp []wire.OutPoint) {

	t.Helper()

	utxos, err := s.UnspentOutputs(ns)
	if err != nil {
		t.Fatal(err)
	}
	for _, expUtxo := range exp {
		found := false
		for _, utxo := range utxos {
			if expUtxo == utxo.OutPoint {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected utxo %v", expUtxo)
		}
	}
}

func assertLocked(t *testing.T, ns walletdb.ReadWriteBucket, op wire.OutPoint,
	timeNow time.Time, exp bool) {

	t.Helper()

	_, _, locked := isLockedOutput(ns, op, timeNow)
	if locked && locked != exp {
		t.Fatalf("expected locked output %v", op)
	}
	if !locked && locked != exp {
		t.Fatalf("unexpected locked output %v", op)
	}
}

func assertOutputLocksExist(t *testing.T, s *Store, ns walletdb.ReadBucket,
	exp ...wire.OutPoint) {

	t.Helper()

	outputs, err := s.ListLockedOutputs(ns)
	if err != nil {
		t.Fatal(err)
	}

	if len(outputs) != len(exp) {
		t.Fatalf("expected to find %v locked output(s), found %v",
			len(exp), len(outputs))
	}

	for _, expOp := range exp {
		exists := false
		for _, found := range outputs {
			if expOp == found.Outpoint {
				exists = true
				break
			}
		}
		if !exists {
			t.Fatalf("expected output lock for %v to exist", expOp)
		}
	}
}

func lock(t *testing.T, s *Store, ns walletdb.ReadWriteBucket,
	id LockID, op wire.OutPoint, exp error) time.Time {

	t.Helper()

	expiry, err := s.LockOutput(ns, id, op, 10*time.Minute)
	if err != exp {
		t.Fatalf("expected err %q, got %q", exp, err)
	}
	if exp != nil && exp != ErrOutputAlreadyLocked {
		assertLocked(t, ns, op, s.clock.Now(), false)
	} else {
		assertLocked(t, ns, op, s.clock.Now(), true)
	}
	return expiry
}

func unlock(t *testing.T, s *Store, ns walletdb.ReadWriteBucket,
	id LockID, op wire.OutPoint, exp error) {

	t.Helper()

	if err := s.UnlockOutput(ns, id, op); err != exp {
		t.Fatalf("expected err %q, got %q", exp, err)
	}
	if exp != nil {
		assertLocked(t, ns, op, s.clock.Now(), true)
	} else {
		assertLocked(t, ns, op, s.clock.Now(), false)
	}
}

func insertUnconfirmedCredit(t *testing.T, store *Store, db walletdb.DB,
	tx *wire.MsgTx, idx uint32) {

	t.Helper()
	insertConfirmedCredit(t, store, db, tx, idx, nil)
}

func insertConfirmedCredit(t *testing.T, store *Store, db walletdb.DB,
	tx *wire.MsgTx, idx uint32, block *BlockMeta) {

	t.Helper()

	commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
		rec, err := NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.InsertTx(ns, rec, block); err != nil {
			t.Fatal(err)
		}
		if err := store.AddCredit(ns, rec, block, idx, false); err != nil {
			t.Fatal(err)
		}
	})
}

// TestOutputLocks aims to test all cases revolving output locks, ensuring they
// are and aren't eligible for coin selection after certain operations.
func TestOutputLocks(t *testing.T) {
	t.Parallel()

	// Define a series of constants we'll use throughout our tests.
	block := &BlockMeta{
		Block: Block{
			Hash:   chainhash.Hash{1, 3, 3, 7},
			Height: 1337,
		},
		Time: time.Now(),
	}

	// Create a coinbase transaction with two outputs, which we'll spend.
	coinbase := newCoinBase(
		btcutil.SatoshiPerBitcoin, btcutil.SatoshiPerBitcoin*2,
	)
	coinbaseHash := coinbase.TxHash()

	// One of the spends will be unconfirmed.
	const unconfirmedBalance = btcutil.SatoshiPerBitcoin / 2
	unconfirmedTx := spendOutput(&coinbaseHash, 0, unconfirmedBalance)
	unconfirmedOutPoint := wire.OutPoint{
		Hash:  unconfirmedTx.TxHash(),
		Index: 0,
	}

	// The other will be confirmed.
	const confirmedBalance = btcutil.SatoshiPerBitcoin
	confirmedTx := spendOutput(&coinbaseHash, 1, confirmedBalance)
	confirmedOutPoint := wire.OutPoint{
		Hash:  confirmedTx.TxHash(),
		Index: 0,
	}

	const balance = unconfirmedBalance + confirmedBalance

	testCases := []struct {
		name string
		run  func(*testing.T, *Store, walletdb.ReadWriteBucket)
	}{
		{
			// Asserts that we cannot lock unknown outputs to the
			// store.
			name: "unknown output",
			run: func(t *testing.T, s *Store, ns walletdb.ReadWriteBucket) {
				lockID := LockID{1}
				op := wire.OutPoint{Index: 1}
				_ = lock(t, s, ns, lockID, op, ErrUnknownOutput)
			},
		},
		{
			// Asserts that we cannot lock outputs that have already
			// been locked to someone else.
			name: "already locked output",
			run: func(t *testing.T, s *Store, ns walletdb.ReadWriteBucket) {
				lockID1 := LockID{1}
				lockID2 := LockID{2}

				_ = lock(
					t, s, ns, lockID1, unconfirmedOutPoint,
					nil,
				)
				_ = lock(
					t, s, ns, lockID2, unconfirmedOutPoint,
					ErrOutputAlreadyLocked,
				)

				_ = lock(
					t, s, ns, lockID1, confirmedOutPoint,
					nil,
				)
				_ = lock(
					t, s, ns, lockID2, confirmedOutPoint,
					ErrOutputAlreadyLocked,
				)
			},
		},
		{
			// Asserts that only the ID which locked at output can
			// manually unlock it.
			name: "unlock output",
			run: func(t *testing.T, s *Store, ns walletdb.ReadWriteBucket) {
				lockID1 := LockID{1}
				lockID2 := LockID{2}

				_ = lock(t, s, ns, lockID1, confirmedOutPoint, nil)
				unlock(
					t, s, ns, lockID2, confirmedOutPoint,
					ErrOutputUnlockNotAllowed,
				)
				unlock(t, s, ns, lockID1, confirmedOutPoint, nil)
			},
		},
		{
			// Asserts that locking an output that's already locked
			// with the correct ID results in an extension of the
			// lock.
			name: "extend locked output lease",
			run: func(t *testing.T, s *Store, ns walletdb.ReadWriteBucket) {
				// Lock the output and set the clock time a
				// minute before the expiration. It should
				// remain locked.
				lockID := LockID{1}
				expiry := lock(
					t, s, ns, lockID, confirmedOutPoint, nil,
				)
				s.clock.(*clock.TestClock).SetTime(
					expiry.Add(-time.Minute),
				)
				assertLocked(
					t, ns, confirmedOutPoint, s.clock.Now(),
					true,
				)

				// Lock it once again, extending its expiration,
				// and set the clock time a second before the
				// expiration. It should remain locked.
				s.clock.(*clock.TestClock).SetTime(
					expiry.Add(-time.Minute),
				)
				newExpiry := lock(
					t, s, ns, lockID, confirmedOutPoint, nil,
				)
				if !newExpiry.After(expiry) {
					t.Fatal("expected output lock " +
						"duration to be renewed")
				}
				s.clock.(*clock.TestClock).SetTime(
					newExpiry.Add(-time.Second),
				)
				assertLocked(
					t, ns, confirmedOutPoint, s.clock.Now(),
					true,
				)

				// Set the clock time to the new expiration, it
				// should now be unlocked.
				s.clock.(*clock.TestClock).SetTime(newExpiry)
				assertLocked(
					t, ns, confirmedOutPoint, s.clock.Now(),
					false,
				)
			},
		},
		{
			// Asserts that balances are reflected properly after
			// locking confirmed and unconfirmed outputs.
			name: "balance after locked outputs",
			run: func(t *testing.T, s *Store, ns walletdb.ReadWriteBucket) {
				// We should see our full balance before locking
				// any outputs.
				assertBalance(
					t, s, ns, false, block.Height, balance,
				)

				// Lock all of our outputs. Our balance should
				// be 0.
				lockID := LockID{1}
				_ = lock(
					t, s, ns, lockID, unconfirmedOutPoint, nil,
				)
				expiry := lock(
					t, s, ns, lockID, confirmedOutPoint, nil,
				)
				assertBalance(t, s, ns, false, block.Height, 0)

				// Wait for the output locks to expire, causing
				// our full balance to return .
				s.clock.(*clock.TestClock).SetTime(expiry)
				assertBalance(
					t, s, ns, false, block.Height, balance,
				)
			},
		},
		{
			// Asserts that the available utxos are reflected
			// properly after locking confirmed and unconfirmed
			// outputs.
			name: "utxos after locked outputs",
			run: func(t *testing.T, s *Store, ns walletdb.ReadWriteBucket) {
				// We should see all of our utxos before locking
				// any.
				assertUtxos(t, s, ns, []wire.OutPoint{
					unconfirmedOutPoint,
					confirmedOutPoint,
				})

				// Lock the unconfirmed utxo, we should now only
				// see the confirmed.
				lockID := LockID{1}
				_ = lock(t, s, ns, lockID, unconfirmedOutPoint, nil)
				assertUtxos(t, s, ns, []wire.OutPoint{
					confirmedOutPoint,
				})

				// Now lock the confirmed utxo, we should no
				// longer see any utxos available.
				expiry := lock(
					t, s, ns, lockID, confirmedOutPoint, nil,
				)
				assertUtxos(t, s, ns, nil)

				// Wait for the output locks to expire for the
				// utxos to become available once again.
				s.clock.(*clock.TestClock).SetTime(expiry)
				assertUtxos(t, s, ns, []wire.OutPoint{
					unconfirmedOutPoint,
					confirmedOutPoint,
				})
			},
		},
		{
			// Asserts that output locks are removed for outputs
			// which have had a confirmed spend, ensuring the
			// database doesn't store stale data.
			name: "clear locked outputs after confirmed spend",
			run: func(t *testing.T, s *Store, ns walletdb.ReadWriteBucket) {
				// Lock an output.
				lockID := LockID{1}
				lock(t, s, ns, lockID, confirmedOutPoint, nil)

				// Create a spend and add it to the store as
				// confirmed.
				txHash := confirmedTx.TxHash()
				spendTx := spendOutput(&txHash, 0, 500)
				spendRec, err := NewTxRecordFromMsgTx(
					spendTx, time.Now(),
				)
				if err != nil {
					t.Fatal(err)
				}
				err = s.InsertTx(ns, spendRec, block)
				if err != nil {
					t.Fatal(err)
				}

				// The output should no longer be locked.
				assertLocked(
					t, ns, confirmedOutPoint, s.clock.Now(),
					false,
				)
			},
		},
		{
			// Assert that deleting expired locked outputs works as
			// intended.
			name: "delete expired locked outputs",
			run: func(t *testing.T, s *Store, ns walletdb.ReadWriteBucket) {
				// Lock an output.
				lockID := LockID{1}
				expiry := lock(
					t, s, ns, lockID, confirmedOutPoint, nil,
				)

				// We should expect to find it if we iterate
				// over the locked outputs bucket.
				assertOutputLocksExist(t, s, ns, confirmedOutPoint)

				// Delete all expired locked outputs. Since the
				// lock hasn't expired yet, it should still
				// exist.
				err := s.DeleteExpiredLockedOutputs(ns)
				if err != nil {
					t.Fatalf("unable to delete expired "+
						"locked outputs: %v", err)
				}
				assertOutputLocksExist(t, s, ns, confirmedOutPoint)

				// Let the output lock expired.
				s.clock.(*clock.TestClock).SetTime(expiry)

				// Lock should not longer be listed.
				assertOutputLocksExist(t, s, ns)

				// But the lock should still exist and active
				// when time is turned back.
				assertLocked(
					t, ns, confirmedOutPoint, time.Time{},
					true,
				)

				// Delete all expired locked outputs. We should
				// no longer see any locked outputs.
				err = s.DeleteExpiredLockedOutputs(ns)
				if err != nil {
					t.Fatalf("unable to delete expired "+
						"locked outputs: %v", err)
				}
				assertOutputLocksExist(t, s, ns)
				assertLocked(
					t, ns, confirmedOutPoint, time.Time{},
					false,
				)
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			store, db, teardown, err := testStore()
			if err != nil {
				t.Fatal(err)
			}
			defer teardown()

			// Replace the store's default clock with a mock one in
			// order to simulate a real clock and speed up our
			// tests.
			store.clock = clock.NewTestClock(time.Time{})

			// Add the spends we created above to the store.
			insertConfirmedCredit(t, store, db, confirmedTx, 0, block)
			insertUnconfirmedCredit(t, store, db, unconfirmedTx, 0)

			// Run the test!
			commitDBTx(t, store, db, func(ns walletdb.ReadWriteBucket) {
				testCase.run(t, store, ns)
			})
		})
	}
}
