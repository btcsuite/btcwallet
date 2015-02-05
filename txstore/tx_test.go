// Copyright (c) 2013, 2014 Conformal Systems LLC <info@conformal.com>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package txstore_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcnet"
	"github.com/btcsuite/btcutil"
	. "github.com/btcsuite/btcwallet/txstore"
)

// Received transaction output for mainnet outpoint
// 61d3696de4c888730cbe06b0ad8ecb6d72d6108e893895aa9bc067bd7eba3fad:0
var (
	TstRecvSerializedTx, _          = hex.DecodeString("010000000114d9ff358894c486b4ae11c2a8cf7851b1df64c53d2e511278eff17c22fb7373000000008c493046022100995447baec31ee9f6d4ec0e05cb2a44f6b817a99d5f6de167d1c75354a946410022100c9ffc23b64d770b0e01e7ff4d25fbc2f1ca8091053078a247905c39fce3760b601410458b8e267add3c1e374cf40f1de02b59213a82e1d84c2b94096e22e2f09387009c96debe1d0bcb2356ffdcf65d2a83d4b34e72c62eccd8490dbf2110167783b2bffffffff0280969800000000001976a914479ed307831d0ac19ebc5f63de7d5f1a430ddb9d88ac38bfaa00000000001976a914dadf9e3484f28b385ddeaa6c575c0c0d18e9788a88ac00000000")
	TstRecvTx, _                    = btcutil.NewTxFromBytes(TstRecvSerializedTx)
	TstRecvTxSpendingTxBlockHash, _ = wire.NewShaHashFromStr("00000000000000017188b968a371bab95aa43522665353b646e41865abae02a4")
	TstRecvAmt                      = int64(10000000)
	TstRecvIndex                    = 684
	TstRecvTxBlockDetails           = &Block{
		Height: 276425,
		Hash:   *TstRecvTxSpendingTxBlockHash,
		Time:   time.Unix(1387737310, 0),
	}

	TstRecvCurrentHeight = int32(284498) // mainnet blockchain height at time of writing
	TstRecvTxOutConfirms = 8074          // hardcoded number of confirmations given the above block height

	TstSpendingSerializedTx, _ = hex.DecodeString("0100000003ad3fba7ebd67c09baa9538898e10d6726dcb8eadb006be0c7388c8e46d69d361000000006b4830450220702c4fbde5532575fed44f8d6e8c3432a2a9bd8cff2f966c3a79b2245a7c88db02210095d6505a57e350720cb52b89a9b56243c15ddfcea0596aedc1ba55d9fb7d5aa0012103cccb5c48a699d3efcca6dae277fee6b82e0229ed754b742659c3acdfed2651f9ffffffffdbd36173f5610e34de5c00ed092174603761595d90190f790e79cda3e5b45bc2010000006b483045022000fa20735e5875e64d05bed43d81b867f3bd8745008d3ff4331ef1617eac7c44022100ad82261fc57faac67fc482a37b6bf18158da0971e300abf5fe2f9fd39e107f58012102d4e1caf3e022757512c204bf09ff56a9981df483aba3c74bb60d3612077c9206ffffffff65536c9d964b6f89b8ef17e83c6666641bc495cb27bab60052f76cd4556ccd0d040000006a473044022068e3886e0299ffa69a1c3ee40f8b6700f5f6d463a9cf9dbf22c055a131fc4abc02202b58957fe19ff1be7a84c458d08016c53fbddec7184ac5e633f2b282ae3420ae012103b4e411b81d32a69fb81178a8ea1abaa12f613336923ee920ffbb1b313af1f4d2ffffffff02ab233200000000001976a91418808b2fbd8d2c6d022aed5cd61f0ce6c0a4cbb688ac4741f011000000001976a914f081088a300c80ce36b717a9914ab5ec8a7d283988ac00000000")
	TstSpendingTx, _           = btcutil.NewTxFromBytes(TstSpendingSerializedTx)
	TstSpendingTxBlockHeight   = int32(279143)
	TstSignedTxBlockHash, _    = wire.NewShaHashFromStr("00000000000000017188b968a371bab95aa43522665353b646e41865abae02a4")
	TstSignedTxIndex           = 123
	TstSignedTxBlockDetails    = &Block{
		Height: TstSpendingTxBlockHeight,
		Hash:   *TstSignedTxBlockHash,
		Time:   time.Unix(1389114091, 0),
	}
)

func TestInsertsCreditsDebitsRollbacks(t *testing.T) {
	// Create a double spend of the received blockchain transaction.
	dupRecvTx, _ := btcutil.NewTxFromBytes(TstRecvSerializedTx)
	// Switch txout amount to 1 BTC.  Transaction store doesn't
	// validate txs, so this is fine for testing a double spend
	// removal.
	TstDupRecvAmount := int64(1e8)
	newDupMsgTx := dupRecvTx.MsgTx()
	newDupMsgTx.TxOut[0].Value = TstDupRecvAmount
	TstDoubleSpendTx := btcutil.NewTx(newDupMsgTx)

	// Create a "signed" (with invalid sigs) tx that spends output 0 of
	// the double spend.
	spendingTx := wire.NewMsgTx()
	spendingTxIn := wire.NewTxIn(wire.NewOutPoint(TstDoubleSpendTx.Sha(), 0), []byte{0, 1, 2, 3, 4})
	spendingTx.AddTxIn(spendingTxIn)
	spendingTxOut1 := wire.NewTxOut(1e7, []byte{5, 6, 7, 8, 9})
	spendingTxOut2 := wire.NewTxOut(9e7, []byte{10, 11, 12, 13, 14})
	spendingTx.AddTxOut(spendingTxOut1)
	spendingTx.AddTxOut(spendingTxOut2)
	TstSpendingTx := btcutil.NewTx(spendingTx)
	var _ = TstSpendingTx

	tests := []struct {
		name     string
		f        func(*Store) (*Store, error)
		bal, unc btcutil.Amount
		unspents map[wire.OutPoint]struct{}
		unmined  map[wire.ShaHash]struct{}
	}{
		{
			name: "new store",
			f: func(_ *Store) (*Store, error) {
				return New("/tmp/tx.bin"), nil
			},
			bal:      0,
			unc:      0,
			unspents: map[wire.OutPoint]struct{}{},
			unmined:  map[wire.ShaHash]struct{}{},
		},
		{
			name: "txout insert",
			f: func(s *Store) (*Store, error) {
				r, err := s.InsertTx(TstRecvTx, nil)
				if err != nil {
					return nil, err
				}

				_, err = r.AddCredit(0, false)
				if err != nil {
					return nil, err
				}
				// Verify that we can create the JSON output without any
				// errors.
				_, err = r.ToJSON("", 100, &btcnet.MainNetParams)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: 0,
			unc: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstRecvTx.Sha(), 0): {},
			},
			unmined: map[wire.ShaHash]struct{}{},
		},
		{
			name: "insert duplicate unconfirmed",
			f: func(s *Store) (*Store, error) {
				r, err := s.InsertTx(TstRecvTx, nil)
				if err != nil {
					return nil, err
				}

				_, err = r.AddCredit(0, false)
				if err != nil {
					return nil, err
				}

				_, err = r.ToJSON("", 100, &btcnet.MainNetParams)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: 0,
			unc: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstRecvTx.Sha(), 0): {},
			},
			unmined: map[wire.ShaHash]struct{}{},
		},
		{
			name: "confirmed txout insert",
			f: func(s *Store) (*Store, error) {
				TstRecvTx.SetIndex(TstRecvIndex)
				r, err := s.InsertTx(TstRecvTx, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				_, err = r.AddCredit(0, false)
				if err != nil {
					return nil, err
				}

				_, err = r.ToJSON("", 100, &btcnet.MainNetParams)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstRecvTx.Sha(), 0): {},
			},
			unmined: map[wire.ShaHash]struct{}{},
		},
		{
			name: "insert duplicate confirmed",
			f: func(s *Store) (*Store, error) {
				TstRecvTx.SetIndex(TstRecvIndex)
				r, err := s.InsertTx(TstRecvTx, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				_, err = r.AddCredit(0, false)
				if err != nil {
					return nil, err
				}

				_, err = r.ToJSON("", 100, &btcnet.MainNetParams)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstRecvTx.Sha(), 0): {},
			},
			unmined: map[wire.ShaHash]struct{}{},
		},
		{
			name: "rollback confirmed credit",
			f: func(s *Store) (*Store, error) {
				err := s.Rollback(TstRecvTxBlockDetails.Height)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: 0,
			unc: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstRecvTx.Sha(), 0): {},
			},
			unmined: map[wire.ShaHash]struct{}{},
		},
		{
			name: "insert confirmed double spend",
			f: func(s *Store) (*Store, error) {
				TstDoubleSpendTx.SetIndex(TstRecvIndex)
				r, err := s.InsertTx(TstDoubleSpendTx, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				_, err = r.AddCredit(0, false)
				if err != nil {
					return nil, err
				}

				_, err = r.ToJSON("", 100, &btcnet.MainNetParams)

				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: btcutil.Amount(TstDoubleSpendTx.MsgTx().TxOut[0].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstDoubleSpendTx.Sha(), 0): {},
			},
			unmined: map[wire.ShaHash]struct{}{},
		},
		{
			name: "insert unconfirmed debit",
			f: func(s *Store) (*Store, error) {
				_, err := s.InsertTx(TstDoubleSpendTx, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				r, err := s.InsertTx(TstSpendingTx, nil)
				if err != nil {
					return nil, err
				}

				_, err = r.AddDebits()
				if err != nil {
					return nil, err
				}

				_, err = r.ToJSON("", 100, &btcnet.MainNetParams)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal:      0,
			unc:      0,
			unspents: map[wire.OutPoint]struct{}{},
			unmined: map[wire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): {},
			},
		},
		{
			name: "insert unconfirmed debit again",
			f: func(s *Store) (*Store, error) {
				_, err := s.InsertTx(TstDoubleSpendTx, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				r, err := s.InsertTx(TstSpendingTx, nil)
				if err != nil {
					return nil, err
				}

				_, err = r.AddDebits()
				if err != nil {
					return nil, err
				}

				_, err = r.ToJSON("", 100, &btcnet.MainNetParams)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal:      0,
			unc:      0,
			unspents: map[wire.OutPoint]struct{}{},
			unmined: map[wire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): {},
			},
		},
		{
			name: "insert change (index 0)",
			f: func(s *Store) (*Store, error) {
				r, err := s.InsertTx(TstSpendingTx, nil)
				if err != nil {
					return nil, err
				}

				_, err = r.AddCredit(0, true)
				if err != nil {
					return nil, err
				}

				_, err = r.ToJSON("", 100, &btcnet.MainNetParams)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: 0,
			unc: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value),
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstSpendingTx.Sha(), 0): {},
			},
			unmined: map[wire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): {},
			},
		},
		{
			name: "insert output back to this own wallet (index 1)",
			f: func(s *Store) (*Store, error) {
				r, err := s.InsertTx(TstSpendingTx, nil)
				if err != nil {
					return nil, err
				}

				_, err = r.AddCredit(1, true)
				if err != nil {
					return nil, err
				}

				_, err = r.ToJSON("", 100, &btcnet.MainNetParams)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: 0,
			unc: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstSpendingTx.Sha(), 0): {},
				*wire.NewOutPoint(TstSpendingTx.Sha(), 1): {},
			},
			unmined: map[wire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): {},
			},
		},
		{
			name: "confirm signed tx",
			f: func(s *Store) (*Store, error) {
				TstSpendingTx.SetIndex(TstSignedTxIndex)
				r, err := s.InsertTx(TstSpendingTx, TstSignedTxBlockDetails)
				if err != nil {
					return nil, err
				}

				_, err = r.ToJSON("", 100, &btcnet.MainNetParams)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstSpendingTx.Sha(), 0): {},
				*wire.NewOutPoint(TstSpendingTx.Sha(), 1): {},
			},
			unmined: map[wire.ShaHash]struct{}{},
		},
		{
			name: "rollback after spending tx",
			f: func(s *Store) (*Store, error) {
				err := s.Rollback(TstSignedTxBlockDetails.Height + 1)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstSpendingTx.Sha(), 0): {},
				*wire.NewOutPoint(TstSpendingTx.Sha(), 1): {},
			},
			unmined: map[wire.ShaHash]struct{}{},
		},
		{
			name: "rollback spending tx block",
			f: func(s *Store) (*Store, error) {
				err := s.Rollback(TstSignedTxBlockDetails.Height)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: 0,
			unc: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstSpendingTx.Sha(), 0): {},
				*wire.NewOutPoint(TstSpendingTx.Sha(), 1): {},
			},
			unmined: map[wire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): {},
			},
		},
		{
			name: "rollback double spend tx block",
			f: func(s *Store) (*Store, error) {
				err := s.Rollback(TstRecvTxBlockDetails.Height)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: 0,
			unc: btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value),
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstSpendingTx.Sha(), 0): {},
				*wire.NewOutPoint(TstSpendingTx.Sha(), 1): {},
			},
			unmined: map[wire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): {},
			},
		},
		{
			name: "insert original recv txout",
			f: func(s *Store) (*Store, error) {
				TstRecvTx.SetIndex(TstRecvIndex)
				r, err := s.InsertTx(TstRecvTx, TstRecvTxBlockDetails)
				if err != nil {
					return nil, err
				}

				_, err = r.AddCredit(0, false)
				if err != nil {
					return nil, err
				}

				_, err = r.ToJSON("", 100, &btcnet.MainNetParams)
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			bal: btcutil.Amount(TstRecvTx.MsgTx().TxOut[0].Value),
			unc: 0,
			unspents: map[wire.OutPoint]struct{}{
				*wire.NewOutPoint(TstRecvTx.Sha(), 0): {},
			},
			unmined: map[wire.ShaHash]struct{}{},
		},
	}

	var s *Store
	for _, test := range tests {
		tmpStore, err := test.f(s)
		if err != nil {
			t.Fatalf("%s: got error: %v", test.name, err)
		}
		s = tmpStore
		bal, err := s.Balance(1, TstRecvCurrentHeight)
		if err != nil {
			t.Fatalf("%s: Confirmed Balance() failed: %v", test.name, err)
		}
		if bal != test.bal {
			t.Fatalf("%s: balance mismatch: expected: %d, got: %d", test.name, test.bal, bal)
		}
		unc, err := s.Balance(0, TstRecvCurrentHeight)
		if err != nil {
			t.Fatalf("%s: Unconfirmed Balance() failed: %v", test.name, err)
		}
		unc -= bal
		if unc != test.unc {
			t.Errorf("%s: unconfirmed balance mismatch: expected %d, got %d", test.name, test.unc, unc)
		}

		// Check that unspent outputs match expected.
		unspent, err := s.UnspentOutputs()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range unspent {
			if r.Spent() {
				t.Errorf("%s: unspent record marked as spent", test.name)
			}

			op := *r.OutPoint()
			if _, ok := test.unspents[op]; !ok {
				t.Errorf("%s: unexpected unspent output: %v", test.name, op)
			}
			delete(test.unspents, op)
		}
		if len(test.unspents) != 0 {
			t.Errorf("%s: missing expected unspent output(s)", test.name)
		}

		// Check that unmined sent txs match expected.
		for _, tx := range s.UnminedDebitTxs() {
			if _, ok := test.unmined[*tx.Sha()]; !ok {
				t.Fatalf("%s: unexpected unmined signed tx: %v", test.name, *tx.Sha())
			}
			delete(test.unmined, *tx.Sha())
		}
		if len(test.unmined) != 0 {
			t.Errorf("%s: missing expected unmined signed tx(s)", test.name)
		}

		// Pass a re-serialized version of the store to each next test.
		buf := new(bytes.Buffer)
		nWritten, err := s.WriteTo(buf)
		if err != nil {
			t.Fatalf("%v: serialization failed: %v (wrote %v bytes)", test.name, err, nWritten)
		}
		if nWritten != int64(buf.Len()) {
			t.Errorf("%v: wrote %v bytes but buffer has %v", test.name, nWritten, buf.Len())
		}
		nRead, err := s.ReadFrom(buf)
		if err != nil {
			t.Fatalf("%v: deserialization failed: %v (read %v bytes after writing %v)",
				test.name, err, nRead, nWritten)
		}
		if nWritten != nRead {
			t.Errorf("%v: number of bytes written (%v) does not match those read (%v)",
				test.name, nWritten, nRead)
		}
	}
}

func TestFindingSpentCredits(t *testing.T) {
	s := New("/tmp/tx.bin")

	// Insert transaction and credit which will be spent.
	r, err := s.InsertTx(TstRecvTx, TstRecvTxBlockDetails)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.AddCredit(0, false)
	if err != nil {
		t.Fatal(err)
	}

	// Insert confirmed transaction which spends the above credit.
	TstSpendingTx.SetIndex(TstSignedTxIndex)
	r2, err := s.InsertTx(TstSpendingTx, TstSignedTxBlockDetails)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r2.AddCredit(0, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r2.AddDebits()
	if err != nil {
		t.Fatal(err)
	}

	bal, err := s.Balance(1, TstSignedTxBlockDetails.Height)
	if err != nil {
		t.Fatal(err)
	}
	if bal != btcutil.Amount(TstSpendingTx.MsgTx().TxOut[0].Value) {
		t.Fatal("bad balance")
	}
	unspents, err := s.UnspentOutputs()
	if err != nil {
		t.Fatal(err)
	}
	op := wire.NewOutPoint(TstSpendingTx.Sha(), 0)
	if *unspents[0].OutPoint() != *op {
		t.Fatal("unspent outpoint doesn't match expected")
	}
	if len(unspents) > 1 {
		t.Fatal("has more than one unspent credit")
	}
}
