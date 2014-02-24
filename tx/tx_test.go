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

package tx_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/conformal/btcutil"
	. "github.com/conformal/btcwallet/tx"
	"github.com/conformal/btcwire"
)

// Received transaction output for mainnet outpoint
// 61d3696de4c888730cbe06b0ad8ecb6d72d6108e893895aa9bc067bd7eba3fad:0
var (
	TstRecvSerializedTx, _          = hex.DecodeString("010000000114d9ff358894c486b4ae11c2a8cf7851b1df64c53d2e511278eff17c22fb7373000000008c493046022100995447baec31ee9f6d4ec0e05cb2a44f6b817a99d5f6de167d1c75354a946410022100c9ffc23b64d770b0e01e7ff4d25fbc2f1ca8091053078a247905c39fce3760b601410458b8e267add3c1e374cf40f1de02b59213a82e1d84c2b94096e22e2f09387009c96debe1d0bcb2356ffdcf65d2a83d4b34e72c62eccd8490dbf2110167783b2bffffffff0280969800000000001976a914479ed307831d0ac19ebc5f63de7d5f1a430ddb9d88ac38bfaa00000000001976a914dadf9e3484f28b385ddeaa6c575c0c0d18e9788a88ac00000000")
	TstRecvTx, _                    = btcutil.NewTxFromBytes(TstRecvSerializedTx)
	TstRecvTxSpendingTxBlockHash, _ = btcwire.NewShaHashFromStr("00000000000000017188b968a371bab95aa43522665353b646e41865abae02a4")
	TstRecvAmt                      = int64(10000000)
	TstRecvTxBlockDetails           = &BlockDetails{
		Height: 276425,
		Hash:   *TstRecvTxSpendingTxBlockHash,
		Index:  684,
		Time:   time.Unix(1387737310, 0),
	}

	TstRecvCurrentHeight = int32(284498) // mainnet blockchain height at time of writing
	TstRecvTxOutConfirms = 8074          // hardcoded number of confirmations given the above block height

	TstSpendingTxBlockHeight = int32(279143)
	TstSignedTxBlockHash, _  = btcwire.NewShaHashFromStr("00000000000000017188b968a371bab95aa43522665353b646e41865abae02a4")
	TstSignedTxBlockDetails  = &BlockDetails{
		Height: TstSpendingTxBlockHeight,
		Hash:   *TstSignedTxBlockHash,
		Index:  123,
		Time:   time.Unix(1389114091, 0),
	}
)

func TestTxStore(t *testing.T) {
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
	spendingTx := btcwire.NewMsgTx()
	spendingTxIn := btcwire.NewTxIn(btcwire.NewOutPoint(TstDoubleSpendTx.Sha(), 0), []byte{0, 1, 2, 3, 4})
	spendingTx.AddTxIn(spendingTxIn)
	spendingTxOut1 := btcwire.NewTxOut(1e7, []byte{5, 6, 7, 8, 9})
	spendingTxOut2 := btcwire.NewTxOut(9e7, []byte{10, 11, 12, 13, 14})
	spendingTx.AddTxOut(spendingTxOut1)
	spendingTx.AddTxOut(spendingTxOut2)
	TstSpendingTx := btcutil.NewTx(spendingTx)

	tests := []struct {
		name     string
		f        func(*Store) *Store
		bal, unc int64
		unspents map[btcwire.OutPoint]struct{}
		unmined  map[btcwire.ShaHash]struct{}
	}{
		{
			name: "new store",
			f: func(_ *Store) *Store {
				return NewStore()
			},
			bal:      0,
			unc:      0,
			unspents: map[btcwire.OutPoint]struct{}{},
			unmined:  map[btcwire.ShaHash]struct{}{},
		},
		{
			name: "txout insert",
			f: func(s *Store) *Store {
				s.InsertRecvTxOut(TstRecvTx, 0, false, time.Now(), nil)
				return s
			},
			bal: 0,
			unc: TstRecvTx.MsgTx().TxOut[0].Value,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstRecvTx.Sha(), 0): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{},
		},
		{
			name: "confirmed txout insert",
			f: func(s *Store) *Store {
				s.InsertRecvTxOut(TstRecvTx, 0, false, TstRecvTxBlockDetails.Time, TstRecvTxBlockDetails)
				return s
			},
			bal: TstRecvTx.MsgTx().TxOut[0].Value,
			unc: 0,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstRecvTx.Sha(), 0): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{},
		},
		{
			name: "insert duplicate confirmed",
			f: func(s *Store) *Store {
				s.InsertRecvTxOut(TstRecvTx, 0, false, TstRecvTxBlockDetails.Time, TstRecvTxBlockDetails)
				return s
			},
			bal: TstRecvTx.MsgTx().TxOut[0].Value,
			unc: 0,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstRecvTx.Sha(), 0): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{},
		},
		{
			name: "insert duplicate unconfirmed",
			f: func(s *Store) *Store {
				s.InsertRecvTxOut(TstRecvTx, 0, false, time.Now(), nil)
				return s
			},
			bal: TstRecvTx.MsgTx().TxOut[0].Value,
			unc: 0,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstRecvTx.Sha(), 0): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{},
		},
		{
			name: "insert double spend with new txout value",
			f: func(s *Store) *Store {
				s.InsertRecvTxOut(TstDoubleSpendTx, 0, false, TstRecvTxBlockDetails.Time, TstRecvTxBlockDetails)
				return s
			},
			bal: TstDoubleSpendTx.MsgTx().TxOut[0].Value,
			unc: 0,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstDoubleSpendTx.Sha(), 0): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{},
		},
		{
			name: "insert unconfirmed signed tx",
			f: func(s *Store) *Store {
				s.InsertSignedTx(TstSpendingTx, nil)
				return s
			},
			bal:      0,
			unc:      0,
			unspents: map[btcwire.OutPoint]struct{}{},
			unmined: map[btcwire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): struct{}{},
			},
		},
		{
			name: "insert unconfirmed signed tx again",
			f: func(s *Store) *Store {
				s.InsertSignedTx(TstSpendingTx, nil)
				return s
			},
			bal:      0,
			unc:      0,
			unspents: map[btcwire.OutPoint]struct{}{},
			unmined: map[btcwire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): struct{}{},
			},
		},
		{
			name: "insert change (index 0)",
			f: func(s *Store) *Store {
				s.InsertRecvTxOut(TstSpendingTx, 0, true, time.Now(), nil)
				return s
			},
			bal: 0,
			unc: TstSpendingTx.MsgTx().TxOut[0].Value,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstSpendingTx.Sha(), 0): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): struct{}{},
			},
		},
		{
			name: "insert output back to this own wallet (index 1)",
			f: func(s *Store) *Store {
				s.InsertRecvTxOut(TstSpendingTx, 1, true, time.Now(), nil)
				return s
			},
			bal: 0,
			unc: TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstSpendingTx.Sha(), 0): struct{}{},
				*btcwire.NewOutPoint(TstSpendingTx.Sha(), 1): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): struct{}{},
			},
		},
		{
			name: "confirmed signed tx",
			f: func(s *Store) *Store {
				s.InsertSignedTx(TstSpendingTx, TstSignedTxBlockDetails)
				return s
			},
			bal: TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value,
			unc: 0,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstSpendingTx.Sha(), 0): struct{}{},
				*btcwire.NewOutPoint(TstSpendingTx.Sha(), 1): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{},
		},
		{
			name: "rollback after spending tx",
			f: func(s *Store) *Store {
				s.Rollback(TstSignedTxBlockDetails.Height + 1)
				return s
			},
			bal: TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value,
			unc: 0,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstSpendingTx.Sha(), 0): struct{}{},
				*btcwire.NewOutPoint(TstSpendingTx.Sha(), 1): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{},
		},
		{
			name: "rollback spending tx block",
			f: func(s *Store) *Store {
				s.Rollback(TstSignedTxBlockDetails.Height)
				return s
			},
			bal: 0,
			unc: TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstSpendingTx.Sha(), 0): struct{}{},
				*btcwire.NewOutPoint(TstSpendingTx.Sha(), 1): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): struct{}{},
			},
		},
		{
			name: "rollback double spend tx block",
			f: func(s *Store) *Store {
				s.Rollback(TstRecvTxBlockDetails.Height)
				return s
			},
			bal: 0,
			unc: TstSpendingTx.MsgTx().TxOut[0].Value + TstSpendingTx.MsgTx().TxOut[1].Value,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstSpendingTx.Sha(), 0): struct{}{},
				*btcwire.NewOutPoint(TstSpendingTx.Sha(), 1): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{
				*TstSpendingTx.Sha(): struct{}{},
			},
		},
		{
			name: "insert original recv txout",
			f: func(s *Store) *Store {
				s.InsertRecvTxOut(TstRecvTx, 0, false, TstRecvTxBlockDetails.Time, TstRecvTxBlockDetails)
				return s
			},
			bal: TstRecvTx.MsgTx().TxOut[0].Value,
			unc: 0,
			unspents: map[btcwire.OutPoint]struct{}{
				*btcwire.NewOutPoint(TstRecvTx.Sha(), 0): struct{}{},
			},
			unmined: map[btcwire.ShaHash]struct{}{},
		},
	}

	var s *Store
	for _, test := range tests {
		s = test.f(s)
		bal := s.Balance(1, TstRecvCurrentHeight)
		if bal != test.bal {
			t.Errorf("%s: balance mismatch: expected %d, got %d", test.name, test.bal, bal)
		}
		unc := s.Balance(0, TstRecvCurrentHeight) - bal
		if unc != test.unc {
			t.Errorf("%s: unconfimred balance mismatch: expected %d, got %d", test.name, test.unc, unc)
		}

		// Check that unspent outputs match expected.
		for _, record := range s.UnspentOutputs() {
			if record.Spent() {
				t.Errorf("%s: unspent record marked as spent", test.name)
			}

			op := *record.OutPoint()
			if _, ok := test.unspents[op]; !ok {
				t.Errorf("%s: unexpected unspent output: %v", test.name, op)
			}
			delete(test.unspents, op)
		}
		if len(test.unspents) != 0 {
			t.Errorf("%s: missing expected unspent output(s)", test.name)
		}

		// Check that unmined signed txs match expected.
		for _, tx := range s.UnminedSignedTxs() {
			if _, ok := test.unmined[*tx.Sha()]; !ok {
				t.Errorf("%s: unexpected unmined signed tx: %v", test.name, *tx.Sha())
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
