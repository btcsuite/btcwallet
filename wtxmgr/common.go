/*
 * Copyright (c) 2013-2015 The Decred developers
 * Copyright (c) 2015 The Decred developers
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

package wtxmgr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrwallet/walletdb"
)

type unspentDebugData struct {
	outPoint    wire.OutPoint
	unmined     bool
	block       chainhash.Hash
	blockHeight int32
}

// ByOutpoint defines the methods needed to satisify sort.Interface to
// sort a slice of Utxos by their outpoint.
type ByOutpoint []*unspentDebugData

func (u ByOutpoint) Len() int { return len(u) }
func (u ByOutpoint) Less(i, j int) bool {
	if u[i].outPoint.Hash.IsEqual(&u[j].outPoint.Hash) {
		return u[i].outPoint.Index < u[j].outPoint.Index
	}
	cmp := bytes.Compare(u[i].outPoint.Hash[:], u[j].outPoint.Hash[:])
	isISmaller := (cmp == -1)
	return isISmaller
}
func (u ByOutpoint) Swap(i, j int) { u[i], u[j] = u[j], u[i] }

func writeUnspentDebugDataToBuf(buf *bytes.Buffer, udd *unspentDebugData) {
	buf.Write(udd.outPoint.Hash[:])

	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(udd.outPoint.Index))
	buf.Write(b)

	buf.Write([]byte{byte(udd.outPoint.Tree)})

	if udd.unmined {
		buf.Write([]byte{0x01})
	} else {
		buf.Write([]byte{0x00})
	}

	buf.Write(udd.block[:])

	b = make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(udd.blockHeight))
	buf.Write(b)
}

func (s *Store) DebugBucketUnspentString(inclUnmined bool) (string, error) {
	var str string
	err := scopedView(s.namespace, func(ns walletdb.Bucket) error {
		var err error
		str, err = s.debugBucketUnspentString(ns, inclUnmined)
		return err
	})
	return str, err
}

func (s *Store) debugBucketUnspentString(ns walletdb.Bucket,
	inclUnmined bool) (string, error) {
	var unspent []*unspentDebugData

	var op wire.OutPoint
	var block Block
	err := ns.Bucket(bucketUnspent).ForEach(func(k, v []byte) error {
		err := readCanonicalOutPoint(k, &op)
		if err != nil {
			return err
		}
		existsUnmined := false
		if existsRawUnminedInput(ns, k) != nil {
			// Skip including unmined if specified.
			if !inclUnmined {
				return nil
			}
			existsUnmined = true
		}
		err = readUnspentBlock(v, &block)
		if err != nil {
			return err
		}

		thisUnspentOutput := &unspentDebugData{
			op,
			existsUnmined,
			block.Hash,
			block.Height,
		}

		unspent = append(unspent, thisUnspentOutput)
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return "", err
		}
		str := "failed iterating unspent bucket"
		return "", storeError(ErrDatabase, str, err)
	}

	sort.Sort(ByOutpoint(unspent))

	var buffer bytes.Buffer
	str := fmt.Sprintf("Unspent outputs\n\n")
	buffer.WriteString(str)

	// Create a buffer, dump all the data into it, and hash.
	var thumbprintBuf bytes.Buffer
	for _, udd := range unspent {
		str = fmt.Sprintf("Hash: %v, Index: %v, Tree: %v, Unmined: %v, "+
			"Block: %v, Block height: %v\n",
			udd.outPoint.Hash,
			udd.outPoint.Index,
			udd.outPoint.Tree,
			udd.unmined,
			udd.block,
			udd.blockHeight)
		buffer.WriteString(str)
		writeUnspentDebugDataToBuf(&thumbprintBuf, udd)
	}

	unspentHash := chainhash.HashFunc(thumbprintBuf.Bytes())
	unspentThumbprint, err := chainhash.NewHash(unspentHash[:])
	if err != nil {
		return "", err
	}

	str = fmt.Sprintf("\nUnspent outputs thumbprint: %v",
		unspentThumbprint)
	buffer.WriteString(str)

	return buffer.String(), nil
}
