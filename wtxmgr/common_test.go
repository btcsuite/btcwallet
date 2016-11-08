// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/boltdb/bolt"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/walletdb"
	_ "github.com/decred/dcrwallet/walletdb/bdb"
)

var (
	wtxmgrNamespaceKey   = []byte("wtxmgr")
	waddrmgrNamespaceKey = []byte("waddrmgr")
)

func setup() (db walletdb.DB, s *Store, teardown func(), err error) {
	tmpDir, err := ioutil.TempDir("", "wtxmgr_test")
	if err != nil {
		teardown = func() {}
		return
	}
	db, err = walletdb.Create("bdb", filepath.Join(tmpDir, "db"))
	if err != nil {
		teardown = func() {
			os.RemoveAll(tmpDir)
		}
		return
	}
	teardown = func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}
	tx, err := db.BeginReadWriteTx()
	if err != nil {
		return
	}
	defer tx.Commit()
	ns, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
	if err != nil {
		return
	}
	_, err = tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
	if err != nil {
		return
	}
	err = Create(ns, &chaincfg.TestNetParams)
	if err != nil {
		return
	}
	acctLookup := func(walletdb.ReadBucket, dcrutil.Address) (uint32, error) { return 0, nil }
	s, err = Open(ns, &chaincfg.TestNetParams, acctLookup)
	return
}

func setupBoltDB() (db *bolt.DB, teardown func(), err error) {
	f, err := ioutil.TempFile("", "wtxmgr_boltdb")
	if err != nil {
		teardown = func() {}
		return
	}
	f.Close()
	teardown = func() {
		os.Remove(f.Name())
	}
	db, err = bolt.Open(f.Name(), 0600, nil)
	return
}

type blockGenerator struct {
	lastHash   chainhash.Hash
	lastHeight int32
}

func makeBlockGenerator() blockGenerator {
	return blockGenerator{lastHash: *chaincfg.TestNetParams.GenesisHash}
}

func (g *blockGenerator) generate(voteBits uint16) *wire.BlockHeader {
	h := &wire.BlockHeader{
		PrevBlock: g.lastHash,
		VoteBits:  voteBits,
		Height:    uint32(g.lastHeight + 1),
	}
	g.lastHash = h.BlockSha()
	g.lastHeight++
	return h
}

func makeHeaderData(h *wire.BlockHeader) BlockHeaderData {
	var b bytes.Buffer
	err := h.Serialize(&b)
	if err != nil {
		panic(err)
	}
	d := BlockHeaderData{BlockHash: h.BlockSha()}
	copy(d.SerializedHeader[:], b.Bytes())
	return d
}

func makeHeaderDataSlice(headers ...*wire.BlockHeader) []BlockHeaderData {
	data := make([]BlockHeaderData, 0, len(headers))
	for _, h := range headers {
		data = append(data, makeHeaderData(h))
	}
	return data
}

func makeBlockMeta(h *wire.BlockHeader) *BlockMeta {
	return &BlockMeta{
		Block: Block{
			Hash:   h.BlockSha(),
			Height: int32(h.Height),
		},
		Time: time.Time{},
	}
}

func decodeHash(reversedHash string) *chainhash.Hash {
	h, err := chainhash.NewHashFromStr(reversedHash)
	if err != nil {
		panic(err)
	}
	return h
}
