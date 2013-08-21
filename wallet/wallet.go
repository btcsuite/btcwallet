/*
 * Copyright (c) 2013 Conformal Systems LLC <info@conformal.com>
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

package wallet

import (
	"bytes"
	"code.google.com/p/go.crypto/ripemd160"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/conformal/btcec"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	"io"
	"sync"
)

const (
	// Length in bytes of KDF output.
	kdfOutputBytes = 32

	// Maximum length in bytes of a comment that can have a size represented
	// as a uint16.
	maxCommentLen = (1 << 16) - 1
)

// Possible errors when dealing with wallets.
var (
	ChecksumErr        = errors.New("Checksum mismatch")
	MalformedEntryErr  = errors.New("Malformed entry")
	WalletDoesNotExist = errors.New("Non-existant wallet")
)

type entryHeader byte

const (
	addrCommentHeader entryHeader = 1 << iota
	txCommentHeader
	deletedHeader
	addrHeader entryHeader = 0
)

// We want to use binaryRead and binaryWrite instead of binary.Read
// and binary.Write because those from the binary package do not return
// the number of bytes actually written or read.  We need to return
// this value to correctly support the io.ReaderFrom and io.WriterTo
// interfaces.
func binaryRead(r io.Reader, order binary.ByteOrder, data interface{}) (n int64, err error) {
	var read int
	buf := make([]byte, binary.Size(data))
	if read, err = r.Read(buf); err != nil {
		return int64(read), err
	}
	return int64(read), binary.Read(bytes.NewBuffer(buf), order, data)
}

// See comment for binaryRead().
func binaryWrite(w io.Writer, order binary.ByteOrder, data interface{}) (n int64, err error) {
	var buf bytes.Buffer
	if err = binary.Write(&buf, order, data); err != nil {
		return 0, err
	}

	written, err := w.Write(buf.Bytes())
	return int64(written), err
}

func keyOneIter(passphrase, salt []byte, memReqts uint64) []byte {
	saltedpass := append(passphrase, salt...)
	lutbl := make([]byte, memReqts)

	// Seed for lookup table
	seed := sha512.Sum512(saltedpass)
	copy(lutbl[:sha512.Size], seed[:])

	for nByte := 0; nByte < (int(memReqts) - sha512.Size); nByte += sha512.Size {
		hash := sha512.Sum512(lutbl[nByte : nByte+sha512.Size])
		copy(lutbl[nByte+sha512.Size:nByte+2*sha512.Size], hash[:])
	}

	x := lutbl[cap(lutbl)-sha512.Size:]

	seqCt := uint32(memReqts / sha512.Size)
	nLookups := seqCt / 2
	for i := uint32(0); i < nLookups; i++ {
		// Armory ignores endianness here.  We assume LE.
		newIdx := binary.LittleEndian.Uint32(x[cap(x)-4:]) % seqCt

		// Index of hash result at newIdx
		vIdx := newIdx * sha512.Size
		v := lutbl[vIdx : vIdx+sha512.Size]

		// XOR hash x with hash v
		for j := 0; j < sha512.Size; j++ {
			x[j] ^= v[j]
		}

		// Save new hash to x
		hash := sha512.Sum512(x)
		copy(x, hash[:])
	}

	return x[:kdfOutputBytes]
}

// Key implements the key derivation function used by Armory
// based on the ROMix algorithm described in Colin Percival's paper
// "Stronger Key Derivation via Sequential Memory-Hard Functions"
// (http://www.tarsnap.com/scrypt/scrypt.pdf).
func Key(passphrase, salt []byte, memReqts uint64, nIters uint32) []byte {
	masterKey := passphrase
	for i := uint32(0); i < nIters; i++ {
		masterKey = keyOneIter(masterKey, salt, memReqts)
	}
	return masterKey
}

type varEntries []io.WriterTo

func (v *varEntries) WriteTo(w io.Writer) (n int64, err error) {
	ss := ([]io.WriterTo)(*v)

	var written int64
	for _, s := range ss {
		var err error
		if written, err = s.WriteTo(w); err != nil {
			return n + written, err
		}
		n += written
	}
	return n, nil
}

func (v *varEntries) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	// Remove any previous entries.
	*v = nil
	wts := ([]io.WriterTo)(*v)

	// Keep reading entries until an EOF is reached.
	for {
		var header entryHeader
		if read, err = binaryRead(r, binary.LittleEndian, &header); err != nil {
			// EOF here is not an error.
			if err == io.EOF {
				return n + read, nil
			}
			return n + read, err
		}
		n += read

		var wt io.WriterTo = nil
		switch header {
		case addrHeader:
			var entry addrEntry
			if read, err = entry.ReadFrom(r); err != nil {
				return n + read, err
			}
			n += read
			wt = &entry
		case addrCommentHeader:
			var entry addrCommentEntry
			if read, err = entry.ReadFrom(r); err != nil {
				return n + read, err
			}
			n += read
			wt = &entry
		case txCommentHeader:
			var entry txCommentEntry
			if read, err = entry.ReadFrom(r); err != nil {
				return n + read, err
			}
			n += read
			wt = &entry
		case deletedHeader:
			var entry deletedEntry
			if read, err = entry.ReadFrom(r); err != nil {
				return n + read, err
			}
			n += read
		default:
			return n, fmt.Errorf("Unknown entry header: %d", uint8(header))
		}
		if wt != nil {
			wts = append(wts, wt)
			*v = wts
		}
	}

	return n, nil
}

// Wallet represents an btcd/Armory wallet in memory.  It
// implements the io.ReaderFrom and io.WriterTo interfaces to read
// from and write to any type of byte streams, including files.
// TODO(jrick) remove as many more magic numbers as possible.
type Wallet struct {
	fileID           [8]byte
	version          uint32
	netMagicBytes    [4]byte
	walletFlags      [8]byte
	uniqID           [6]byte
	createDate       [8]byte
	name             [32]byte
	description      [256]byte
	highestUsed      int64
	kdfParams        kdfParameters
	encryptionParams [256]byte
	keyGenerator     btcAddress
	appendedEntries  varEntries

	// These are not serialized
	key struct {
		sync.Mutex
		secret []byte
	}
	addrMap        map[[ripemd160.Size]byte]*btcAddress
	addrCommentMap map[[ripemd160.Size]byte]*[]byte
	chainIdxMap    map[int64]*[ripemd160.Size]byte
	txCommentMap   map[[sha256.Size]byte]*[]byte
	lastChainIdx   int64
}

// WriteTo serializes a Wallet and writes it to a io.Writer,
// returning the number of bytes written and any errors encountered.
func (wallet *Wallet) WriteTo(w io.Writer) (n int64, err error) {
	// Iterate through each entry needing to be written.  If data
	// implements io.WriterTo, use its WriteTo func.  Otherwise,
	// data is a pointer to a fixed size value.
	datas := []interface{}{
		&wallet.fileID,
		&wallet.version,
		&wallet.netMagicBytes,
		&wallet.walletFlags,
		&wallet.uniqID,
		&wallet.createDate,
		&wallet.name,
		&wallet.description,
		&wallet.highestUsed,
		&wallet.kdfParams,
		&wallet.encryptionParams,
		&wallet.keyGenerator,
		make([]byte, 1024),
		&wallet.appendedEntries,
	}
	var read int64
	for _, data := range datas {
		if s, ok := data.(io.WriterTo); ok {
			read, err = s.WriteTo(w)
		} else {
			read, err = binaryWrite(w, binary.LittleEndian, data)
		}
		n += read
		if err != nil {
			return n, err
		}
	}

	return n, nil
}

// ReadFrom reads data from a io.Reader and saves it to a Wallet,
// returning the number of bytes read and any errors encountered.
func (wallet *Wallet) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	wallet.addrMap = make(map[[ripemd160.Size]byte]*btcAddress)
	wallet.addrCommentMap = make(map[[ripemd160.Size]byte]*[]byte)
	wallet.chainIdxMap = make(map[int64]*[ripemd160.Size]byte)
	wallet.txCommentMap = make(map[[sha256.Size]byte]*[]byte)

	// Iterate through each entry needing to be read.  If data
	// implements io.ReaderFrom, use its ReadFrom func.  Otherwise,
	// data is a pointer to a fixed sized value.
	datas := []interface{}{
		&wallet.fileID,
		&wallet.version,
		&wallet.netMagicBytes,
		&wallet.walletFlags,
		&wallet.uniqID,
		&wallet.createDate,
		&wallet.name,
		&wallet.description,
		&wallet.highestUsed,
		&wallet.kdfParams,
		&wallet.encryptionParams,
		&wallet.keyGenerator,
		make([]byte, 1024),
		&wallet.appendedEntries,
	}
	for _, data := range datas {
		var err error
		if rf, ok := data.(io.ReaderFrom); ok {
			read, err = rf.ReadFrom(r)
		} else {
			read, err = binaryRead(r, binary.LittleEndian, data)
		}
		n += read
		if err != nil {
			return n, err
		}
	}

	// Add root address to address map
	wallet.addrMap[wallet.keyGenerator.pubKeyHash] = &wallet.keyGenerator
	wallet.chainIdxMap[wallet.keyGenerator.chainIndex] = &wallet.keyGenerator.pubKeyHash

	// Fill unserializied fields.
	wts := ([]io.WriterTo)(wallet.appendedEntries)
	for _, wt := range wts {
		switch wt.(type) {
		case *addrEntry:
			e := wt.(*addrEntry)
			wallet.addrMap[e.pubKeyHash160] = &e.addr
			wallet.chainIdxMap[e.addr.chainIndex] = &e.pubKeyHash160
			if wallet.lastChainIdx < e.addr.chainIndex {
				wallet.lastChainIdx = e.addr.chainIndex
			}
		case *addrCommentEntry:
			e := wt.(*addrCommentEntry)
			wallet.addrCommentMap[e.pubKeyHash160] = &e.comment
		case *txCommentEntry:
			e := wt.(*txCommentEntry)
			wallet.txCommentMap[e.txHash] = &e.comment
		default:
			return n, errors.New("Unknown appended entry")
		}
	}

	return n, nil
}

// Unlock derives an AES key from passphrase and wallet's KDF
// parameters and unlocks the root key of the wallet.
func (wallet *Wallet) Unlock(passphrase []byte) error {
	key := Key(passphrase, wallet.kdfParams.salt[:],
		wallet.kdfParams.mem, wallet.kdfParams.nIter)

	// Attempt unlocking root address
	if err := wallet.keyGenerator.unlock(key); err != nil {
		return err
	} else {
		wallet.key.Lock()
		wallet.key.secret = key
		wallet.key.Unlock()
		return nil
	}
}

// Lock does a best effort to zero the keys.
// Being go this might not succeed but try anway.
// TODO(jrick)
func (wallet *Wallet) Lock() (err error) {
	wallet.key.Lock()
	if wallet.key.secret != nil {
		for i, _ := range wallet.key.secret {
			wallet.key.secret[i] = 0
		}
		wallet.key.secret = nil
	} else {
		err = fmt.Errorf("Wallet already locked")
	}
	wallet.key.Unlock()
	return err
}

func (wallet *Wallet) IsLocked() (locked bool) {
	wallet.key.Lock()
	locked = wallet.key.secret == nil
	wallet.key.Unlock()
	return locked
}

// Returns wallet version as string and int.
// TODO(jrick)
func (wallet *Wallet) Version() (string, int) {
	return "", 0
}

// TODO(jrick)
func (wallet *Wallet) NextUnusedAddress() string {
	_ = wallet.lastChainIdx
	wallet.highestUsed++
	new160, err := wallet.addr160ForIdx(wallet.highestUsed)
	if err != nil {
		return ""
	}
	addr := wallet.addrMap[*new160]
	if addr != nil {
		return btcutil.Base58Encode(addr.pubKeyHash[:])
	} else {
		return ""
	}
}

func (wallet *Wallet) addr160ForIdx(idx int64) (*[ripemd160.Size]byte, error) {
	if idx > wallet.lastChainIdx {
		return nil, errors.New("Chain index out of range")
	}
	return wallet.chainIdxMap[idx], nil
}

func (wallet *Wallet) GetActiveAddresses() []string {
	addrs := []string{}
	for i := int64(-1); i <= wallet.highestUsed; i++ {
		addr160, err := wallet.addr160ForIdx(i)
		if err != nil {
			return addrs
		}
		addr := wallet.addrMap[*addr160]
		addrs = append(addrs, btcutil.Base58Encode(addr.pubKeyHash[:]))
	}
	return addrs
}

/*
func OpenWallet(file string) (*Wallet, error) {

}
*/

type btcAddress struct {
	pubKeyHash [ripemd160.Size]byte
	version    uint32
	flags      uint64
	chaincode  [32]byte
	chainIndex int64
	chainDepth int64
	initVector [16]byte
	privKey    [32]byte
	pubKey     [65]byte
	firstSeen  uint64
	lastSeen   uint64
	firstBlock uint32
	lastBlock  uint32
	privKeyCT  []byte // Points to clear text private key if unlocked.
}

// ReadFrom reads an encrypted address from an io.Reader.
func (addr *btcAddress) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	// Checksums
	var chkPubKeyHash uint32
	var chkChaincode uint32
	var chkInitVector uint32
	var chkPrivKey uint32
	var chkPubKey uint32

	// Read serialized wallet into addr fields and checksums.
	datas := []interface{}{
		&addr.pubKeyHash,
		&chkPubKeyHash,
		&addr.version,
		&addr.flags,
		&addr.chaincode,
		&chkChaincode,
		&addr.chainIndex,
		&addr.chainDepth,
		&addr.initVector,
		&chkInitVector,
		&addr.privKey,
		&chkPrivKey,
		&addr.pubKey,
		&chkPubKey,
		&addr.firstSeen,
		&addr.lastSeen,
		&addr.firstBlock,
		&addr.lastBlock,
	}
	for _, data := range datas {
		if read, err = binaryRead(r, binary.LittleEndian, data); err != nil {
			return n + read, err
		}
		n += read
	}

	// Verify checksums, correct errors where possible.
	checks := []struct {
		data []byte
		chk  uint32
	}{
		{addr.pubKeyHash[:], chkPubKeyHash},
		{addr.chaincode[:], chkChaincode},
		{addr.initVector[:], chkInitVector},
		{addr.privKey[:], chkPrivKey},
		{addr.pubKey[:], chkPubKey},
	}
	for i, _ := range checks {
		if err = verifyAndFix(checks[i].data, checks[i].chk); err != nil {
			return n, err
		}
	}

	// TODO(jrick) verify encryption

	return n, nil
}

func (addr *btcAddress) WriteTo(w io.Writer) (n int64, err error) {
	var written int64

	datas := []interface{}{
		&addr.pubKeyHash,
		walletHash(addr.pubKeyHash[:]),
		&addr.version,
		&addr.flags,
		&addr.chaincode,
		walletHash(addr.chaincode[:]),
		&addr.chainIndex,
		&addr.chainDepth,
		&addr.initVector,
		walletHash(addr.initVector[:]),
		&addr.privKey,
		walletHash(addr.privKey[:]),
		&addr.pubKey,
		walletHash(addr.pubKey[:]),
		&addr.firstSeen,
		&addr.lastSeen,
		&addr.firstBlock,
		&addr.lastBlock,
	}
	for _, data := range datas {
		written, err = binaryWrite(w, binary.LittleEndian, data)
		if err != nil {
			return n + written, err
		}
		n += written
	}
	return n, nil
}

func (addr *btcAddress) unlock(key []byte) error {
	aesBlockDecrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, addr.initVector[:])
	ct := make([]byte, 32)
	aesDecrypter.XORKeyStream(ct, addr.privKey[:])
	addr.privKeyCT = ct

	pubKey, err := btcec.ParsePubKey(addr.pubKey[:], btcec.S256())
	if err != nil {
		return fmt.Errorf("ParsePubKey faild:", err)
	}
	x, y := btcec.S256().ScalarBaseMult(addr.privKeyCT)
	if x.Cmp(pubKey.X) != 0 || y.Cmp(pubKey.Y) != 0 {
		return fmt.Errorf("decryption failed")
	}

	return nil
}

// TODO(jrick)
func (addr *btcAddress) changeEncryptionKey(oldkey, newkey []byte) error {
	return nil
}

// TODO(jrick)
func (addr *btcAddress) verifyEncryptionKey() {
}

// TODO(jrick)
func newRandomAddress(key []byte) *btcAddress {
	addr := &btcAddress{}
	return addr
}

func walletHash(b []byte) uint32 {
	sum := btcwire.DoubleSha256(b)
	return binary.LittleEndian.Uint32(sum)
}

// TODO(jrick) add error correction.
func verifyAndFix(b []byte, chk uint32) error {
	if walletHash(b) != chk {
		return ChecksumErr
	}
	return nil
}

type kdfParameters struct {
	mem   uint64
	nIter uint32
	salt  [32]byte
}

func (params *kdfParameters) WriteTo(w io.Writer) (n int64, err error) {
	var written int64

	memBytes := make([]byte, 8)
	nIterBytes := make([]byte, 4)
	binary.LittleEndian.PutUint64(memBytes, params.mem)
	binary.LittleEndian.PutUint32(nIterBytes, params.nIter)
	chkedBytes := append(memBytes, nIterBytes...)
	chkedBytes = append(chkedBytes, params.salt[:]...)

	datas := []interface{}{
		&params.mem,
		&params.nIter,
		&params.salt,
		walletHash(chkedBytes),
		make([]byte, 256-(binary.Size(params)+4)), // padding
	}
	for _, data := range datas {
		if written, err = binaryWrite(w, binary.LittleEndian, data); err != nil {
			return n + written, err
		}
		n += written
	}

	return n, nil
}

func (params *kdfParameters) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	// These must be read in but are not saved directly to params.
	chkedBytes := make([]byte, 44)
	var chk uint32
	padding := make([]byte, 256-(binary.Size(params)+4))

	datas := []interface{}{
		chkedBytes,
		&chk,
		padding,
	}
	for _, data := range datas {
		if read, err = binaryRead(r, binary.LittleEndian, data); err != nil {
			return n + read, err
		}
		n += read
	}

	// Verify checksum
	if err = verifyAndFix(chkedBytes, chk); err != nil {
		return n, err
	}

	// Write params
	buf := bytes.NewBuffer(chkedBytes)
	datas = []interface{}{
		&params.mem,
		&params.nIter,
		&params.salt,
	}
	for _, data := range datas {
		if err = binary.Read(buf, binary.LittleEndian, data); err != nil {
			return n, err
		}
	}

	return n, nil
}

type addrEntry struct {
	pubKeyHash160 [ripemd160.Size]byte
	addr          btcAddress
}

func (e *addrEntry) WriteTo(w io.Writer) (n int64, err error) {
	var written int64

	// Write header
	if written, err = binaryWrite(w, binary.LittleEndian, addrHeader); err != nil {
		return n + written, err
	}
	n += written

	// Write hash
	if written, err = binaryWrite(w, binary.LittleEndian, &e.pubKeyHash160); err != nil {
		return n + written, err
	}
	n += written

	// Write btcAddress
	written, err = e.addr.WriteTo(w)
	return n + written, err
}

func (e *addrEntry) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	if read, err = binaryRead(r, binary.LittleEndian, &e.pubKeyHash160); err != nil {
		return n + read, err
	}
	n += read

	read, err = e.addr.ReadFrom(r)
	return n + read, err
}

type addrCommentEntry struct {
	pubKeyHash160 [ripemd160.Size]byte
	comment       []byte
}

func (e *addrCommentEntry) WriteTo(w io.Writer) (n int64, err error) {
	var written int64

	// Comments shall not overflow their entry.
	if len(e.comment) > maxCommentLen {
		return n, MalformedEntryErr
	}

	// Write header
	if written, err = binaryWrite(w, binary.LittleEndian, addrCommentHeader); err != nil {
		return n + written, err
	}
	n += written

	// Write hash
	if written, err = binaryWrite(w, binary.LittleEndian, &e.pubKeyHash160); err != nil {
		return n + written, err
	}
	n += written

	// Write length
	if written, err = binaryWrite(w, binary.LittleEndian, uint16(len(e.comment))); err != nil {
		return n + written, err
	}
	n += written

	// Write comment
	written, err = binaryWrite(w, binary.LittleEndian, e.comment)
	return n + written, err
}

func (e *addrCommentEntry) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	if read, err = binaryRead(r, binary.LittleEndian, &e.pubKeyHash160); err != nil {
		return n + read, err
	}
	n += read

	var clen uint16
	if read, err = binaryRead(r, binary.LittleEndian, &clen); err != nil {
		return n + read, err
	}
	n += read

	e.comment = make([]byte, clen)
	read, err = binaryRead(r, binary.LittleEndian, e.comment)
	return n + read, err
}

type txCommentEntry struct {
	txHash  [sha256.Size]byte
	comment []byte
}

func (e *txCommentEntry) WriteTo(w io.Writer) (n int64, err error) {
	var written int64

	// Comments shall not overflow their entry.
	if len(e.comment) > maxCommentLen {
		return n, MalformedEntryErr
	}

	// Write header
	if written, err = binaryWrite(w, binary.LittleEndian, txCommentHeader); err != nil {
		return n + written, err
	}
	n += written

	// Write length
	if written, err = binaryWrite(w, binary.LittleEndian, uint16(len(e.comment))); err != nil {
		return n + written, err
	}

	// Write comment
	written, err = binaryWrite(w, binary.LittleEndian, e.comment)
	return n + written, err
}

func (e *txCommentEntry) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	if read, err = binaryRead(r, binary.LittleEndian, &e.txHash); err != nil {
		return n + read, err
	}
	n += read

	var clen uint16
	if read, err = binaryRead(r, binary.LittleEndian, &clen); err != nil {
		return n + read, err
	}
	n += read

	e.comment = make([]byte, clen)
	read, err = binaryRead(r, binary.LittleEndian, e.comment)
	return n + read, err
}

type deletedEntry struct {
}

func (e *deletedEntry) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	var ulen uint16
	if read, err = binaryRead(r, binary.LittleEndian, &ulen); err != nil {
		return n + read, err
	}
	n += read

	unused := make([]byte, ulen)
	if nRead, err := r.Read(unused); err == io.EOF {
		return n + int64(nRead), nil
	} else {
		return n + int64(nRead), err
	}
}

type UTXOStore struct {
}

type utxo struct {
	pubKeyHash [ripemd160.Size]byte
	*btcwire.TxOut
	block int64
}
