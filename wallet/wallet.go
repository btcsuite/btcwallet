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
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/conformal/btcec"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	"github.com/davecgh/go-spew/spew"
	"hash"
	"io"
	"math"
	"math/big"
	"sync"
	"time"
)

var _ = spew.Dump

const (
	// Length in bytes of KDF output.
	kdfOutputBytes = 32

	// Maximum length in bytes of a comment that can have a size represented
	// as a uint16.
	maxCommentLen = (1 << 16) - 1
)

const (
	defaultKdfComputeTime = 0.25
	defaultKdfMaxMem      = 32 * 1024 * 1024
)

// Possible errors when dealing with wallets.
var (
	ChecksumErr        = errors.New("Checksum mismatch")
	MalformedEntryErr  = errors.New("Malformed entry")
	WalletDoesNotExist = errors.New("Non-existant wallet")
)

var (
	// '\xbaWALLET\x00'
	fileID = [8]byte{0xba, 0x57, 0x41, 0x4c, 0x4c, 0x45, 0x54, 0x00}

	mainnetMagicBytes = [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	testnetMagicBytes = [4]byte{0x0b, 0x11, 0x09, 0x07}
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

// Calculate the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// calculate hash160 which is ripemd160(sha256(data))
func calcHash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}

// calculate hash256 which is sha256(sha256(data))
func calcHash256(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), sha256.New())
}

// First byte in uncompressed pubKey field.
const pubkeyUncompressed = 0x4

// pubkeyFromPrivkey creates a 65-byte encoded pubkey based on a
// 32-byte privkey.
func pubkeyFromPrivkey(privkey []byte) (pubkey []byte) {
	x, y := btcec.S256().ScalarBaseMult(privkey)

	pubkey = make([]byte, 65)
	pubkey[0] = pubkeyUncompressed
	copy(pubkey[1:33], x.Bytes())
	copy(pubkey[33:], y.Bytes())

	return pubkey
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
func Key(passphrase []byte, params *kdfParameters) []byte {
	masterKey := passphrase
	for i := uint32(0); i < params.nIter; i++ {
		masterKey = keyOneIter(masterKey, params.salt[:], params.mem)
	}
	return masterKey
}

// leftPad returns a new slice of length size. The contents of input are right
// aligned in the new slice.
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}

// ChainedPrivKey deterministically generates new private key using a
// previous address and chaincode.  privkey and chaincode must be 32
// bytes long, and pubkey may either be 65 bytes or nil (in which case it
// is generated by the privkey).
func ChainedPrivKey(privkey, pubkey, chaincode []byte) ([]byte, error) {
	if len(privkey) != 32 {
		return nil, fmt.Errorf("Invalid privkey length %d (must be 32)",
			len(privkey))
	}
	if len(chaincode) != 32 {
		return nil, fmt.Errorf("Invalid chaincode length %d (must be 32)",
			len(chaincode))
	}
	if pubkey == nil {
		pubkey = pubkeyFromPrivkey(privkey)
	} else if len(pubkey) != 65 {
		return nil, fmt.Errorf("Invalid pubkey length %d.", len(pubkey))
	}

	// This is a perfect example of YOLO crypto.  Armory claims this XORing
	// with the SHA256 hash of the pubkey is done to add extra entropy (why
	// you'd want to add entropy to a deterministic function, I don't know),
	// even though the pubkey is generated directly from the privkey.  In
	// terms of security or privacy, this is a complete waste of CPU cycles,
	// but we do the same because we want to keep compatibility with
	// Armory's chained address generation.
	xorbytes := make([]byte, 32)
	chainMod := calcHash256(pubkey)
	for i, _ := range xorbytes {
		xorbytes[i] = chainMod[i] ^ chaincode[i]
	}
	chainXor := new(big.Int).SetBytes(xorbytes)
	privint := new(big.Int).SetBytes(privkey)

	t := new(big.Int).Mul(chainXor, privint)
	b := t.Mod(t, btcec.S256().N).Bytes()
	return leftPad(b, 32), nil
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
	version        uint32
	net            btcwire.BitcoinNet
	flags          walletFlags
	uniqID         [6]byte
	createDate     int64
	name           [32]byte
	desc           [256]byte
	highestUsed    int64
	kdfParams      kdfParameters
	keyGenerator   btcAddress
	addrMap        map[[ripemd160.Size]byte]*btcAddress
	addrCommentMap map[[ripemd160.Size]byte]*[]byte
	txCommentMap   map[[sha256.Size]byte]*[]byte

	// These are not serialized
	key struct {
		sync.Mutex
		secret []byte
	}
	chainIdxMap  map[int64]*[ripemd160.Size]byte
	lastChainIdx int64
}

// NewWallet() creates and initializes a new Wallet.  name's and
// desc's binary representation must not exceed 32 and 256 bytes,
// respectively.  All address private keys are encrypted with passphrase.
// The wallet is returned unlocked.
func NewWallet(name, desc string, passphrase []byte) (*Wallet, error) {
	if binary.Size(name) > 32 {
		return nil, errors.New("name exceeds 32 byte maximum size")
	}
	if binary.Size(desc) > 256 {
		return nil, errors.New("desc exceeds 256 byte maximum size")
	}

	kdfp := computeKdfParameters(defaultKdfComputeTime, defaultKdfMaxMem)

	rootkey, chaincode := make([]byte, 32), make([]byte, 32)
	rand.Read(rootkey)
	rand.Read(chaincode)
	root, err := newRootBtcAddress(rootkey, nil, chaincode)
	if err != nil {
		return nil, err
	}
	aeskey := Key([]byte(passphrase), kdfp)
	if err := root.encrypt(aeskey); err != nil {
		return nil, err
	}

	// Number of pregenerated addresses.
	const pregenerated = 100

	// TODO(jrick): not sure we will need uniqID, but would be good for
	// compat with armory.
	w := &Wallet{
		version: 0, // TODO(jrick): implement versioning
		net:     btcwire.MainNet,
		flags: walletFlags{
			useEncryption: true,
			watchingOnly:  false,
		},
		createDate: time.Now().Unix(),
		highestUsed: -1,
		kdfParams:      *kdfp,
		keyGenerator:   *root,
		addrMap:        make(map[[ripemd160.Size]byte]*btcAddress),
		addrCommentMap: make(map[[ripemd160.Size]byte]*[]byte),
		txCommentMap:   make(map[[sha256.Size]byte]*[]byte),
		chainIdxMap:    make(map[int64]*[ripemd160.Size]byte),
		lastChainIdx:   pregenerated - 1,
	}

	// Add root address to maps.
	w.addrMap[w.keyGenerator.pubKeyHash] = &w.keyGenerator
	w.chainIdxMap[w.keyGenerator.chainIndex] = &w.keyGenerator.pubKeyHash

	// Pre-generate 100 encrypted addresses and add to maps.
	addr := &w.keyGenerator
	cc := addr.chaincode[:]
	for i := 0; i < pregenerated; i++ {
		privkey, err := ChainedPrivKey(addr.privKeyCT, addr.pubKey[:], cc)
		if err != nil {
			return nil, err
		}
		newaddr, err := newBtcAddress(privkey, nil)
		if err != nil {
			return nil, err
		}
		if err = newaddr.encrypt(aeskey); err != nil {
			return nil, err
		}
		w.addrMap[newaddr.pubKeyHash] = newaddr
		newaddr.chainIndex = addr.chainIndex + 1
		w.chainIdxMap[newaddr.chainIndex] = &newaddr.pubKeyHash
		copy(newaddr.chaincode[:], cc) // armory does this.. but why?
		addr = newaddr
	}

	copy(w.name[:], []byte(name))
	copy(w.desc[:], []byte(desc))
	return w, nil
}

func (w *Wallet) Name() string {
	return string(w.name[:])
}

// ReadFrom reads data from a io.Reader and saves it to a Wallet,
// returning the number of bytes read and any errors encountered.
func (w *Wallet) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	w.addrMap = make(map[[ripemd160.Size]byte]*btcAddress)
	w.addrCommentMap = make(map[[ripemd160.Size]byte]*[]byte)
	w.chainIdxMap = make(map[int64]*[ripemd160.Size]byte)
	w.txCommentMap = make(map[[sha256.Size]byte]*[]byte)

	var id [8]byte
	var appendedEntries varEntries

	// Iterate through each entry needing to be read.  If data
	// implements io.ReaderFrom, use its ReadFrom func.  Otherwise,
	// data is a pointer to a fixed sized value.
	datas := []interface{}{
		&id,
		&w.version,
		&w.net,
		&w.flags,
		&w.uniqID,
		&w.createDate,
		&w.name,
		&w.desc,
		&w.highestUsed,
		&w.kdfParams,
		make([]byte, 256),
		&w.keyGenerator,
		make([]byte, 1024),
		&appendedEntries,
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

	if id != fileID {
		return n, errors.New("Unknown File ID.")
	}

	// Add root address to address map
	w.addrMap[w.keyGenerator.pubKeyHash] = &w.keyGenerator
	w.chainIdxMap[w.keyGenerator.chainIndex] = &w.keyGenerator.pubKeyHash

	// Fill unserializied fields.
	wts := ([]io.WriterTo)(appendedEntries)
	for _, wt := range wts {
		switch wt.(type) {
		case *addrEntry:
			e := wt.(*addrEntry)
			w.addrMap[e.pubKeyHash160] = &e.addr
			w.chainIdxMap[e.addr.chainIndex] = &e.pubKeyHash160
			if w.lastChainIdx < e.addr.chainIndex {
				w.lastChainIdx = e.addr.chainIndex
			}
		case *addrCommentEntry:
			e := wt.(*addrCommentEntry)
			w.addrCommentMap[e.pubKeyHash160] = &e.comment
		case *txCommentEntry:
			e := wt.(*txCommentEntry)
			w.txCommentMap[e.txHash] = &e.comment
		default:
			return n, errors.New("Unknown appended entry")
		}
	}

	return n, nil
}

// WriteTo serializes a Wallet and writes it to a io.Writer,
// returning the number of bytes written and any errors encountered.
func (w *Wallet) WriteTo(wtr io.Writer) (n int64, err error) {
	wts := make([]io.WriterTo, len(w.addrMap)-1)
	for hash, addr := range w.addrMap {
		if addr.chainIndex != -1 { // ignore root address
			e := &addrEntry{
				pubKeyHash160: hash,
				addr:          *addr,
			}
			wts[addr.chainIndex] = e
		}
	}
	for hash, comment := range w.addrCommentMap {
		e := &addrCommentEntry{
			pubKeyHash160: hash,
			comment:       *comment,
		}
		wts = append(wts, e)
	}
	for hash, comment := range w.txCommentMap {
		e := &txCommentEntry{
			txHash:  hash,
			comment: *comment,
		}
		wts = append(wts, e)
	}
	appendedEntries := varEntries(wts)

	// Iterate through each entry needing to be written.  If data
	// implements io.WriterTo, use its WriteTo func.  Otherwise,
	// data is a pointer to a fixed size value.
	datas := []interface{}{
		&fileID,
		&w.version,
		&w.net,
		&w.flags,
		&w.uniqID,
		&w.createDate,
		&w.name,
		&w.desc,
		&w.highestUsed,
		&w.kdfParams,
		make([]byte, 256),
		&w.keyGenerator,
		make([]byte, 1024),
		&appendedEntries,
	}
	var written int64
	for _, data := range datas {
		if s, ok := data.(io.WriterTo); ok {
			written, err = s.WriteTo(wtr)
		} else {
			written, err = binaryWrite(wtr, binary.LittleEndian, data)
		}
		n += written
		if err != nil {
			return n, err
		}
	}

	return n, nil
}

// Unlock derives an AES key from passphrase and wallet's KDF
// parameters and unlocks the root key of the wallet.
func (w *Wallet) Unlock(passphrase []byte) error {
	key := Key(passphrase, &w.kdfParams)

	// Attempt unlocking root address
	if err := w.keyGenerator.unlock(key); err != nil {
		return err
	} else {
		w.key.Lock()
		w.key.secret = key
		w.key.Unlock()
		return nil
	}
}

// Lock does a best effort to zero the keys.
// Being go this might not succeed but try anway.
// TODO(jrick)
func (w *Wallet) Lock() (err error) {
	// Remove clear text private keys from all entries.
	for _, addr := range w.addrMap {
		addr.privKeyCT = nil
	}

	w.key.Lock()
	if w.key.secret != nil {
		for i, _ := range w.key.secret {
			w.key.secret[i] = 0
		}
		w.key.secret = nil
	} else {
		err = fmt.Errorf("Wallet already locked")
	}
	w.key.Unlock()

	return nil
}

// IsLocked returns whether a wallet is unlocked (in which case the
// key is saved in memory), or locked.
func (w *Wallet) IsLocked() (locked bool) {
	w.key.Lock()
	locked = w.key.secret == nil
	w.key.Unlock()
	return locked
}

// Returns wallet version as string and int.
// TODO(jrick)
func (w *Wallet) Version() (string, int) {
	return "", 0
}

// NextUnusedAddress attempts to get the next chained address.  It
// currently relies on pre-generated addresses and will return an empty
// string if the address pool has run out. TODO(jrick)
func (w *Wallet) NextUnusedAddress() string {
	_ = w.lastChainIdx
	w.highestUsed++
	new160, err := w.addr160ForIdx(w.highestUsed)
	if err != nil {
		return ""
	}
	addr := w.addrMap[*new160]
	if addr != nil {
		return btcutil.Base58Encode(addr.pubKeyHash[:])
	} else {
		return ""
	}
}

func (w *Wallet) addr160ForIdx(idx int64) (*[ripemd160.Size]byte, error) {
	if idx > w.lastChainIdx {
		return nil, errors.New("Chain index out of range")
	}
	return w.chainIdxMap[idx], nil
}

// GetActiveAddresses returns all wallet addresses that have been
// requested to be generated.  These do not include pre-generated
// addresses.
func (w *Wallet) GetActiveAddresses() []string {
	addrs := []string{}
	for i := int64(-1); i <= w.highestUsed; i++ {
		addr160, err := w.addr160ForIdx(i)
		if err != nil {
			return addrs
		}
		addr := w.addrMap[*addr160]
		addrs = append(addrs, btcutil.Base58Encode(addr.pubKeyHash[:]))
	}
	return addrs
}

type walletFlags struct {
	useEncryption bool
	watchingOnly  bool
}

func (wf *walletFlags) ReadFrom(r io.Reader) (n int64, err error) {
	raw := make([]byte, 8)
	n, err = binaryRead(r, binary.LittleEndian, raw)
	wf.useEncryption = raw[0] != 0
	wf.watchingOnly = raw[1] != 0
	return n, err
}

func (wf *walletFlags) WriteTo(w io.Writer) (n int64, err error) {
	raw := make([]byte, 8)
	if wf.useEncryption {
		raw[0] = 1
	}
	if wf.watchingOnly {
		raw[1] = 1
	}
	return binaryWrite(w, binary.LittleEndian, raw)
}

type addrFlags struct {
	hasPrivKey bool
	hasPubKey  bool
	encrypted  bool
}

func (af *addrFlags) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64
	var b [8]byte
	read, err = binaryRead(r, binary.LittleEndian, &b)
	if err != nil {
		return n + read, err
	}
	n += read

	if b[0]&(1<<0) != 0 {
		af.hasPrivKey = true
	}
	if b[0]&(1<<1) != 0 {
		af.hasPubKey = true
	}
	if b[0]&(1<<2) == 0 {
		return n, errors.New("Address flag specifies unencrypted address.")
	}
	af.encrypted = true

	return n, nil
}

func (af *addrFlags) WriteTo(w io.Writer) (n int64, err error) {
	var b [8]byte
	if af.hasPrivKey {
		b[0] |= 1 << 0
	}
	if af.hasPubKey {
		b[0] |= 1 << 1
	}
	if !af.encrypted {
		// We only support encrypted privkeys.
		return n, errors.New("Address must be encrypted.")
	}
	b[0] |= 1 << 2

	return binaryWrite(w, binary.LittleEndian, b)
}

type btcAddress struct {
	pubKeyHash [ripemd160.Size]byte
	flags      addrFlags
	chaincode  [32]byte
	chainIndex int64
	chainDepth int64 // currently unused (will use when extending a locked wallet)
	initVector [16]byte
	privKey    [32]byte
	pubKey     [65]byte
	firstSeen  uint64
	lastSeen   uint64
	firstBlock uint32
	lastBlock  uint32
	privKeyCT  []byte // non-nil if unlocked.
}

// newBtcAddress initializes and returns a new address.  privkey must
// be 32 bytes.  iv must be 16 bytes, or nil (in which case it is
// randomly generated).
func newBtcAddress(privkey, iv []byte) (addr *btcAddress, err error) {
	if len(privkey) != 32 {
		return nil, errors.New("Private key is not 32 bytes.")
	}
	if iv == nil {
		iv = make([]byte, 16)
		rand.Read(iv)
	} else if len(iv) != 16 {
		return nil, errors.New("Init vector must be nil or 16 bytes large.")
	}

	addr = &btcAddress{
		privKeyCT: privkey,
		flags: addrFlags{
			hasPrivKey: true,
			hasPubKey:  true,
		},
		firstSeen:  math.MaxUint64,
		firstBlock: math.MaxUint32,
	}
	copy(addr.initVector[:], iv)
	pub := pubkeyFromPrivkey(privkey)
	copy(addr.pubKey[:], pub)
	copy(addr.pubKeyHash[:], calcHash160(pub))

	return addr, nil
}

// newRootBtcAddress generates a new address, also setting the
// chaincode and chain index to represent this address as a root
// address.
func newRootBtcAddress(privKey, iv, chaincode []byte) (addr *btcAddress, err error) {
	if len(chaincode) != 32 {
		return nil, errors.New("Chaincode is not 32 bytes.")
	}

	addr, err = newBtcAddress(privKey, iv)
	if err != nil {
		return nil, err
	}

	copy(addr.chaincode[:], chaincode)
	addr.chainIndex = -1

	return addr, err
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
		make([]byte, 4), // version
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
		if rf, ok := data.(io.ReaderFrom); ok {
			read, err = rf.ReadFrom(r)
		} else {
			read, err = binaryRead(r, binary.LittleEndian, data)
		}
		if err != nil {
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

	return n, nil
}

func (addr *btcAddress) WriteTo(w io.Writer) (n int64, err error) {
	var written int64

	datas := []interface{}{
		&addr.pubKeyHash,
		walletHash(addr.pubKeyHash[:]),
		make([]byte, 4), //version
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
		if wt, ok := data.(io.WriterTo); ok {
			written, err = wt.WriteTo(w)
		} else {
			written, err = binaryWrite(w, binary.LittleEndian, data)
		}
		if err != nil {
			return n + written, err
		}
		n += written
	}
	return n, nil
}

// encrypt attempts to encrypt an address's clear text private key,
// failing if the address is already encrypted or if the private key is
// not 32 bytes.  If successful, the encryption flag is set.
func (a *btcAddress) encrypt(key []byte) error {
	if a.flags.encrypted {
		return errors.New("Address already encrypted.")
	}
	if len(a.privKeyCT) != 32 {
		return errors.New("Invalid clear text private key.")
	}

	aesBlockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, a.initVector[:])

	aesEncrypter.XORKeyStream(a.privKey[:], a.privKeyCT)

	a.flags.encrypted = true
	return nil
}

// lock removes the reference this address holds to its clear text
// private key.  This function fails if the address is not encrypted.
func (a *btcAddress) lock() error {
	if !a.flags.encrypted {
		return errors.New("Unable to lock unencrypted address.")
	}

	a.privKeyCT = nil
	return nil
}

// unlock decrypts and stores a pointer to this address's private key,
// failing if the address is not encrypted, or the provided key is
// incorrect.
func (a *btcAddress) unlock(key []byte) error {
	if !a.flags.encrypted {
		return errors.New("Unable to unlock unencrypted address.")
	}

	aesBlockDecrypter, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, a.initVector[:])
	ct := make([]byte, 32)
	aesDecrypter.XORKeyStream(ct, a.privKey[:])

	pubKey, err := btcec.ParsePubKey(a.pubKey[:], btcec.S256())
	if err != nil {
		return fmt.Errorf("ParsePubKey faild:", err)
	}
	x, y := btcec.S256().ScalarBaseMult(ct)
	if x.Cmp(pubKey.X) != 0 || y.Cmp(pubKey.Y) != 0 {
		return errors.New("Decryption failed.")
	}

	a.privKeyCT = ct
	return nil
}

// TODO(jrick)
func (addr *btcAddress) changeEncryptionKey(oldkey, newkey []byte) error {
	return nil
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

// computeKdfParameters returns best guess parameters to the
// memory-hard key derivation function to make the computation last
// targetSec seconds, while using no more than maxMem bytes of memory.
func computeKdfParameters(targetSec float64, maxMem uint64) *kdfParameters {
	params := &kdfParameters{}
	rand.Read(params.salt[:])

	testKey := []byte("This is an example key to test KDF iteration speed")

	memoryReqtBytes := uint64(1024)
	approxSec := float64(0)

	for approxSec <= targetSec/4 && memoryReqtBytes < maxMem {
		memoryReqtBytes *= 2
		before := time.Now()
		_ = keyOneIter(testKey, params.salt[:], memoryReqtBytes)
		approxSec = time.Since(before).Seconds()
	}

	allItersSec := float64(0)
	nIter := uint32(1)
	for allItersSec < 0.02 { // This is a magic number straight from armory's source.
		nIter *= 2
		before := time.Now()
		for i := uint32(0); i < nIter; i++ {
			_ = keyOneIter(testKey, params.salt[:], memoryReqtBytes)
		}
		allItersSec = time.Since(before).Seconds()
	}

	params.mem = memoryReqtBytes
	params.nIter = nIter

	return params
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

	// Read params
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
	n += written
	return n, err
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
