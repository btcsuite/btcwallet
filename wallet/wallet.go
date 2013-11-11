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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/conformal/btcec"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	"hash"
	"io"
	"math/big"
	"sync"
	"time"
)

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
	ErrAddressNotFound    = errors.New("address not found")
	ErrChecksumMismatch   = errors.New("checksum mismatch")
	ErrMalformedEntry     = errors.New("malformed entry")
	ErrNetworkMismatch    = errors.New("network mismatch")
	ErrWalletDoesNotExist = errors.New("non-existant wallet")
	ErrWalletLocked       = errors.New("wallet is locked")
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
	if read < binary.Size(data) {
		return int64(read), io.EOF
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

// calculate sha512(data)
func calcSha512(buf []byte) []byte {
	return calcHash(buf, sha512.New())
}

// pubkeyFromPrivkey creates an encoded pubkey based on a
// 32-byte privkey.  The returned pubkey is 33 bytes if compressed,
// or 65 bytes if uncompressed.
func pubkeyFromPrivkey(privkey []byte, compress bool) (pubkey []byte) {
	x, y := btcec.S256().ScalarBaseMult(privkey)
	pub := (*btcec.PublicKey)(&ecdsa.PublicKey{
		Curve: btcec.S256(),
		X:     x,
		Y:     y,
	})

	if compress {
		return pub.SerializeCompressed()
	}
	return pub.SerializeUncompressed()
}

func keyOneIter(passphrase, salt []byte, memReqts uint64) []byte {
	saltedpass := append(passphrase, salt...)
	lutbl := make([]byte, memReqts)

	// Seed for lookup table
	seed := calcSha512(saltedpass)
	copy(lutbl[:sha512.Size], seed)

	for nByte := 0; nByte < (int(memReqts) - sha512.Size); nByte += sha512.Size {
		hash := calcSha512(lutbl[nByte : nByte+sha512.Size])
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
		hash := calcSha512(x)
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

func pad(size int, b []byte) []byte {
	// Prevent a possible panic if the input exceeds the expected size.
	if len(b) > size {
		size = len(b)
	}

	p := make([]byte, size)
	copy(p[size-len(b):], b)
	return p
}

// ChainedPrivKey deterministically generates a new private key using a
// previous address and chaincode.  privkey and chaincode must be 32
// bytes long, and pubkey may either be 33 bytes, 65 bytes or nil (in
// which case it is generated by the privkey).
func ChainedPrivKey(privkey, pubkey, chaincode []byte) ([]byte, error) {
	if len(privkey) != 32 {
		return nil, fmt.Errorf("invalid privkey length %d (must be 32)",
			len(privkey))
	}
	if len(chaincode) != 32 {
		return nil, fmt.Errorf("invalid chaincode length %d (must be 32)",
			len(chaincode))
	}
	if pubkey == nil {
		pubkey = pubkeyFromPrivkey(privkey, true)
	} else if !(len(pubkey) == 65 || len(pubkey) == 33) {
		return nil, fmt.Errorf("invalid pubkey length %d", len(pubkey))
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
	for i := range xorbytes {
		xorbytes[i] = chainMod[i] ^ chaincode[i]
	}
	chainXor := new(big.Int).SetBytes(xorbytes)
	privint := new(big.Int).SetBytes(privkey)

	t := new(big.Int).Mul(chainXor, privint)
	b := t.Mod(t, btcec.S256().N).Bytes()
	return pad(32, b), nil
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

		var wt io.WriterTo
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
			return n, fmt.Errorf("unknown entry header: %d", uint8(header))
		}
		if wt != nil {
			wts = append(wts, wt)
			*v = wts
		}
	}
}

type addressHashKey string
type transactionHashKey string
type comment []byte

// Wallet represents an btcd/Armory wallet in memory.  It
// implements the io.ReaderFrom and io.WriterTo interfaces to read
// from and write to any type of byte streams, including files.
// TODO(jrick) remove as many more magic numbers as possible.
type Wallet struct {
	version      uint32
	net          btcwire.BitcoinNet
	flags        walletFlags
	uniqID       [6]byte
	createDate   int64
	name         [32]byte
	desc         [256]byte
	highestUsed  int64
	kdfParams    kdfParameters
	keyGenerator btcAddress

	// These are non-standard and fit in the extra 1024 bytes between the
	// root address and the appended entries.
	syncedBlockHeight int32
	syncedBlockHash   btcwire.ShaHash

	addrMap        map[addressHashKey]*btcAddress
	addrCommentMap map[addressHashKey]comment
	txCommentMap   map[transactionHashKey]comment

	// These are not serialized.
	secret struct {
		sync.Mutex
		key []byte
	}
	chainIdxMap  map[int64]addressHashKey
	lastChainIdx int64
}

// UnusedWalletBytes specifies the number of actually unused bytes
// between the root address and the appended entries in a serialized
// wallet.  Armory's wallet file format provides 1024 unused bytes
// in this space.  btcwallet requires saving a few additional details
// with the wallet file, so the binary sizes of those are subtracted
// from 1024.  Currently, these are:
//
//  - last synced block height (int32, 4 bytes)
//  - last synced block hash (btcwire.ShaHash, btcwire.HashSize bytes)
const UnusedWalletBytes = 1024 - 4 - btcwire.HashSize

// NewWallet creates and initializes a new Wallet.  name's and
// desc's binary representation must not exceed 32 and 256 bytes,
// respectively.  All address private keys are encrypted with passphrase.
// The wallet is returned unlocked.
func NewWallet(name, desc string, passphrase []byte, net btcwire.BitcoinNet, createdAt *BlockStamp) (*Wallet, error) {
	// Check sizes of inputs.
	if len([]byte(name)) > 32 {
		return nil, errors.New("name exceeds 32 byte maximum size")
	}
	if len([]byte(desc)) > 256 {
		return nil, errors.New("desc exceeds 256 byte maximum size")
	}

	// Randomly-generate rootkey and chaincode.
	rootkey, chaincode := make([]byte, 32), make([]byte, 32)
	rand.Read(rootkey)
	rand.Read(chaincode)

	// Create new root address from key and chaincode.
	root, err := newRootBtcAddress(rootkey, nil, chaincode, createdAt)
	if err != nil {
		return nil, err
	}

	// Compute AES key and encrypt root address.
	kdfp := computeKdfParameters(defaultKdfComputeTime, defaultKdfMaxMem)
	aeskey := Key([]byte(passphrase), kdfp)
	if err := root.encrypt(aeskey); err != nil {
		return nil, err
	}

	// Define number of addresses to pre-generate for keypool.
	const nPregenerated = 100

	// Create and fill wallet.
	w := &Wallet{
		version: 0, // TODO(jrick): implement versioning
		// TODO(jrick): not sure we will need uniqID, but would be good for
		// compat with armory.
		net: net,
		flags: walletFlags{
			useEncryption: true,
			watchingOnly:  false,
		},
		createDate:        time.Now().Unix(),
		highestUsed:       -1,
		kdfParams:         *kdfp,
		keyGenerator:      *root,
		syncedBlockHeight: createdAt.Height,
		syncedBlockHash:   createdAt.Hash,
		addrMap:           make(map[addressHashKey]*btcAddress),
		addrCommentMap:    make(map[addressHashKey]comment),
		txCommentMap:      make(map[transactionHashKey]comment),
		chainIdxMap:       make(map[int64]addressHashKey),
		lastChainIdx:      nPregenerated - 1,
	}
	copy(w.name[:], []byte(name))
	copy(w.desc[:], []byte(desc))

	// Add root address to maps.
	w.addrMap[addressHashKey(w.keyGenerator.pubKeyHash[:])] = &w.keyGenerator
	w.chainIdxMap[w.keyGenerator.chainIndex] = addressHashKey(w.keyGenerator.pubKeyHash[:])

	// Pre-generate encrypted addresses and add to maps.
	addr := &w.keyGenerator
	cc := addr.chaincode[:]
	for i := 0; i < nPregenerated; i++ {
		// Wallet has not been returned to the caller yet, so need to
		// lock and unlock the previous address's key's clear text
		// private key mutex.
		privkey, err := ChainedPrivKey(addr.privKeyCT.key, addr.pubKey, cc)
		if err != nil {
			return nil, err
		}
		newaddr, err := newBtcAddress(privkey, nil, createdAt)
		if err != nil {
			return nil, err
		}
		if err = newaddr.encrypt(aeskey); err != nil {
			return nil, err
		}
		w.addrMap[addressHashKey(newaddr.pubKeyHash[:])] = newaddr
		newaddr.chainIndex = addr.chainIndex + 1
		w.chainIdxMap[newaddr.chainIndex] = addressHashKey(newaddr.pubKeyHash[:])
		copy(newaddr.chaincode[:], cc) // armory does this.. but why?
		addr = newaddr
	}

	return w, nil
}

// Name returns the name of a wallet.  This name is used as the
// account name for btcwallet JSON methods.
func (w *Wallet) Name() string {
	return string(w.name[:])
}

// ReadFrom reads data from a io.Reader and saves it to a Wallet,
// returning the number of bytes read and any errors encountered.
func (w *Wallet) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	w.addrMap = make(map[addressHashKey]*btcAddress)
	w.addrCommentMap = make(map[addressHashKey]comment)
	w.chainIdxMap = make(map[int64]addressHashKey)
	w.txCommentMap = make(map[transactionHashKey]comment)

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
		&w.syncedBlockHeight,
		&w.syncedBlockHash,
		make([]byte, UnusedWalletBytes),
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
		return n, errors.New("unknown file ID")
	}

	// Add root address to address map
	w.addrMap[addressHashKey(w.keyGenerator.pubKeyHash[:])] = &w.keyGenerator
	w.chainIdxMap[w.keyGenerator.chainIndex] = addressHashKey(w.keyGenerator.pubKeyHash[:])

	// Fill unserializied fields.
	wts := ([]io.WriterTo)(appendedEntries)
	for _, wt := range wts {
		switch wt.(type) {
		case *addrEntry:
			e := wt.(*addrEntry)
			w.addrMap[addressHashKey(e.pubKeyHash160[:])] = &e.addr
			w.chainIdxMap[e.addr.chainIndex] = addressHashKey(e.pubKeyHash160[:])
			if w.lastChainIdx < e.addr.chainIndex {
				w.lastChainIdx = e.addr.chainIndex
			}
		case *addrCommentEntry:
			e := wt.(*addrCommentEntry)
			w.addrCommentMap[addressHashKey(e.pubKeyHash160[:])] = comment(e.comment)
		case *txCommentEntry:
			e := wt.(*txCommentEntry)
			w.txCommentMap[transactionHashKey(e.txHash[:])] = comment(e.comment)
		default:
			return n, errors.New("unknown appended entry")
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
			e := addrEntry{
				addr: *addr,
			}
			copy(e.pubKeyHash160[:], []byte(hash))
			wts[addr.chainIndex] = &e
		}
	}
	for hash, comment := range w.addrCommentMap {
		e := &addrCommentEntry{
			comment: []byte(comment),
		}
		copy(e.pubKeyHash160[:], []byte(hash))
		wts = append(wts, e)
	}
	for hash, comment := range w.txCommentMap {
		e := &txCommentEntry{
			comment: []byte(comment),
		}
		copy(e.txHash[:], []byte(hash))
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
		&w.syncedBlockHeight,
		&w.syncedBlockHash,
		make([]byte, UnusedWalletBytes),
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
// parameters and unlocks the root key of the wallet.  If
// the unlock was successful, the wallet's secret key is saved,
// allowing the decryption of any encrypted private key.
func (w *Wallet) Unlock(passphrase []byte) error {
	// Derive key from KDF parameters and passphrase.
	key := Key(passphrase, &w.kdfParams)

	// Unlock root address with derived key.
	if _, err := w.keyGenerator.unlock(key); err != nil {
		return err
	}

	// If unlock was successful, save the secret key.
	w.secret.Lock()
	w.secret.key = key
	w.secret.Unlock()
	return nil
}

// Lock performs a best try effort to remove and zero all secret keys
// associated with the wallet.
func (w *Wallet) Lock() (err error) {
	// Remove clear text passphrase from wallet.
	w.secret.Lock()
	if w.secret.key == nil {
		err = ErrWalletLocked
	} else {
		zero(w.secret.key)
		w.secret.key = nil
	}
	w.secret.Unlock()

	// Remove clear text private keys from all address entries.
	for _, addr := range w.addrMap {
		addr.privKeyCT.Lock()
		zero(addr.privKeyCT.key)
		addr.privKeyCT.key = nil
		addr.privKeyCT.Unlock()
	}

	return err
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// IsLocked returns whether a wallet is unlocked (in which case the
// key is saved in memory), or locked.
func (w *Wallet) IsLocked() (locked bool) {
	w.secret.Lock()
	locked = w.secret.key == nil
	w.secret.Unlock()
	return locked
}

// Version returns a wallet's version as a string and int.
// TODO(jrick)
func (w *Wallet) Version() (string, int) {
	return "", 0
}

// NextUnusedAddress attempts to get the next chained address.
//
// TODO(jrick): this currently relies on pre-generated addresses
// and will return an empty string if the address pool has run out.
func (w *Wallet) NextUnusedAddress() (string, error) {
	// Attempt to get address hash of next chained address.
	next160, err := w.addr160ForIdx(w.highestUsed + 1)
	if err != nil {
		// TODO(jrick): Re-fill key pool.
		return "", errors.New("cannot find generated address")
	} else {
		w.highestUsed++
	}

	// Look up address.
	addr := w.addrMap[next160]
	if addr == nil {
		return "", errors.New("cannot find generated address")
	}

	// Create and return payment address for address hash.
	return addr.paymentAddress(w.net)
}

// addrHashForAddress decodes and returns the address hash for a
// payment address string, performing some basic sanity checking that it
// matches the Bitcoin network used by the wallet.
func (w *Wallet) addrHashForAddress(addr string) ([]byte, error) {
	addr160, net, err := btcutil.DecodeAddress(addr)
	if err != nil {
		return nil, err
	}

	// Return error if address is for the wrong Bitcoin network.
	switch {
	case net == btcutil.MainNetAddr && w.net != btcwire.MainNet:
		fallthrough
	case net == btcutil.TestNetAddr && w.net != btcwire.TestNet:
		return nil, ErrNetworkMismatch
	}

	return addr160, nil
}

// GetAddressKey returns the private key for a payment address stored
// in a wallet.  This can fail if the payment address is for a different
// Bitcoin network than what this wallet uses, the address is not
// contained in the wallet, the address does not include a public and
// private key, or if the wallet is locked.
func (w *Wallet) GetAddressKey(addr string) (key *ecdsa.PrivateKey, err error) {
	// Get address hash for payment address string.
	addr160, err := w.addrHashForAddress(addr)
	if err != nil {
		return nil, err
	}

	// Lookup address from map.
	btcaddr, ok := w.addrMap[addressHashKey(addr160)]
	if !ok {
		return nil, ErrAddressNotFound
	}

	// Both the pubkey and encrypted privkey must be recorded to return
	// the private key.  Error if neither are saved.
	if !btcaddr.flags.hasPubKey {
		return nil, errors.New("no public key for address")
	}
	if !btcaddr.flags.hasPrivKey {
		return nil, errors.New("no private key for address")
	}

	// Parse public key.
	pubkey, err := btcec.ParsePubKey(btcaddr.pubKey, btcec.S256())
	if err != nil {
		return nil, err
	}

	// The wallet's secret will be zeroed on lock, so make a local
	// copy.
	localSecret := make([]byte, 32)
	w.secret.Lock()
	if len(w.secret.key) != 32 {
		w.secret.Unlock()
		return nil, ErrWalletLocked
	}
	copy(localSecret, w.secret.key)
	w.secret.Unlock()

	// Unlock address with wallet secret.  unlock returns a copy of the
	// clear text private key, and may be used safely even during an address
	// lock.
	privKeyCT, err := btcaddr.unlock(localSecret)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PrivateKey{
		PublicKey: *pubkey,
		D:         new(big.Int).SetBytes(privKeyCT),
	}, nil
}

// GetAddressInfo returns an AddressInfo for an address in a wallet.
func (w *Wallet) GetAddressInfo(addr string) (*AddressInfo, error) {
	// Get address hash for addr.
	addr160, err := w.addrHashForAddress(addr)
	if err != nil {
		return nil, err
	}

	// Look up address by address hash.
	btcaddr, ok := w.addrMap[addressHashKey(addr160)]
	if !ok {
		return nil, errors.New("address not in wallet")
	}

	return btcaddr.info(w.net)
}

// Net returns the bitcoin network identifier for this wallet.
func (w *Wallet) Net() btcwire.BitcoinNet {
	return w.net
}

// SetSyncedWith marks the wallet to be in sync with the block
// described by height and hash.
func (w *Wallet) SetSyncedWith(bs *BlockStamp) {
	w.syncedBlockHeight = bs.Height
	copy(w.syncedBlockHash[:], bs.Hash[:])
}

// SyncedWith returns the height and hash of the block the wallet is
// currently marked to be in sync with.
func (w *Wallet) SyncedWith() *BlockStamp {
	return &BlockStamp{
		Height: w.syncedBlockHeight,
		Hash:   w.syncedBlockHash,
	}
}

// CreatedAt returns the height of the blockchain at the time of wallet
// creation.  This is needed when performaing a full rescan to prevent
// unnecessary rescanning before wallet addresses first appeared.
func (w *Wallet) CreatedAt() int32 {
	return w.keyGenerator.firstBlock
}

func (w *Wallet) addr160ForIdx(idx int64) (addressHashKey, error) {
	if idx > w.lastChainIdx {
		return "", errors.New("chain index out of range")
	}
	return w.chainIdxMap[idx], nil
}

// AddressInfo holds information regarding an address needed to manage
// a complete wallet.
type AddressInfo struct {
	Address    string
	AddrHash   string
	FirstBlock int32
	Compressed bool
}

// GetSortedActiveAddresses returns all wallet addresses that have been
// requested to be generated.  These do not include unused addresses in
// the key pool.  Use this when ordered addresses are needed.  Otherwise,
// GetActiveAddresses is preferred.
func (w *Wallet) GetSortedActiveAddresses() []*AddressInfo {
	addrs := make([]*AddressInfo, 0, w.highestUsed+1)
	for i := int64(-1); i <= w.highestUsed; i++ {
		addr160, err := w.addr160ForIdx(i)
		if err != nil {
			return addrs
		}
		addr := w.addrMap[addr160]
		info, err := addr.info(w.Net())
		if err == nil {
			addrs = append(addrs, info)
		}
	}
	return addrs
}

// GetActiveAddresses returns a map between active payment addresses
// and their full info.  These do not include unused addresses in the
// key pool.  If addresses must be sorted, use GetSortedActiveAddresses.
func (w *Wallet) GetActiveAddresses() map[string]*AddressInfo {
	addrs := make(map[string]*AddressInfo)
	for i := int64(-1); i <= w.highestUsed; i++ {
		addr160, err := w.addr160ForIdx(i)
		if err != nil {
			return addrs
		}
		addr := w.addrMap[addr160]
		info, err := addr.info(w.Net())
		if err == nil {
			addrs[info.Address] = info
		}
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
	hasPrivKey              bool
	hasPubKey               bool
	encrypted               bool
	createPrivKeyNextUnlock bool // unimplemented in btcwallet
	compressed              bool
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
		return n, errors.New("address flag specifies unencrypted address")
	}
	af.encrypted = true
	if b[0]&(1<<3) != 0 {
		af.createPrivKeyNextUnlock = true
	}
	if b[0]&(1<<4) != 0 {
		af.compressed = true
	}

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
		return n, errors.New("address must be encrypted")
	}
	b[0] |= 1 << 2
	if af.createPrivKeyNextUnlock {
		b[0] |= 1 << 3
	}
	if af.compressed {
		b[0] |= 1 << 4
	}

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
	pubKey     publicKey
	firstSeen  int64
	lastSeen   int64
	firstBlock int32
	lastBlock  int32
	privKeyCT  struct {
		sync.Mutex
		key []byte // non-nil if unlocked.
	}
}

const (
	pubkeyCompressed   byte = 0x2
	pubkeyUncompressed byte = 0x4
)

type publicKey []byte

func (k *publicKey) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64
	var format byte
	read, err = binaryRead(r, binary.LittleEndian, &format)
	if err != nil {
		return n + read, err
	}
	n += read

	// Remove the oddness from the format
	noodd := format
	noodd &= ^byte(0x1)

	var s []byte
	switch noodd {
	case pubkeyUncompressed:
		// Read the remaining 64 bytes.
		s = make([]byte, 64)

	case pubkeyCompressed:
		// Read the remaining 32 bytes.
		s = make([]byte, 32)

	default:
		return n, errors.New("unrecognized pubkey format")
	}

	read, err = binaryRead(r, binary.LittleEndian, &s)
	if err != nil {
		return n + read, err
	}
	n += read

	*k = append([]byte{format}, s...)
	return
}

func (k *publicKey) WriteTo(w io.Writer) (n int64, err error) {
	return binaryWrite(w, binary.LittleEndian, []byte(*k))
}

// newBtcAddress initializes and returns a new address.  privkey must
// be 32 bytes.  iv must be 16 bytes, or nil (in which case it is
// randomly generated).
func newBtcAddress(privkey, iv []byte, bs *BlockStamp) (addr *btcAddress, err error) {
	if len(privkey) != 32 {
		return nil, errors.New("private key is not 32 bytes")
	}
	if iv == nil {
		iv = make([]byte, 16)
		rand.Read(iv)
	} else if len(iv) != 16 {
		return nil, errors.New("init vector must be nil or 16 bytes large")
	}

	addr = &btcAddress{
		flags: addrFlags{
			hasPrivKey: true,
			hasPubKey:  true,
			compressed: true,
		},
		firstSeen:  time.Now().Unix(),
		firstBlock: bs.Height,
	}
	addr.privKeyCT.key = privkey
	copy(addr.initVector[:], iv)
	addr.pubKey = pubkeyFromPrivkey(privkey, true)
	copy(addr.pubKeyHash[:], calcHash160(addr.pubKey))

	return addr, nil
}

// newRootBtcAddress generates a new address, also setting the
// chaincode and chain index to represent this address as a root
// address.
func newRootBtcAddress(privKey, iv, chaincode []byte, bs *BlockStamp) (addr *btcAddress, err error) {
	if len(chaincode) != 32 {
		return nil, errors.New("chaincode is not 32 bytes")
	}

	addr, err = newBtcAddress(privKey, iv, bs)
	if err != nil {
		return nil, err
	}

	copy(addr.chaincode[:], chaincode)
	addr.chainIndex = -1

	return addr, err
}

// ReadFrom reads an encrypted address from an io.Reader.
func (a *btcAddress) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	// Checksums
	var chkPubKeyHash uint32
	var chkChaincode uint32
	var chkInitVector uint32
	var chkPrivKey uint32
	var chkPubKey uint32

	// Read serialized wallet into addr fields and checksums.
	datas := []interface{}{
		&a.pubKeyHash,
		&chkPubKeyHash,
		make([]byte, 4), // version
		&a.flags,
		&a.chaincode,
		&chkChaincode,
		&a.chainIndex,
		&a.chainDepth,
		&a.initVector,
		&chkInitVector,
		&a.privKey,
		&chkPrivKey,
		&a.pubKey,
		&chkPubKey,
		&a.firstSeen,
		&a.lastSeen,
		&a.firstBlock,
		&a.lastBlock,
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
		{a.pubKeyHash[:], chkPubKeyHash},
		{a.chaincode[:], chkChaincode},
		{a.initVector[:], chkInitVector},
		{a.privKey[:], chkPrivKey},
		{a.pubKey, chkPubKey},
	}
	for i := range checks {
		if err = verifyAndFix(checks[i].data, checks[i].chk); err != nil {
			return n, err
		}
	}

	return n, nil
}

func (a *btcAddress) WriteTo(w io.Writer) (n int64, err error) {
	var written int64

	datas := []interface{}{
		&a.pubKeyHash,
		walletHash(a.pubKeyHash[:]),
		make([]byte, 4), //version
		&a.flags,
		&a.chaincode,
		walletHash(a.chaincode[:]),
		&a.chainIndex,
		&a.chainDepth,
		&a.initVector,
		walletHash(a.initVector[:]),
		&a.privKey,
		walletHash(a.privKey[:]),
		&a.pubKey,
		walletHash(a.pubKey),
		&a.firstSeen,
		&a.lastSeen,
		&a.firstBlock,
		&a.lastBlock,
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
		return errors.New("address already encrypted")
	}
	a.privKeyCT.Lock()
	defer a.privKeyCT.Unlock()
	if len(a.privKeyCT.key) != 32 {
		return errors.New("invalid clear text private key")
	}

	aesBlockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, a.initVector[:])

	aesEncrypter.XORKeyStream(a.privKey[:], a.privKeyCT.key)

	a.flags.encrypted = true
	return nil
}

// lock removes the reference this address holds to its clear text
// private key.  This function fails if the address is not encrypted.
func (a *btcAddress) lock() error {
	if !a.flags.encrypted {
		return errors.New("unable to lock unencrypted address")
	}

	a.privKeyCT.Lock()
	zero(a.privKeyCT.key)
	a.privKeyCT.key = nil
	a.privKeyCT.Unlock()
	return nil
}

// unlock decrypts and stores a pointer to this address's private key,
// failing if the address is not encrypted, or the provided key is
// incorrect.  The returned clear text private key will always be a copy
// that may be safely used by the caller without worrying about it being
// zeroed during an address lock.
func (a *btcAddress) unlock(key []byte) (privKeyCT []byte, err error) {
	if !a.flags.encrypted {
		return nil, errors.New("unable to unlock unencrypted address")
	}

	// If secret is already saved, return a copy without performing a full
	// unlock.
	a.privKeyCT.Lock()
	if len(a.privKeyCT.key) == 32 {
		privKeyCT := make([]byte, 32)
		copy(privKeyCT, a.privKeyCT.key)
		a.privKeyCT.Unlock()
		return privKeyCT, nil
	}
	a.privKeyCT.Unlock()

	// Decrypt private key with AES key.
	aesBlockDecrypter, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, a.initVector[:])
	privkey := make([]byte, 32)
	aesDecrypter.XORKeyStream(privkey, a.privKey[:])

	// Generate new x, y from clear text private key and check that they
	// match the recorded pubkey.
	pubKey, err := btcec.ParsePubKey(a.pubKey, btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("cannot parse pubkey: %s", err)
	}
	x, y := btcec.S256().ScalarBaseMult(privkey)
	if x.Cmp(pubKey.X) != 0 || y.Cmp(pubKey.Y) != 0 {
		return nil, errors.New("decryption failed")
	}

	privkeyCopy := make([]byte, 32)
	copy(privkeyCopy, privkey)
	a.privKeyCT.Lock()
	a.privKeyCT.key = privkey
	a.privKeyCT.Unlock()
	return privkeyCopy, nil
}

// TODO(jrick)
func (a *btcAddress) changeEncryptionKey(oldkey, newkey []byte) error {
	return errors.New("unimplemented")
}

// paymentAddress returns a human readable payment address string for
// an address.
func (a *btcAddress) paymentAddress(net btcwire.BitcoinNet) (string, error) {
	return btcutil.EncodeAddress(a.pubKeyHash[:], net)
}

// info returns information about a btcAddress stored in a AddressInfo
// struct.
func (a *btcAddress) info(net btcwire.BitcoinNet) (*AddressInfo, error) {
	address, err := a.paymentAddress(net)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Address:    address,
		AddrHash:   string(a.pubKeyHash[:]),
		FirstBlock: a.firstBlock,
		Compressed: a.flags.compressed,
	}, nil
}

func walletHash(b []byte) uint32 {
	sum := btcwire.DoubleSha256(b)
	return binary.LittleEndian.Uint32(sum)
}

// TODO(jrick) add error correction.
func verifyAndFix(b []byte, chk uint32) error {
	if walletHash(b) != chk {
		return ErrChecksumMismatch
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
		return n, ErrMalformedEntry
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
		return n, ErrMalformedEntry
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

type deletedEntry struct{}

func (e *deletedEntry) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64

	var ulen uint16
	if read, err = binaryRead(r, binary.LittleEndian, &ulen); err != nil {
		return n + read, err
	}
	n += read

	unused := make([]byte, ulen)
	nRead, err := r.Read(unused)
	if err == io.EOF {
		return n + int64(nRead), nil
	}
	return n + int64(nRead), err
}

// BlockStamp defines a block (by height and a unique hash) and is
// used to mark a point in the blockchain that a wallet element is
// synced to.
type BlockStamp struct {
	Height int32
	Hash   btcwire.ShaHash
}
