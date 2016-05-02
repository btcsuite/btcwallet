/*
 * Copyright (c) 2015 Conformal Systems LLC <info@conformal.com>
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

package wstakemgr

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/decred/dcrd/blockchain"
	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
	walletchain "github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/walletdb"
)

const (
	revocationFeeTestNet int64 = 10000
	revocationFeeMainNet int64 = 7500000
)

// sstxRecord is the structure for a stored SStx.
type sstxRecord struct {
	tx          *dcrutil.Tx
	ts          time.Time
	voteBitsSet bool
	voteBits    uint16
	voteBitsExt []byte
}

// ssgenRecord is the structure for a stored SSGen tx. There's no
// real reason to store the actual transaction I don't think,
// the inputs and outputs are all predetermined from the block
// height and the original SStx it references.
type ssgenRecord struct {
	blockHash   chainhash.Hash
	blockHeight uint32
	txHash      chainhash.Hash
	voteBits    uint16
	ts          time.Time
}

// ssrtxRecord is the structure for a stored SSRtx. While the
// ssrtx itself does not include the block hash or block height,
// we still preserve that so that we know the block ntfn that
// informed us that the sstx was missed.
type ssrtxRecord struct {
	blockHash   chainhash.Hash
	blockHeight uint32
	txHash      chainhash.Hash
	ts          time.Time
}

// TicketStatus is the current status of a stake pool ticket.
type TicketStatus uint8

const (
	// TSImmatureOrLive indicates that the ticket is either
	// live or immature.
	TSImmatureOrLive = iota

	// TSVoted indicates that the ticket was spent as a vote.
	TSVoted

	// TSMissed indicates that the ticket was spent as a
	// revocation.
	TSMissed
)

// PoolTicket is a 73-byte struct that is used to preserve user's
// ticket information when they have an account at the stake pool.
type PoolTicket struct {
	Ticket       chainhash.Hash
	HeightTicket uint32
	Status       TicketStatus
	HeightSpent  uint32
	SpentBy      chainhash.Hash
}

// StakePoolUser is a list of tickets for a given user (P2SH
// address) in the stake pool.
type StakePoolUser struct {
	Tickets        []*PoolTicket
	InvalidTickets []*chainhash.Hash
}

// StakeStore represents a safely accessible database of
// stake transactions.
type StakeStore struct {
	mtx *sync.Mutex

	namespace walletdb.Namespace
	Params    *chaincfg.Params
	Manager   *waddrmgr.Manager
	chainSvr  *walletchain.RPCClient
	isClosed  bool

	ownedSStxs map[chainhash.Hash]struct{}
}

// StakeNotification is the data structure that contains information
// about an SStx (ticket), SSGen (vote), or SSRtx (revocation)
// produced by wallet.
type StakeNotification struct {
	TxType    int8 // These are the same as in staketx.go of stake, but int8
	TxHash    chainhash.Hash
	BlockHash chainhash.Hash // SSGen only
	Height    int32          // SSGen only
	Amount    int64          // SStx only
	SStxIn    chainhash.Hash // SSGen and SSRtx
	VoteBits  uint16         // SSGen only
}

// checkHashInStore checks if a hash exists in ownedSStxs.
func (s *StakeStore) checkHashInStore(hash *chainhash.Hash) bool {
	_, exists := s.ownedSStxs[*hash]
	return exists
}

// CheckHashInStore is the exported version of CheckHashInStore that is
// safe for concurrent access.
func (s *StakeStore) CheckHashInStore(hash *chainhash.Hash) bool {
	if s.isClosed {
		return false
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.checkHashInStore(hash)
}

// addHashToStore adds a hash into ownedSStxs.
func (s *StakeStore) addHashToStore(hash *chainhash.Hash) {
	s.ownedSStxs[*hash] = struct{}{}
}

// insertSStx inserts an SStx into the store.
func (s *StakeStore) insertSStx(sstx *dcrutil.Tx, voteBits uint16) error {
	// If we already have the SStx, no need to
	// try to include twice.
	exists := s.checkHashInStore(sstx.Sha())
	if exists {
		log.Tracef("Attempted to insert SStx %v into the stake store, "+
			"but the SStx already exists.", sstx.Sha())
		return nil
	}
	record := &sstxRecord{
		sstx,
		time.Now(),
		true,
		voteBits,
		nil, // TODO Allow for extensible voteBits
	}

	// Add the SStx to the database.
	err := s.namespace.Update(func(tx walletdb.Tx) error {
		if putErr := putSStxRecord(tx, record, voteBits); putErr != nil {
			return putErr
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Add the SStx's hash to the internal list in the store.
	s.addHashToStore(sstx.Sha())

	return nil
}

// InsertSStx is the exported version of insertSStx that is safe for concurrent
// access.
func (s *StakeStore) InsertSStx(sstx *dcrutil.Tx, voteBits uint16) error {
	if s.isClosed {
		str := "stake store is closed"
		return stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.insertSStx(sstx, voteBits)
}

// sstxVoteBits fetches the intended voteBits for a given SStx. This per-
// ticket voteBits will override the default voteBits set by the wallet.
func (s *StakeStore) sstxVoteBits(sstx *chainhash.Hash) (bool, uint16, error) {
	// If we already have the SStx, no need to
	// try to include twice.
	exists := s.checkHashInStore(sstx)
	if !exists {
		str := fmt.Sprintf("ticket %v not found in store", sstx)
		return false, 0, stakeStoreError(ErrNoExist, str, nil)
	}

	// Attempt to update the SStx in the database.
	voteBitsSet := false
	voteBits := uint16(0)
	err := s.namespace.View(func(tx walletdb.Tx) error {
		var fetchErr error
		if voteBitsSet, voteBits, fetchErr = fetchSStxRecordVoteBits(tx,
			sstx); fetchErr != nil {
			return fetchErr
		}

		return nil
	})
	if err != nil {
		return voteBitsSet, voteBits, err
	}

	return voteBitsSet, voteBits, err
}

// SStxVoteBits is the exported version of sstxVoteBits that is
// safe for concurrent access.
func (s *StakeStore) SStxVoteBits(sstx *chainhash.Hash) (bool, uint16, error) {
	if s.isClosed {
		str := "stake store is closed"
		return false, 0, stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.sstxVoteBits(sstx)
}

// updateSStxVoteBits updates the intended voteBits for a given SStx. This per-
// ticket voteBits will override the default voteBits set by the wallet.
func (s *StakeStore) updateSStxVoteBits(sstx *chainhash.Hash,
	voteBits uint16) error {
	// If we already have the SStx, no need to
	// try to include twice.
	exists := s.checkHashInStore(sstx)
	if !exists {
		str := fmt.Sprintf("ticket %v not found in store", sstx)
		return stakeStoreError(ErrNoExist, str, nil)
	}

	// Attempt to update the SStx in the database.
	err := s.namespace.Update(func(tx walletdb.Tx) error {
		if updErr := updateSStxRecordVoteBits(tx, sstx, voteBits); updErr != nil {
			return updErr
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// UpdateSStxVoteBits is the exported version of updateSStxVoteBits that is
// safe for concurrent access.
func (s *StakeStore) UpdateSStxVoteBits(sstx *chainhash.Hash,
	voteBits uint16) error {
	if s.isClosed {
		str := "stake store is closed"
		return stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.updateSStxVoteBits(sstx, voteBits)
}

// dumpSStxHashes dumps the hashes of all owned SStxs. Note
// that this doesn't use the DB.
func (s *StakeStore) dumpSStxHashes() []chainhash.Hash {
	if s.isClosed {
		return nil
	}

	// Copy the hash list of sstxs. You could pass the pointer
	// directly but you risk that the size of the internal
	// ownedSStxs is later modified while the end user is
	// working with the returned list.
	ownedSStxs := make([]chainhash.Hash, len(s.ownedSStxs))

	itr := 0
	for hash := range s.ownedSStxs {
		ownedSStxs[itr] = hash
		itr++
	}

	return ownedSStxs
}

// DumpSStxHashes is the exported version of dumpSStxHashes that is safe
// for concurrent access.
func (s *StakeStore) DumpSStxHashes() ([]chainhash.Hash, error) {
	if s.isClosed {
		str := "stake store is closed"
		return nil, stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.dumpSStxHashes(), nil
}

// dumpSStxHashes dumps the hashes of all owned SStxs for some address.
func (s *StakeStore) dumpSStxHashesForAddress(addr dcrutil.Address) ([]chainhash.Hash, error) {
	// Extract the HASH160 script hash; if it's not 20 bytes
	// long, return an error.
	scriptHash := addr.ScriptAddress()
	if len(scriptHash) != 20 {
		str := "stake store is closed"
		return nil, stakeStoreError(ErrInput, str, nil)
	}

	var err error
	allTickets := s.dumpSStxHashes()
	var ticketsForAddr []chainhash.Hash

	// Access the database and store the result locally.
	err = s.namespace.View(func(tx walletdb.Tx) error {
		var err error
		var thisScrHash []byte
		for _, h := range allTickets {
			thisScrHash, err = fetchSStxRecordSStxTicketScriptHash(tx, &h)
			if err != nil {
				return err
			}
			if bytes.Equal(scriptHash, thisScrHash) {
				ticketsForAddr = append(ticketsForAddr, h)
			}
		}
		return nil
	})
	if err != nil {
		str := "failure getting ticket 0th out script hashes from db"
		return nil, stakeStoreError(ErrDatabase, str, err)
	}

	return ticketsForAddr, nil
}

// DumpSStxHashesForAddress is the exported version of dumpSStxHashesForAddress
// that is safe for concurrent access.
func (s *StakeStore) DumpSStxHashesForAddress(addr dcrutil.Address) ([]chainhash.Hash, error) {
	if s.isClosed {
		str := "stake store is closed"
		return nil, stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.dumpSStxHashesForAddress(addr)
}

// sstxAddress returns the address for a given ticket.
func (s *StakeStore) sstxAddress(hash *chainhash.Hash) (dcrutil.Address, error) {
	// Access the database and store the result locally.
	var addr dcrutil.Address
	err := s.namespace.View(func(tx walletdb.Tx) error {
		thisScrHash, errFetch := fetchSStxRecordSStxTicketScriptHash(tx, hash)
		if errFetch != nil {
			return errFetch
		}
		var errAddr error
		addr, errAddr = dcrutil.NewAddressScriptHashFromHash(thisScrHash,
			s.Params)
		if errAddr != nil {
			return errAddr
		}

		return nil
	})
	if err != nil {
		str := "failure getting ticket 0th out script hashes from db"
		return nil, stakeStoreError(ErrDatabase, str, err)
	}

	return addr, nil
}

// SStxAddress is the exported, concurrency safe version of sstxAddress.
func (s *StakeStore) SStxAddress(hash *chainhash.Hash) (dcrutil.Address, error) {
	if s.isClosed {
		str := "stake store is closed"
		return nil, stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.sstxAddress(hash)
}

// dumpSSGenHashes fetches and returns the entire list of votes generated by
// this wallet, including votes that were produced but were never included in
// the blockchain.
func (s *StakeStore) dumpSSGenHashes() ([]chainhash.Hash, error) {
	var voteList []chainhash.Hash

	err := s.namespace.View(func(tx walletdb.Tx) error {
		var errForEach error

		// Open the vite records database.
		bucket := tx.RootBucket().Bucket(ssgenRecordsBucketName)

		// Store each hash sequentially.
		errForEach = bucket.ForEach(func(k []byte, v []byte) error {
			recs, errDeser := deserializeSSGenRecords(v)
			if errDeser != nil {
				return errDeser
			}

			for _, rec := range recs {
				voteList = append(voteList, rec.txHash)
			}
			return nil
		})

		return errForEach
	})
	if err != nil {
		return nil, err
	}

	return voteList, nil
}

// DumpSSGenHashes is the exported version of dumpSSGenHashes that is safe
// for concurrent access.
func (s *StakeStore) DumpSSGenHashes() ([]chainhash.Hash, error) {
	if s.isClosed {
		str := "stake store is closed"
		return nil, stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.dumpSSGenHashes()
}

// dumpSSRtxHashes fetches the entire list of revocations generated by this
// wallet.
func (s *StakeStore) dumpSSRtxHashes() ([]chainhash.Hash, error) {
	var revocationList []chainhash.Hash

	err := s.namespace.View(func(tx walletdb.Tx) error {
		var errForEach error

		// Open the revocation records database.
		bucket := tx.RootBucket().Bucket(ssrtxRecordsBucketName)

		// Store each hash sequentially.
		errForEach = bucket.ForEach(func(k []byte, v []byte) error {
			rec, errDeser := deserializeSSRtxRecord(v)
			if errDeser != nil {
				return errDeser
			}

			revocationList = append(revocationList, rec.txHash)
			return nil
		})

		return errForEach
	})
	if err != nil {
		return nil, err
	}

	return revocationList, nil
}

// DumpSSRtxHashes is the exported version of dumpSSRtxHashes that is safe
// for concurrent access.
func (s *StakeStore) DumpSSRtxHashes() ([]chainhash.Hash, error) {
	if s.isClosed {
		str := "stake store is closed"
		return nil, stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.dumpSSRtxHashes()
}

// dumpSSRtxTickets fetches the entire list of tickets spent as revocations
// byt this wallet.
func (s *StakeStore) dumpSSRtxTickets() ([]chainhash.Hash, error) {
	var ticketList []chainhash.Hash

	err := s.namespace.View(func(tx walletdb.Tx) error {
		var errForEach error

		// Open the revocation records database.
		bucket := tx.RootBucket().Bucket(ssrtxRecordsBucketName)

		// Store each hash sequentially.
		errForEach = bucket.ForEach(func(k []byte, v []byte) error {
			ticket, errDeser := chainhash.NewHash(k)
			if errDeser != nil {
				return errDeser
			}

			ticketList = append(ticketList, *ticket)
			return nil
		})

		return errForEach
	})
	if err != nil {
		return nil, err
	}

	return ticketList, nil
}

// DumpSSRtxTickets is the exported version of dumpSSRtxTickets that is safe
// for concurrent access.
func (s *StakeStore) DumpSSRtxTickets() ([]chainhash.Hash, error) {
	if s.isClosed {
		str := "stake store is closed"
		return nil, stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.dumpSSRtxTickets()
}

// A function to get a single owned SStx.
func (s *StakeStore) getSStx(hash *chainhash.Hash) (*sstxRecord, error) {
	var record *sstxRecord

	// Access the database and store the result locally.
	err := s.namespace.View(func(tx walletdb.Tx) error {
		var err error
		record, err = fetchSStxRecord(tx, hash)

		return err
	})
	if err != nil {
		return nil, err
	}

	return record, nil
}

// insertSSGen inserts an SSGen record into the DB (keyed to the SStx it
// spends.
func (s *StakeStore) insertSSGen(blockHash *chainhash.Hash, blockHeight int64,
	ssgenHash *chainhash.Hash, voteBits uint16, sstxHash *chainhash.Hash) error {

	if blockHeight <= 0 {
		return fmt.Errorf("invalid SSGen block height")
	}

	record := &ssgenRecord{
		*blockHash,
		uint32(blockHeight),
		*ssgenHash,
		voteBits,
		time.Now(),
	}

	// Add the SSGen to the database.
	err := s.namespace.Update(func(tx walletdb.Tx) error {
		if putErr := putSSGenRecord(tx, sstxHash, record); putErr != nil {
			return putErr
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// InsertSSGen is the exported version of insertSSGen that is safe for
// concurrent access.
func (s *StakeStore) InsertSSGen(blockHash *chainhash.Hash, blockHeight int64,
	ssgenHash *chainhash.Hash, voteBits uint16, sstxHash *chainhash.Hash) error {
	if s.isClosed {
		str := "stake store is closed"
		return stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.insertSSGen(blockHash, blockHeight, ssgenHash, voteBits, sstxHash)
}

// getSSGens gets a list of SSGens that have been generated for some stake
// ticket.
func (s *StakeStore) getSSGens(sstxHash *chainhash.Hash) ([]*ssgenRecord, error) {
	var records []*ssgenRecord

	// Access the database and store the result locally.
	err := s.namespace.View(func(tx walletdb.Tx) error {
		var err error
		records, err = fetchSSGenRecords(tx, sstxHash)

		return err
	})
	if err != nil {
		return nil, err
	}

	return records, nil
}

// SendRawTransaction sends a raw transaction using the chainSvr.
// TODO Shouldn't this be locked? Eventually import the mutex lock
// from wallet maybe.
func (s *StakeStore) SendRawTransaction(msgTx *wire.MsgTx) (*chainhash.Hash,
	error) {
	if s.isClosed {
		str := "stake store is closed"
		return nil, stakeStoreError(ErrStoreClosed, str, nil)
	}

	if s.chainSvr != nil {
		return s.chainSvr.SendRawTransaction(msgTx, false)
	}

	return nil, fmt.Errorf("cannot sendrawtranscation, client not " +
		"initialized")
}

// SignVRTransaction signs a vote (SSGen) or revocation (SSRtx)
// transaction. isSSGen indicates if it is an SSGen; if it's not,
// it's an SSRtx.
func (s *StakeStore) SignVRTransaction(msgTx *wire.MsgTx, sstx *dcrutil.Tx,
	isSSGen bool) error {
	if s.isClosed {
		str := "stake store is closed"
		return stakeStoreError(ErrStoreClosed, str, nil)
	}

	txInNumToSign := 0
	hashType := txscript.SigHashAll

	if isSSGen {
		// For an SSGen tx, skip the first input as it is a stake base
		// and doesn't need to be signed.
		msgTx.TxIn[0].SignatureScript = s.Params.StakeBaseSigScript
		txInNumToSign = 1
	}

	// Get the script for the OP_SSTX tagged output that we need
	// to sign.
	sstxOutScript := sstx.MsgTx().TxOut[0].PkScript

	// Set up our callbacks that we pass to dcrscript so it can
	// look up the appropriate keys and scripts by address.
	getKey := txscript.KeyClosure(func(addr dcrutil.Address) (
		chainec.PrivateKey, bool, error) {
		address, err := s.Manager.Address(addr)
		if err != nil {
			return nil, false, err
		}

		pka, ok := address.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return nil, false, fmt.Errorf("address is not " +
				"a pubkey address")
		}

		key, err := pka.PrivKey()
		if err != nil {
			return nil, false, err
		}

		return key, pka.Compressed(), nil
	})

	getScript := txscript.ScriptClosure(func(
		addr dcrutil.Address) ([]byte, error) {
		address, err := s.Manager.Address(addr)
		if err != nil {
			return nil, err
		}
		sa, ok := address.(waddrmgr.ManagedScriptAddress)
		if !ok {
			return nil, fmt.Errorf("address is not a script" +
				" address")
		}

		return sa.Script()
	})

	// Attempt to generate the signed txin.
	signedScript, err := txscript.SignTxOutput(s.Params,
		msgTx,
		txInNumToSign,
		sstxOutScript,
		hashType,
		getKey,
		getScript,
		msgTx.TxIn[txInNumToSign].SignatureScript,
		chainec.ECTypeSecp256k1)
	if err != nil {
		return fmt.Errorf("failed to sign ssgen or "+
			"ssrtx, error: %v", err.Error())
	}

	msgTx.TxIn[txInNumToSign].SignatureScript = signedScript

	// Either it was already signed or we just signed it.
	// Find out if it is completely satisfied or still needs more.
	// Decred: Needed??
	flags := txscript.ScriptBip16
	engine, err := txscript.NewEngine(sstxOutScript,
		msgTx,
		txInNumToSign,
		flags,
		txscript.DefaultScriptVersion)
	if err != nil {
		return fmt.Errorf("failed to generate signature script engine for "+
			"ssgen or ssrtx, error: %v", err.Error())
	}
	err = engine.Execute()
	if err != nil {
		return fmt.Errorf("failed to generate correct signature script for "+
			"ssgen or ssrtx: %v", err.Error())
	}

	return nil
}

// GenerateVote creates a new SSGen given a header hash, height, sstx
// tx hash, and votebits.
func (s *StakeStore) generateVote(blockHash *chainhash.Hash, height int64,
	sstxHash *chainhash.Hash, defaultVoteBits uint16) (*StakeNotification, error) {
	// 1. Fetch the SStx, then calculate all the values we'll need later for
	// the generation of the SSGen tx outputs.
	sstxRecord, err := s.getSStx(sstxHash)
	if err != nil {
		return nil, err
	}
	sstx := sstxRecord.tx
	sstxMsgTx := sstx.MsgTx()

	// The legacy wallet didn't store anything about the voteBits to use.
	// In the case we're loading a legacy wallet and the voteBits are
	// unset, just use the default voteBits as set by the user.
	voteBits := defaultVoteBits
	if sstxRecord.voteBitsSet {
		voteBits = sstxRecord.voteBits
	}

	// Store the sstx pubkeyhashes and amounts as found in the transaction
	// outputs.
	// TODO Get information on the allowable fee range for the vote
	// and check to make sure we don't overflow that.
	ssgenPayTypes, ssgenPkhs, sstxAmts, _, _, _ :=
		stake.GetSStxStakeOutputInfo(sstx)

	// Get the current reward.
	stakeVoteSubsidy := blockchain.CalcStakeVoteSubsidy(height,
		s.Params)

	// Calculate the output values from this data.
	ssgenCalcAmts := stake.GetStakeRewards(sstxAmts,
		sstxMsgTx.TxOut[0].Value,
		stakeVoteSubsidy)

	// 2. Add all transaction inputs to a new transaction after performing
	// some validity checks. First, add the stake base, then the OP_SSTX
	// tagged output.
	msgTx := wire.NewMsgTx()

	// Stakebase.
	stakeBaseOutPoint := wire.NewOutPoint(&chainhash.Hash{},
		uint32(0xFFFFFFFF),
		dcrutil.TxTreeRegular)
	txInStakeBase := wire.NewTxIn(stakeBaseOutPoint, []byte{})
	msgTx.AddTxIn(txInStakeBase)

	// Add the subsidy amount into the input.
	msgTx.TxIn[0].ValueIn = stakeVoteSubsidy

	// SStx tagged output as an OutPoint.
	prevOut := wire.NewOutPoint(sstxHash,
		0, // Index 0
		1) // Tree stake
	txIn := wire.NewTxIn(prevOut, []byte{})
	msgTx.AddTxIn(txIn)

	// 3. Add the OP_RETURN null data pushes of the block header hash,
	// the block height, and votebits, then add all the OP_SSGEN tagged
	// outputs.
	//
	// Block reference output.
	blockRefScript, err := txscript.GenerateSSGenBlockRef(*blockHash,
		uint32(height))
	if err != nil {
		return nil, err
	}
	blockRefOut := wire.NewTxOut(0, blockRefScript)
	msgTx.AddTxOut(blockRefOut)

	// Votebits output.
	blockVBScript, err := txscript.GenerateSSGenVotes(voteBits)
	if err != nil {
		return nil, err
	}
	blockVBOut := wire.NewTxOut(0, blockVBScript)
	msgTx.AddTxOut(blockVBOut)

	// Add all the SSGen-tagged transaction outputs to the transaction after
	// performing some validity checks.
	for i, ssgenPkh := range ssgenPkhs {
		// Create a new script which pays to the provided address specified in
		// the original ticket tx.
		var ssgenOutScript []byte
		switch ssgenPayTypes[i] {
		case false: // P2PKH
			ssgenOutScript, err = txscript.PayToSSGenPKHDirect(ssgenPkh)
			if err != nil {
				return nil, err
			}
		case true: // P2SH
			ssgenOutScript, err = txscript.PayToSSGenSHDirect(ssgenPkh)
			if err != nil {
				return nil, err
			}
		}

		// Add the txout to our SSGen tx.
		txOut := wire.NewTxOut(ssgenCalcAmts[i], ssgenOutScript)

		msgTx.AddTxOut(txOut)
	}

	// Check to make sure our SSGen was created correctly.
	ssgenTx := dcrutil.NewTx(msgTx)
	ssgenTx.SetTree(dcrutil.TxTreeStake)
	_, err = stake.IsSSGen(ssgenTx)
	if err != nil {
		return nil, err
	}

	// Sign the transaction.
	err = s.SignVRTransaction(msgTx, sstx, true)
	if err != nil {
		return nil, err
	}

	// Store the information about the SSGen.
	err = s.insertSSGen(blockHash,
		height,
		ssgenTx.Sha(),
		voteBits,
		sstx.Sha())
	if err != nil {
		return nil, err
	}

	// Send the transaction.
	ssgenSha, err := s.chainSvr.SendRawTransaction(msgTx, false)
	if err != nil {
		return nil, err
	}

	log.Debugf("Generated SSGen %v, voting on block %v at height %v. "+
		"The ticket used to generate the SSGen was %v.",
		ssgenSha, blockHash, height, sstxHash)

	// Generate a notification to return.
	ntfn := &StakeNotification{
		TxType:    int8(stake.TxTypeSSGen),
		TxHash:    *ssgenSha,
		BlockHash: *blockHash,
		Height:    int32(height),
		Amount:    0,
		SStxIn:    *sstx.Sha(),
		VoteBits:  voteBits,
	}

	return ntfn, nil
}

// insertSSRtx inserts an SSRtx record into the DB (keyed to the SStx it
// spends.
func (s *StakeStore) insertSSRtx(blockHash *chainhash.Hash, blockHeight int64,
	ssrtxHash *chainhash.Hash, sstxHash *chainhash.Hash) error {
	if blockHeight <= 0 {
		return fmt.Errorf("invalid SSRtx block height")
	}

	record := &ssrtxRecord{
		*blockHash,
		uint32(blockHeight),
		*ssrtxHash,
		time.Now(),
	}

	// Add the SSRtx to the database.
	err := s.namespace.Update(func(tx walletdb.Tx) error {
		if putErr := putSSRtxRecord(tx, sstxHash, record); putErr != nil {
			return putErr
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// InsertSSRtx is the exported version of insertSSRtx that is safe for
// concurrent access.
func (s *StakeStore) InsertSSRtx(blockHash *chainhash.Hash, blockHeight int64,
	ssrtxHash *chainhash.Hash, sstxHash *chainhash.Hash) error {
	if s.isClosed {
		str := "stake store is closed"
		return stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.insertSSRtx(blockHash, blockHeight, ssrtxHash, sstxHash)
}

// GetSSRtxs gets a list of SSRtxs that have been generated for some stake
// ticket.
func (s *StakeStore) getSSRtxs(sstxHash *chainhash.Hash) ([]*ssrtxRecord, error) {
	var records []*ssrtxRecord

	// Access the database and store the result locally.
	err := s.namespace.View(func(tx walletdb.Tx) error {
		var err error
		records, err = fetchSSRtxRecords(tx, sstxHash)

		return err
	})
	if err != nil {
		return nil, err
	}

	return records, nil
}

// GenerateRevocation generates a revocation (SSRtx), signs it, and
// submits it by SendRawTransaction. It also stores a record of it
// in the local database.
func (s *StakeStore) generateRevocation(blockHash *chainhash.Hash, height int64,
	sstxHash *chainhash.Hash) (*StakeNotification, error) {
	var revocationFee int64
	switch {
	case s.Params == &chaincfg.MainNetParams:
		revocationFee = revocationFeeMainNet
	case s.Params == &chaincfg.TestNetParams:
		revocationFee = revocationFeeTestNet
	default:
		revocationFee = revocationFeeTestNet
	}

	// 1. Fetch the SStx, then calculate all the values we'll need later for
	// the generation of the SSRtx tx outputs.
	sstxRecord, err := s.getSStx(sstxHash)
	if err != nil {
		return nil, err
	}
	sstx := sstxRecord.tx

	// Store the sstx pubkeyhashes and amounts as found in the transaction
	// outputs.
	// TODO Get information on the allowable fee range for the revocation
	// and check to make sure we don't overflow that.
	sstxPayTypes, sstxPkhs, sstxAmts, _, _, _ :=
		stake.GetSStxStakeOutputInfo(sstx)

	ssrtxCalcAmts := stake.GetStakeRewards(sstxAmts, sstx.MsgTx().TxOut[0].Value,
		int64(0))

	// 2. Add the only input.
	msgTx := wire.NewMsgTx()

	// SStx tagged output as an OutPoint; reference this as
	// the only input.
	prevOut := wire.NewOutPoint(sstxHash,
		0, // Index 0
		1) // Tree stake
	txIn := wire.NewTxIn(prevOut, []byte{})
	msgTx.AddTxIn(txIn)

	// 3. Add all the OP_SSRTX tagged outputs.

	// Add all the SSRtx-tagged transaction outputs to the transaction after
	// performing some validity checks.
	feeAdded := false
	for i, sstxPkh := range sstxPkhs {
		// Create a new script which pays to the provided address specified in
		// the original ticket tx.
		var ssrtxOutScript []byte
		switch sstxPayTypes[i] {
		case false: // P2PKH
			ssrtxOutScript, err = txscript.PayToSSRtxPKHDirect(sstxPkh)
			if err != nil {
				return nil, err
			}
		case true: // P2SH
			ssrtxOutScript, err = txscript.PayToSSRtxSHDirect(sstxPkh)
			if err != nil {
				return nil, err
			}
		}

		// Add a fee from an output that has enough.
		amt := ssrtxCalcAmts[i]
		if !feeAdded && ssrtxCalcAmts[i] >= revocationFee {
			amt -= revocationFee
			feeAdded = true
		}

		// Add the txout to our SSRtx tx.
		txOut := wire.NewTxOut(amt, ssrtxOutScript)
		msgTx.AddTxOut(txOut)
	}

	// Check to make sure our SSRtx was created correctly.
	ssrtxTx := dcrutil.NewTx(msgTx)
	ssrtxTx.SetTree(dcrutil.TxTreeStake)
	_, err = stake.IsSSRtx(ssrtxTx)
	if err != nil {
		return nil, err
	}

	// Sign the transaction.
	err = s.SignVRTransaction(msgTx, sstx, false)
	if err != nil {
		return nil, err
	}

	// Store the information about the SSRtx.
	err = s.insertSSRtx(blockHash,
		height,
		ssrtxTx.Sha(),
		sstx.Sha())
	if err != nil {
		return nil, err
	}

	// Send the transaction.
	ssrtxSha, err := s.chainSvr.SendRawTransaction(msgTx, false)
	if err != nil {
		return nil, err
	}

	log.Debugf("Generated SSRtx %v. The ticket used to "+
		"generate the SSRtx was %v.", ssrtxSha, sstx.Sha())

	// Generate a notification to return.
	ntfn := &StakeNotification{
		TxType:    int8(stake.TxTypeSSRtx),
		TxHash:    *ssrtxSha,
		BlockHash: chainhash.Hash{},
		Height:    0,
		Amount:    0,
		SStxIn:    *sstx.Sha(),
		VoteBits:  0,
	}

	return ntfn, nil
}

// HandleWinningTicketsNtfn scans the list of eligible tickets and, if any
// of these tickets in the sstx store match these tickets, spends them as
// votes.
func (s StakeStore) HandleWinningTicketsNtfn(blockHash *chainhash.Hash,
	blockHeight int64,
	tickets []*chainhash.Hash,
	defaultVoteBits uint16) ([]*StakeNotification, error) {
	if s.isClosed {
		str := "stake store is closed"
		return nil, stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Go through the list of tickets and see any of the
	// ones we own match those eligible.
	var ticketsToPull []*chainhash.Hash

	// Lock the mutex because checkHashInStore touches
	// a mutable element of StakeStore s.
	for _, ticket := range tickets {
		if s.checkHashInStore(ticket) {
			ticketsToPull = append(ticketsToPull, ticket)
		}
	}

	// No matching tickets (boo!), return.
	if len(ticketsToPull) == 0 {
		return nil, nil
	}

	ntfns := make([]*StakeNotification, len(ticketsToPull), len(ticketsToPull))
	voteErrors := make([]error, len(ticketsToPull), len(ticketsToPull))
	// Matching tickets (yay!), generate some SSGen.
	for i, ticket := range ticketsToPull {
		ntfns[i], voteErrors[i] = s.generateVote(blockHash, blockHeight, ticket,
			defaultVoteBits)
	}

	errStr := ""
	for i, err := range voteErrors {
		if err != nil {
			errStr += fmt.Sprintf("Error encountered attempting to create "+
				"vote using ticket %v: ", ticketsToPull[i])
			errStr += err.Error()
			errStr += "\n"
		}
	}

	if errStr != "" {
		return nil, fmt.Errorf("%v", errStr)
	}

	return ntfns, nil
}

// HandleMissedTicketsNtfn scans the list of missed tickets and, if any
// of these tickets in the sstx store match these tickets, spends them as
// SSRtx.
func (s StakeStore) HandleMissedTicketsNtfn(blockHash *chainhash.Hash,
	blockHeight int64,
	tickets []*chainhash.Hash) ([]*StakeNotification, error) {
	if s.isClosed {
		str := "stake store is closed"
		return nil, stakeStoreError(ErrStoreClosed, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Go through the list of tickets and see any of the
	// ones we own match those eligible.
	var ticketsToPull []*chainhash.Hash

	// Lock the mutex because checkHashInStore touches
	// a mutable element of StakeStore s.
	for _, ticket := range tickets {
		if s.checkHashInStore(ticket) {
			ticketsToPull = append(ticketsToPull, ticket)
		}
	}

	// No matching tickets, return.
	if len(ticketsToPull) == 0 {
		return nil, nil
	}

	ntfns := make([]*StakeNotification, len(ticketsToPull), len(ticketsToPull))
	revocationErrors := make([]error, len(ticketsToPull), len(ticketsToPull))
	// Matching tickets, generate some SSRtx.
	for i, ticket := range ticketsToPull {
		ntfns[i], revocationErrors[i] = s.generateRevocation(blockHash,
			blockHeight, ticket)
	}

	errStr := ""
	for i, err := range revocationErrors {
		if err != nil {
			errStr += fmt.Sprintf("Error encountered attempting to create "+
				"revocation using ticket %v: ", ticketsToPull[i])
			errStr += err.Error()
			errStr += "\n"
		}
	}

	if errStr != "" {
		return nil, fmt.Errorf("%v", errStr)
	}

	return ntfns, nil
}

// updateStakePoolUserTickets updates a stake pool ticket for a given user.
// If the ticket does not currently exist in the database, it adds it. If it
// does exist (the ticket hash exists), it replaces the old record.
func (s *StakeStore) updateStakePoolUserTickets(user dcrutil.Address,
	ticket *PoolTicket) error {
	_, isScriptHash := user.(*dcrutil.AddressScriptHash)
	_, isP2PKH := user.(*dcrutil.AddressPubKeyHash)
	if !(isScriptHash || isP2PKH) {
		str := fmt.Sprintf("user %v is invalid", user.EncodeAddress())
		return stakeStoreError(ErrBadPoolUserAddr, str, nil)
	}
	scriptHashB := user.ScriptAddress()
	scriptHash := new([20]byte)
	copy(scriptHash[:], scriptHashB)

	err := s.namespace.Update(func(tx walletdb.Tx) error {
		if updErr := updateStakePoolUserTickets(tx, *scriptHash,
			ticket); updErr != nil {
			return updErr
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// UpdateStakePoolUserTickets is the exported and concurrency safe form of
// updateStakePoolUserTickets.
func (s *StakeStore) UpdateStakePoolUserTickets(user dcrutil.Address,
	ticket *PoolTicket) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.updateStakePoolUserTickets(user, ticket)
}

// updateStakePoolUserInvalTickets updates the list of invalid stake pool
// tickets for a given user. If the ticket does not currently exist in the
// database, it adds it.
func (s *StakeStore) updateStakePoolUserInvalTickets(user dcrutil.Address,
	ticket *chainhash.Hash) error {
	_, isScriptHash := user.(*dcrutil.AddressScriptHash)
	_, isP2PKH := user.(*dcrutil.AddressPubKeyHash)
	if !(isScriptHash || isP2PKH) {
		str := fmt.Sprintf("user %v is invalid", user.EncodeAddress())
		return stakeStoreError(ErrBadPoolUserAddr, str, nil)
	}
	scriptHashB := user.ScriptAddress()
	scriptHash := new([20]byte)
	copy(scriptHash[:], scriptHashB)

	err := s.namespace.Update(func(tx walletdb.Tx) error {
		if updErr := updateStakePoolInvalUserTickets(tx, *scriptHash,
			ticket); updErr != nil {
			return updErr
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// UpdateStakePoolUserInvalTickets is the exported and concurrency safe form of
// updateStakePoolUserInvalTickets.
func (s *StakeStore) UpdateStakePoolUserInvalTickets(user dcrutil.Address,
	ticket *chainhash.Hash) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.updateStakePoolUserInvalTickets(user, ticket)
}

// stakePoolUserInfo returns the stake pool user information for a given stake
// pool user, keyed to their P2SH voting address.
func (s *StakeStore) stakePoolUserInfo(user dcrutil.Address) (*StakePoolUser,
	error) {
	_, isScriptHash := user.(*dcrutil.AddressScriptHash)
	_, isP2PKH := user.(*dcrutil.AddressPubKeyHash)
	if !(isScriptHash || isP2PKH) {
		str := fmt.Sprintf("user %v is invalid", user.EncodeAddress())
		return nil, stakeStoreError(ErrBadPoolUserAddr, str, nil)
	}
	scriptHashB := user.ScriptAddress()
	scriptHash := new([20]byte)
	copy(scriptHash[:], scriptHashB)

	stakePoolUser := new(StakePoolUser)

	err := s.namespace.View(func(tx walletdb.Tx) error {
		// Catch missing user errors below and blank out the stake
		// pool user information for the section if the user has
		// no entries.
		missingValidTickets, missingInvalidTickets := false, false

		userTickets, fetchErrVal := fetchStakePoolUserTickets(tx, *scriptHash)
		if fetchErrVal != nil {
			stakeMgrErr, is := fetchErrVal.(StakeStoreError)
			if is {
				missingValidTickets = stakeMgrErr.ErrorCode ==
					ErrPoolUserTicketsNotFound
			} else {
				return fetchErrVal
			}
		}
		if missingValidTickets {
			userTickets = make([]*PoolTicket, 0)
		}

		invalTickets, fetchErrInval := fetchStakePoolUserInvalTickets(tx,
			*scriptHash)
		if fetchErrInval != nil {
			stakeMgrErr, is := fetchErrInval.(StakeStoreError)
			if is {
				missingInvalidTickets = stakeMgrErr.ErrorCode ==
					ErrPoolUserInvalTcktsNotFound
			} else {
				return fetchErrInval
			}
		}
		if missingInvalidTickets {
			invalTickets = make([]*chainhash.Hash, 0)
		}

		stakePoolUser.Tickets = userTickets
		stakePoolUser.InvalidTickets = invalTickets

		return nil
	})
	if err != nil {
		return nil, err
	}

	return stakePoolUser, nil
}

// StakePoolUserInfo is the exported and concurrency safe form of
// stakePoolUserInfo.
func (s *StakeStore) StakePoolUserInfo(user dcrutil.Address) (*StakePoolUser,
	error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	return s.stakePoolUserInfo(user)
}

// loadManager returns a new stake manager that results from loading it from
// the passed opened database.  The public passphrase is required to decrypt the
// public keys.
func (s *StakeStore) loadOwnedSStxs(namespace walletdb.Namespace) error {
	// Regenerate the list of tickets.
	// Perform all database lookups in a read-only view.
	ticketList := make(map[chainhash.Hash]struct{})

	err := namespace.View(func(tx walletdb.Tx) error {
		var errForEach error

		// Open the sstx records database.
		bucket := tx.RootBucket().Bucket(sstxRecordsBucketName)

		// Store each key sequentially.
		errForEach = bucket.ForEach(func(k []byte, v []byte) error {
			var errNewHash error
			var hash *chainhash.Hash

			hash, errNewHash = chainhash.NewHash(k)
			if errNewHash != nil {
				return errNewHash
			}
			ticketList[*hash] = struct{}{}
			return nil
		})

		return errForEach
	})
	if err != nil {
		return err
	}

	s.ownedSStxs = ticketList
	return nil
}

// SetChainSvr is used to set the chainSvr to a given pointer. Should
// be called after chainSvr is initialized in wallet.
func (s *StakeStore) SetChainSvr(chainSvr *walletchain.RPCClient) {
	s.chainSvr = chainSvr
}

// newStakeStore initializes a new stake store with the given parameters.
func newStakeStore(namespace walletdb.Namespace, params *chaincfg.Params,
	manager *waddrmgr.Manager) *StakeStore {
	var mtx = &sync.Mutex{}

	return &StakeStore{
		mtx:        mtx,
		namespace:  namespace,
		Params:     params,
		Manager:    manager,
		chainSvr:   nil,
		isClosed:   false,
		ownedSStxs: make(map[chainhash.Hash]struct{}),
	}
}

// Open loads an existing stake manager from the given namespace, waddrmgr, and
// network parameters.
//
// A ManagerError with an error code of ErrNoExist will be returned if the
// passed manager does not exist in the specified namespace.
func Open(namespace walletdb.Namespace, manager *waddrmgr.Manager,
	params *chaincfg.Params) (*StakeStore, error) {
	// Return an error if the manager has NOT already been created in the
	// given database namespace.
	exists, err := stakeStoreExists(namespace)
	if err != nil {
		return nil, err
	}
	if !exists {
		str := "the specified stake store/manager does not exist in db"
		return nil, stakeStoreError(ErrNoExist, str, nil)
	}

	ss := newStakeStore(namespace, params, manager)

	err = ss.loadOwnedSStxs(namespace)
	if err != nil {
		return nil, err
	}

	return ss, nil
}

// Create creates a new persistent stake manager in the passed database namespace.
// A ManagerError with an error code of ErrAlreadyExists will be returned the
// address manager already exists in the specified namespace.
func Create(namespace walletdb.Namespace) error {
	// Return an error if the manager has already been created in the given
	// database namespace.
	exists, err := stakeStoreExists(namespace)
	if err != nil {
		return err
	}
	if exists {
		str := "error, stake store exists already"
		return stakeStoreError(ErrAlreadyExists, str, nil)
	}

	// Initialize the database for first use.
	return initializeEmpty(namespace)
}

// Close cleanly shuts down the stake store.
func (s *StakeStore) Close() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.isClosed = true
	return nil
}
