/*
 * Copyright (c) 2015 The btcsuite developers
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

package votingpool

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/btcsuite/fastsha256"
)

const (
	// Maximum tx size (in bytes). This should be the same as bitcoind's
	// MAX_STANDARD_TX_SIZE.
	txMaxSize = 100000

	// feeIncrement is the minimum transation fee (0.00001 BTC, measured in satoshis)
	// added to transactions requiring a fee.
	feeIncrement = 1e3

	outputStatusSuccess = "success"
	outputStatusSplit   = "split"
	outputStatusPartial = "partial"
)

// OutBailmentID is the unique ID of a user's outbailment, comprising the
// name of the server the user connected to, and the transaction number,
// internal to that server.
type OutBailmentID string

// Ntxid is the normalized ID of a given bitcoin transaction, which is generated
// by hashing the serialized tx with nil sig scripts on all inputs.
type Ntxid string

// OutputRequest represents one of the outputs (address/amount) requested by a
// withdrawal, and includes information about the user's outbailment request.
type OutputRequest struct {
	Address  btcutil.Address
	Amount   btcutil.Amount
	PkScript []byte

	// The notary server that received the outbailment request.
	Server string

	// The server-specific transaction number for the outbailment request.
	Transaction uint32

	// cachedHash is used to cache the hash of the outBailmentID so it
	// only has to be calculated once.
	cachedHash []byte
}

// WithdrawalOutput represents a possibly fulfilled OutputRequest.
type WithdrawalOutput struct {
	request OutputRequest
	status  string
	// The outpoints that fulfill the OutputRequest. There will be more than one in case we
	// need to split the request across multiple transactions.
	outpoints []OutBailmentOutpoint
}

// OutBailmentOutpoint represents one of the outpoints created to fulfill an OutputRequest.
type OutBailmentOutpoint struct {
	ntxid  Ntxid
	index  uint32
	amount btcutil.Amount
}

// changeAwareTx is a wrapper around wire.MsgTx that has some auxiliary data
// needed when processing voting pool withdrawals.
type changeAwareTx struct {
	*wire.MsgTx
	// The index of the tx's change output. -1 if there's no change output.
	changeIdx int32
	// A map allowing us to link each TxIn from this tx to the
	// WithdrawalAddress of the credit they spend.
	addrs map[wire.OutPoint]WithdrawalAddress
	// Has this transaction been broadcast yet?
	broadcast bool
}

// WithdrawalStatus contains the details of a processed withdrawal, including
// the status of each requested output, the total amount of network fees and the
// next input and change addresses to use in a subsequent withdrawal request.
type WithdrawalStatus struct {
	nextInputAddr  AddressIdentifier
	nextChangeAddr AddressIdentifier
	fees           btcutil.Amount
	outputs        map[OutBailmentID]*WithdrawalOutput
	sigs           map[Ntxid]TxSigs
	transactions   map[Ntxid]changeAwareTx
}

// withdrawalInfo contains all the details of an existing withdrawal, including
// the original request parameters and the WithdrawalStatus returned by
// StartWithdrawal.
type withdrawalInfo struct {
	requests      []OutputRequest
	startAddress  WithdrawalAddress
	changeStart   ChangeAddress
	lastSeriesID  uint32
	dustThreshold btcutil.Amount
	status        WithdrawalStatus
}

// TxSigs is a slice containing one element for each input of a given
// transaction.
type TxSigs []TxInSigs

// TxInSigs represents the raw signatures (one for every pubkey in the multi-sig
// script) for a given transaction input. They should match the order of pubkeys
// in the script and an empty RawSig should be used when the private key for a
// pubkey is not known.
type TxInSigs struct {
	Required uint32
	Sigs     []RawSig
}

func newTxInSigs(reqSigs uint32, length int) TxInSigs {
	sigs := make([]RawSig, length)
	for i := range sigs {
		sigs[i] = emptyRawSig
	}
	return TxInSigs{Required: reqSigs, Sigs: sigs}
}

// RawSig represents one of the signatures included in the unlocking script of
// inputs spending from P2SH UTXOs.
type RawSig []byte

var emptyRawSig = RawSig{}

// byAmount defines the methods needed to satisify sort.Interface to
// sort a slice of OutputRequests by their amount.
type byAmount []OutputRequest

func (u byAmount) Len() int           { return len(u) }
func (u byAmount) Less(i, j int) bool { return u[i].Amount < u[j].Amount }
func (u byAmount) Swap(i, j int)      { u[i], u[j] = u[j], u[i] }

// byOutBailmentID defines the methods needed to satisify sort.Interface to sort
// a slice of OutputRequests by their outBailmentIDHash.
type byOutBailmentID []OutputRequest

func (s byOutBailmentID) Len() int      { return len(s) }
func (s byOutBailmentID) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s byOutBailmentID) Less(i, j int) bool {
	return bytes.Compare(s[i].outBailmentIDHash(), s[j].outBailmentIDHash()) < 0
}

func (tx *changeAwareTx) addToStore(store *wtxmgr.Store) error {
	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx.MsgTx, time.Now())
	if err != nil {
		return newError(ErrWithdrawalTxStorage, "error constructing TxRecord for storing", err)
	}

	if err := store.InsertTx(rec, nil); err != nil {
		return newError(ErrWithdrawalTxStorage, "error adding tx to store", err)
	}
	if tx.changeIdx != -1 {
		if err = store.AddCredit(rec, nil, uint32(tx.changeIdx), true); err != nil {
			return newError(ErrWithdrawalTxStorage, "error adding tx credits to store", err)
		}
	}
	tx.broadcast = true
	return nil
}

// Outputs returns a map of outbailment IDs to WithdrawalOutputs for all outputs
// requested in this withdrawal.
func (s *WithdrawalStatus) Outputs() map[OutBailmentID]*WithdrawalOutput {
	return s.outputs
}

// Sigs returns a map of ntxids to signature lists for every input in the tx
// with that ntxid.
func (s *WithdrawalStatus) Sigs() map[Ntxid]TxSigs {
	return s.sigs
}

// Fees returns the total amount of network fees included in all transactions
// generated as part of a withdrawal.
func (s *WithdrawalStatus) Fees() btcutil.Amount {
	return s.fees
}

// NextInputAddr returns the votingpool address that should be used as the
// startAddress of subsequent withdrawals.
func (s *WithdrawalStatus) NextInputAddr() AddressIdentifier {
	return s.nextInputAddr
}

// NextChangeAddr returns the votingpool address that should be used as the
// changeStart of subsequent withdrawals.
func (s *WithdrawalStatus) NextChangeAddr() AddressIdentifier {
	return s.nextChangeAddr
}

// String makes OutputRequest satisfy the Stringer interface.
func (r OutputRequest) String() string {
	return fmt.Sprintf("OutputRequest %s to send %v to %s", r.outBailmentID(), r.Amount, r.Address)
}

func (r OutputRequest) outBailmentID() OutBailmentID {
	return OutBailmentID(fmt.Sprintf("%s:%d", r.Server, r.Transaction))
}

// outBailmentIDHash returns a byte slice which is used when sorting
// OutputRequests.
func (r OutputRequest) outBailmentIDHash() []byte {
	if r.cachedHash != nil {
		return r.cachedHash
	}
	str := r.Server + strconv.Itoa(int(r.Transaction))
	hasher := fastsha256.New()
	// hasher.Write() always returns nil as the error, so it's safe to ignore it here.
	_, _ = hasher.Write([]byte(str))
	id := hasher.Sum(nil)
	r.cachedHash = id
	return id
}

func (o *WithdrawalOutput) String() string {
	return fmt.Sprintf("WithdrawalOutput for %s", o.request)
}

func (o *WithdrawalOutput) addOutpoint(outpoint OutBailmentOutpoint) {
	o.outpoints = append(o.outpoints, outpoint)
}

// Status returns the status of this WithdrawalOutput.
func (o *WithdrawalOutput) Status() string {
	return o.status
}

// Address returns the string representation of this WithdrawalOutput's address.
func (o *WithdrawalOutput) Address() string {
	return o.request.Address.String()
}

// Outpoints returns a slice containing the OutBailmentOutpoints created to
// fulfill this output.
func (o *WithdrawalOutput) Outpoints() []OutBailmentOutpoint {
	return o.outpoints
}

// Amount returns the amount (in satoshis) in this OutBailmentOutpoint.
func (o OutBailmentOutpoint) Amount() btcutil.Amount {
	return o.amount
}

// withdrawal holds all the state needed for Pool.Withdrawal() to do its job.
type withdrawal struct {
	pool            *Pool
	roundID         uint32
	status          *WithdrawalStatus
	transactions    []*withdrawalTx
	pendingRequests []OutputRequest
	eligibleInputs  []credit
	current         *withdrawalTx
	nextChangeAddr  *ChangeAddress
	// txOptions is a function called for every new withdrawalTx created as
	// part of this withdrawal. It is defined as a function field because it
	// exists mainly so that tests can mock withdrawalTx fields.
	txOptions func(tx *withdrawalTx)
}

// withdrawalTxOut wraps an OutputRequest and provides a separate amount field.
// It is necessary because some requests may be partially fulfilled or split
// across transactions.
type withdrawalTxOut struct {
	// Notice that in the case of a split output, the OutputRequest here will
	// be a copy of the original one with the amount being the remainder of the
	// originally requested amount minus the amounts fulfilled by other
	// withdrawalTxOut. The original OutputRequest, if needed, can be obtained
	// from WithdrawalStatus.outputs.
	request OutputRequest
	amount  btcutil.Amount
}

// String makes withdrawalTxOut satisfy the Stringer interface.
func (o *withdrawalTxOut) String() string {
	return fmt.Sprintf("withdrawalTxOut fulfilling %v of %s", o.amount, o.request)
}

func (o *withdrawalTxOut) pkScript() []byte {
	return o.request.PkScript
}

// withdrawalTx represents a transaction constructed by the withdrawal process.
type withdrawalTx struct {
	inputs  []credit
	outputs []*withdrawalTxOut
	fee     btcutil.Amount

	// changeOutput holds information about the change for this transaction.
	changeOutput *wire.TxOut

	// calculateSize returns the estimated serialized size (in bytes) of this
	// tx. See calculateTxSize() for details on how that's done. We use a
	// struct field instead of a method so that it can be replaced in tests.
	calculateSize func() int
	// calculateFee calculates the expected network fees for this tx. We use a
	// struct field instead of a method so that it can be replaced in tests.
	calculateFee func() btcutil.Amount
}

// newWithdrawalTx creates a new withdrawalTx and calls setOptions()
// passing the newly created tx.
func newWithdrawalTx(setOptions func(tx *withdrawalTx)) *withdrawalTx {
	tx := &withdrawalTx{}
	tx.calculateSize = func() int { return calculateTxSize(tx) }
	tx.calculateFee = func() btcutil.Amount {
		return btcutil.Amount(1+tx.calculateSize()/1000) * feeIncrement
	}
	setOptions(tx)
	return tx
}

// ntxid returns the unique ID for this transaction.
func (tx *withdrawalTx) ntxid() Ntxid {
	msgtx := tx.toMsgTx()
	for _, txin := range msgtx.TxIn {
		txin.SignatureScript = nil
	}
	return Ntxid(msgtx.TxSha().String())
}

// isTooBig returns true if the size (in bytes) of the given tx is greater
// than or equal to txMaxSize.
func (tx *withdrawalTx) isTooBig() bool {
	// In bitcoind a tx is considered standard only if smaller than
	// MAX_STANDARD_TX_SIZE; that's why we consider anything >= txMaxSize to
	// be too big.
	return tx.calculateSize() >= txMaxSize
}

// inputTotal returns the sum amount of all inputs in this tx.
func (tx *withdrawalTx) inputTotal() (total btcutil.Amount) {
	for _, input := range tx.inputs {
		total += input.Amount
	}
	return total
}

// outputTotal returns the sum amount of all outputs in this tx. It does not
// include the amount for the change output, in case the tx has one.
func (tx *withdrawalTx) outputTotal() (total btcutil.Amount) {
	for _, output := range tx.outputs {
		total += output.amount
	}
	return total
}

// hasChange returns true if this transaction has a change output.
func (tx *withdrawalTx) hasChange() bool {
	return tx.changeOutput != nil
}

// toMsgTx generates a btcwire.MsgTx with this tx's inputs and outputs.
func (tx *withdrawalTx) toMsgTx() *wire.MsgTx {
	msgtx := wire.NewMsgTx()
	for _, o := range tx.outputs {
		msgtx.AddTxOut(wire.NewTxOut(int64(o.amount), o.pkScript()))
	}

	if tx.hasChange() {
		msgtx.AddTxOut(tx.changeOutput)
	}

	for _, i := range tx.inputs {
		msgtx.AddTxIn(wire.NewTxIn(&i.OutPoint, []byte{}))
	}
	return msgtx
}

// addOutput adds a new output to this transaction.
func (tx *withdrawalTx) addOutput(request OutputRequest) {
	log.Debugf("Added tx output sending %s to %s", request.Amount, request.Address)
	tx.outputs = append(tx.outputs, &withdrawalTxOut{request: request, amount: request.Amount})
}

// removeOutput removes the last added output and returns it.
func (tx *withdrawalTx) removeOutput() *withdrawalTxOut {
	removed := tx.outputs[len(tx.outputs)-1]
	tx.outputs = tx.outputs[:len(tx.outputs)-1]
	log.Debugf("Removed tx output sending %s to %s", removed.amount, removed.request.Address)
	return removed
}

// addInput adds a new input to this transaction.
func (tx *withdrawalTx) addInput(input credit) {
	log.Debugf("Added tx input with amount %v", input.Amount)
	tx.inputs = append(tx.inputs, input)
}

// removeInput removes the last added input and returns it.
func (tx *withdrawalTx) removeInput() credit {
	removed := tx.inputs[len(tx.inputs)-1]
	tx.inputs = tx.inputs[:len(tx.inputs)-1]
	log.Debugf("Removed tx input with amount %v", removed.Amount)
	return removed
}

// addChange adds a change output if there are any satoshis left after paying
// all the outputs and network fees. It returns true if a change output was
// added.
//
// This method must be called only once, and no extra inputs/outputs should be
// added after it's called. Also, callsites must make sure adding a change
// output won't cause the tx to exceed the size limit.
func (tx *withdrawalTx) addChange(pkScript []byte) bool {
	tx.fee = tx.calculateFee()
	change := tx.inputTotal() - tx.outputTotal() - tx.fee
	log.Debugf("addChange: input total %v, output total %v, fee %v", tx.inputTotal(),
		tx.outputTotal(), tx.fee)
	if change > 0 {
		tx.changeOutput = wire.NewTxOut(int64(change), pkScript)
		log.Debugf("Added change output with amount %v", change)
	}
	return tx.hasChange()
}

// rollBackLastOutput will roll back the last added output and possibly remove
// inputs that are no longer needed to cover the remaining outputs. The method
// returns the removed output and the removed inputs, in the reverse order they
// were added, if any.
//
// The tx needs to have two or more outputs. The case with only one output must
// be handled separately (by the split output procedure).
func (tx *withdrawalTx) rollBackLastOutput() ([]credit, *withdrawalTxOut, error) {
	// Check precondition: At least two outputs are required in the transaction.
	if len(tx.outputs) < 2 {
		str := fmt.Sprintf("at least two outputs expected; got %d", len(tx.outputs))
		return nil, nil, newError(ErrPreconditionNotMet, str, nil)
	}

	removedOutput := tx.removeOutput()

	var removedInputs []credit
	// Continue until sum(in) < sum(out) + fee
	for tx.inputTotal() >= tx.outputTotal()+tx.calculateFee() {
		removedInputs = append(removedInputs, tx.removeInput())
	}

	// Re-add the last item from removedInputs, which is the last popped input.
	tx.addInput(removedInputs[len(removedInputs)-1])
	removedInputs = removedInputs[:len(removedInputs)-1]
	return removedInputs, removedOutput, nil
}

func defaultTxOptions(tx *withdrawalTx) {}

func newWithdrawal(pool *Pool, roundID uint32, requests []OutputRequest, inputs []credit,
	changeStart ChangeAddress) *withdrawal {
	outputs := make(map[OutBailmentID]*WithdrawalOutput, len(requests))
	for _, request := range requests {
		outputs[request.outBailmentID()] = &WithdrawalOutput{request: request}
	}
	status := &WithdrawalStatus{
		outputs:        outputs,
		nextChangeAddr: changeStart,
	}
	return &withdrawal{
		pool:            pool,
		roundID:         roundID,
		pendingRequests: requests,
		eligibleInputs:  inputs,
		status:          status,
		txOptions:       defaultTxOptions,
		nextChangeAddr:  &changeStart,
	}
}

// StartWithdrawal uses a fully deterministic algorithm to construct
// transactions fulfilling as many of the given output requests as possible.
// It returns a WithdrawalStatus containing the outpoints fulfilling the
// requested outputs and a map of normalized transaction IDs (ntxid) to
// signature lists (one for every private key available to this wallet) for each
// of those transaction's inputs. More details about the actual algorithm can be
// found at http://opentransactions.org/wiki/index.php/Startwithdrawal
// This method must be called with the address manager unlocked.
func (p *Pool) StartWithdrawal(roundID uint32, requests []OutputRequest,
	startAddress WithdrawalAddress, lastSeriesID uint32, changeStart ChangeAddress,
	dustThreshold btcutil.Amount, minConf int, txStore *wtxmgr.Store) (*WithdrawalStatus, error) {

	status, err := getWithdrawalStatusMatching(p, roundID, requests, startAddress, lastSeriesID,
		changeStart, dustThreshold)
	if err != nil {
		return nil, err
	}
	if status != nil {
		return status, nil
	}

	return p.fulfillAndSaveWithdrawal(roundID, requests, startAddress, lastSeriesID, changeStart,
		dustThreshold, minConf, txStore)
}

func (p *Pool) fulfillAndSaveWithdrawal(roundID uint32, requests []OutputRequest,
	startAddress WithdrawalAddress, lastSeriesID uint32, changeStart ChangeAddress,
	dustThreshold btcutil.Amount, minConf int, store *wtxmgr.Store) (*WithdrawalStatus, error) {
	eligible, err := p.getEligibleInputs(store, startAddress, lastSeriesID, dustThreshold, minConf)
	if err != nil {
		return nil, err
	}

	w := newWithdrawal(p, roundID, requests, eligible, changeStart)
	if err = w.fulfillRequests(); err != nil {
		return nil, err
	}
	if err = w.updateOutputsStatusAndNextInputAddr(lastSeriesID, dustThreshold, minConf, store); err != nil {
		return nil, err
	}
	w.status.sigs, err = getRawSigs(w.status.transactions)
	if err != nil {
		return nil, err
	}
	err = p.saveWithdrawal(roundID, requests, startAddress, lastSeriesID, changeStart,
		dustThreshold, *w.status)
	if err != nil {
		return nil, err
	}
	return w.status, nil
}

// UpdateWithdrawal looks up the information from the withdrawal with the given
// roundID, merges the existing signature lists with the given ones, broadcasts
// all transactions that can be signed (i.e. for which we have the minimum
// number of signatures) and that haven't been broadcast yet, and finally saves
// the updated withdrawal information in the database.
// It must be called with the address manager unlocked.
func (p *Pool) UpdateWithdrawal(roundID uint32, sigs map[Ntxid]TxSigs, store *wtxmgr.Store) (
	map[Ntxid]TxSigs, error) {
	wInfo, err := getWithdrawalInfo(p, roundID)
	if err != nil {
		return nil, err
	}
	status := wInfo.status

	// Re-generate the raw signatures and merge them with the existing ones as
	// one or more series may have been made hot since the StartWithdrawal call
	// that initiated this withdrawal.
	newSigs, err := getRawSigs(status.transactions)
	if err != nil {
		return nil, err
	}
	if err = status.mergeSigs(newSigs); err != nil {
		return nil, err
	}

	// Now merge the raw signatures passed in.
	if err = status.mergeSigs(sigs); err != nil {
		return nil, err
	}
	if err = status.maybeBroadcastTxs(p.manager, store); err != nil {
		return nil, err
	}
	err = p.saveWithdrawal(roundID, wInfo.requests, wInfo.startAddress, wInfo.lastSeriesID,
		wInfo.changeStart, wInfo.dustThreshold, wInfo.status)
	if err != nil {
		return nil, err
	}
	return status.sigs, nil
}

// maybeBroadcastTxs will attempt to sign all transactions in this
// WithdrawalStatus (using the raw signatures from WithdrawalStatus.sigs),
// and broadcast the ones that can be signed (i.e. those for which we have
// the minimum required signatures for each input). Any transactions broadcast
// will be modified to indicate that, so the DB entry for this WithdrawalStatus
// must be updated (via Pool.saveWithdrawal()) after this method returns.
// This method must be called with the manager unlocked.
func (s *WithdrawalStatus) maybeBroadcastTxs(mgr *waddrmgr.Manager, store *wtxmgr.Store) error {
	for ntxid, tx := range s.transactions {
		err := signTx(tx.MsgTx, s.sigs[ntxid], mgr, store)
		if err != nil && err.(Error).ErrorCode == ErrNotEnoughSigs {
			log.Debugf("Not enough signatures for all inputs of tx %s; not broadcasting it", ntxid)
			continue
		} else if err != nil {
			log.Debugf("Error attempting to sign tx %s", ntxid)
			return err
		}
		// NOTE: Transactions are added one by one to wtxmgr, but if this
		// method returns an error the callsites will not update this
		// WithdrawalStatus in the DB and we may end up with broadcast
		// transactions that are not marked as such in the votingpool DB. That
		// shouldn't be a problem as wallet clients will retry the operation
		// and tx.addToStore() is a no-op for transactions that have already
		// been added.
		if err := tx.addToStore(store); err != nil {
			return err
		}
		log.Debugf("Successfully signed and broadcast tx %s", ntxid)
		// tx.addSelfToStore() will have modified tx fields, but we're working
		// on a copy of the original one thanks to the for/range loop, so we
		// need to overwrite the original one in the map.
		s.transactions[ntxid] = tx
	}
	return nil
}

func (s *WithdrawalStatus) mergeSigs(sigs map[Ntxid]TxSigs) error {
	if len(s.sigs) != len(sigs) {
		msg := fmt.Sprintf("number of new TxSigs (%d) does not match existing ones (%d)",
			len(s.sigs), len(sigs))
		return newError(ErrSigsListMismatch, msg, nil)
	}
	for ntxid, txSigs := range sigs {
		existingSigs, ok := s.sigs[ntxid]
		if !ok {
			return newError(ErrSigsListMismatch, fmt.Sprintf("missing sigs for tx %s", ntxid), nil)
		}
		if len(existingSigs) != len(txSigs) {
			msg := fmt.Sprintf("number of new siglists (%d) for tx %s does not match existing "+
				"ones (%d)", len(txSigs), ntxid, len(existingSigs))
			return newError(ErrSigsListMismatch, msg, nil)
		}
		for input, txInSigs := range txSigs {
			if len(txInSigs.Sigs) != len(existingSigs[input].Sigs) {
				msg := fmt.Sprintf("number of new sigs (%d) for tx %s, input %d "+
					"does not match existing ones (%d)", len(txInSigs.Sigs), ntxid,
					input, len(existingSigs[input].Sigs))
				return newError(ErrSigsListMismatch, msg, nil)
			}
			for branch, sig := range txInSigs.Sigs {
				if bytes.Equal(sig, emptyRawSig) {
					continue
				}
				existingSig := existingSigs[input].Sigs[branch]
				if bytes.Equal(existingSig, emptyRawSig) {
					log.Debugf("Adding raw sig for tx %v, input %d, branch %d", ntxid, input, branch)
					existingSigs[input].Sigs[branch] = sig
				} else if !bytes.Equal(existingSig, sig) {
					// Neither the new sig nor the existing one are empty, and
					// they don't match. Since we use deterministic signatures,
					// this could only happen if there's a bug in the code that
					// generates the signature lists or in the signature
					// construction itself.
					msg := fmt.Sprintf("cannot merge signatures: both existing and new sig for "+
						"tx %s, input %d, branch %d are non-empty but they don't match.",
						ntxid, input, branch)
					return newError(ErrSigsListMismatch, msg, nil)
				}
			}
		}
	}
	return nil
}

func (p *Pool) saveWithdrawal(roundID uint32, requests []OutputRequest,
	startAddress WithdrawalAddress, lastSeriesID uint32, changeStart ChangeAddress,
	dustThreshold btcutil.Amount, status WithdrawalStatus) error {
	serialized, err := serializeWithdrawal(requests, startAddress, lastSeriesID, changeStart,
		dustThreshold, status)
	if err != nil {
		return err
	}
	return p.namespace.Update(
		func(tx walletdb.Tx) error {
			return putWithdrawal(tx, p.ID, roundID, serialized)
		})
}

// popRequest removes and returns the first request from the stack of pending
// requests.
func (w *withdrawal) popRequest() OutputRequest {
	request := w.pendingRequests[0]
	w.pendingRequests = w.pendingRequests[1:]
	return request
}

// pushRequest adds a new request to the top of the stack of pending requests.
func (w *withdrawal) pushRequest(request OutputRequest) {
	w.pendingRequests = append([]OutputRequest{request}, w.pendingRequests...)
}

// popInput removes and returns the first input from the stack of eligible
// inputs.
func (w *withdrawal) popInput() credit {
	input := w.eligibleInputs[len(w.eligibleInputs)-1]
	w.eligibleInputs = w.eligibleInputs[:len(w.eligibleInputs)-1]
	return input
}

// peekInput returns the first input from the stack of eligible inputs, without
// changing the stack.
func (w *withdrawal) peekInput() credit {
	return w.eligibleInputs[len(w.eligibleInputs)-1]
}

// pushInput adds a new input to the top of the stack of eligible inputs.
func (w *withdrawal) pushInput(input credit) {
	w.eligibleInputs = append(w.eligibleInputs, input)
}

// If this returns it means we have added an output and the necessary inputs to fulfil that
// output plus the required fees. It also means the tx won't reach the size limit even
// after we add a change output and sign all inputs.
func (w *withdrawal) fulfillNextRequest() error {
	request := w.popRequest()
	output := w.status.outputs[request.outBailmentID()]
	// We start with an output status of success and let the methods that deal
	// with special cases change it when appropriate.
	output.status = outputStatusSuccess
	w.current.addOutput(request)

	if w.current.isTooBig() {
		return w.handleOversizeTx()
	}

	fee := w.current.calculateFee()
	for w.current.inputTotal() < w.current.outputTotal()+fee {
		if len(w.eligibleInputs) == 0 {
			log.Debug("Splitting last output because we don't have enough inputs")
			if err := w.splitLastOutput(); err != nil {
				return err
			}
			break
		}
		w.current.addInput(w.popInput())
		fee = w.current.calculateFee()

		if w.current.isTooBig() {
			return w.handleOversizeTx()
		}
	}
	return nil
}

// handleOversizeTx handles the case when a transaction has become too
// big by either rolling back an output or splitting it.
func (w *withdrawal) handleOversizeTx() error {
	if len(w.current.outputs) > 1 {
		log.Debug("Rolling back last output because tx got too big")
		inputs, output, err := w.current.rollBackLastOutput()
		if err != nil {
			return newError(ErrWithdrawalProcessing, "failed to rollback last output", err)
		}
		for _, input := range inputs {
			w.pushInput(input)
		}
		w.pushRequest(output.request)
	} else if len(w.current.outputs) == 1 {
		log.Debug("Splitting last output because tx got too big...")
		w.pushInput(w.current.removeInput())
		if err := w.splitLastOutput(); err != nil {
			return err
		}
	} else {
		return newError(ErrPreconditionNotMet, "Oversize tx must have at least one output", nil)
	}
	return w.finalizeCurrentTx()
}

// finalizeCurrentTx finalizes the transaction in w.current, moves it to the
// list of finalized transactions and replaces w.current with a new empty
// transaction.
func (w *withdrawal) finalizeCurrentTx() error {
	log.Debug("Finalizing current transaction")
	tx := w.current
	if len(tx.outputs) == 0 {
		log.Debug("Current transaction has no outputs, doing nothing")
		return nil
	}

	pkScript, err := txscript.PayToAddrScript(w.nextChangeAddr.addr)
	if err != nil {
		return newError(ErrWithdrawalProcessing, "failed to generate pkScript for change address", err)
	}
	if tx.addChange(pkScript) {
		var err error
		addr := w.nextChangeAddr
		w.nextChangeAddr, err = addr.pool.ChangeAddress(addr.SeriesID(), addr.Index()+1)
		if err != nil {
			return newError(ErrWithdrawalProcessing, "failed to get next change address", err)
		}
	}

	ntxid := tx.ntxid()
	for i, txOut := range tx.outputs {
		outputStatus := w.status.outputs[txOut.request.outBailmentID()]
		outputStatus.addOutpoint(
			OutBailmentOutpoint{ntxid: ntxid, index: uint32(i), amount: txOut.amount})
	}

	// Check that WithdrawalOutput entries with status==success have the sum of
	// their outpoint amounts matching the requested amount.
	for _, txOut := range tx.outputs {
		// Look up the original request we received because txOut.request may
		// represent a split request and thus have a different amount from the
		// original one.
		outputStatus := w.status.outputs[txOut.request.outBailmentID()]
		origRequest := outputStatus.request
		amtFulfilled := btcutil.Amount(0)
		for _, outpoint := range outputStatus.outpoints {
			amtFulfilled += outpoint.amount
		}
		if outputStatus.status == outputStatusSuccess && amtFulfilled != origRequest.Amount {
			msg := fmt.Sprintf("%s was not completely fulfilled; only %v fulfilled", origRequest,
				amtFulfilled)
			return newError(ErrWithdrawalProcessing, msg, nil)
		}
	}

	w.transactions = append(w.transactions, tx)
	w.current = newWithdrawalTx(w.txOptions)
	return nil
}

// maybeDropRequests will check the total amount we have in eligible inputs and drop
// requested outputs (in descending amount order) if we don't have enough to
// fulfill them all. For every dropped output request we update its entry in
// w.status.outputs with the status string set to outputStatusPartial.
func (w *withdrawal) maybeDropRequests() {
	inputAmount := btcutil.Amount(0)
	for _, input := range w.eligibleInputs {
		inputAmount += input.Amount
	}
	outputAmount := btcutil.Amount(0)
	for _, request := range w.pendingRequests {
		outputAmount += request.Amount
	}
	sort.Sort(sort.Reverse(byAmount(w.pendingRequests)))
	for inputAmount < outputAmount {
		request := w.popRequest()
		log.Infof("Not fulfilling request to send %v to %v; not enough credits.",
			request.Amount, request.Address)
		outputAmount -= request.Amount
		// We set the status to outputStatusPartial here but later on in
		// updateOutputsStatusAndNextInputAddr() we'll update it again to
		// include the series that need to be thawed in order for this request
		// to be fulfilled.
		w.status.outputs[request.outBailmentID()].status = outputStatusPartial
	}
}

func (w *withdrawal) fulfillRequests() error {
	w.maybeDropRequests()
	if len(w.pendingRequests) == 0 {
		log.Info("Not enough inputs to fulfill any withdrawal requests")
		return nil
	}

	// Sort outputs by outBailmentID (hash(server ID, tx #))
	sort.Sort(byOutBailmentID(w.pendingRequests))

	w.current = newWithdrawalTx(w.txOptions)
	for len(w.pendingRequests) > 0 {
		if err := w.fulfillNextRequest(); err != nil {
			return err
		}
		tx := w.current
		if len(w.eligibleInputs) == 0 && tx.inputTotal() <= tx.outputTotal()+tx.calculateFee() {
			// We don't have more eligible inputs and all the inputs in the
			// current tx have been spent.
			break
		}
	}

	if err := w.finalizeCurrentTx(); err != nil {
		return err
	}

	w.status.nextChangeAddr = w.nextChangeAddr.addressIdentifier
	w.status.transactions = make(map[Ntxid]changeAwareTx, len(w.transactions))
	for _, tx := range w.transactions {
		w.status.fees += tx.fee
		msgtx := tx.toMsgTx()
		changeIdx := -1
		if tx.hasChange() {
			// When withdrawalTx has a change, we know it will be the last entry
			// in the generated MsgTx.
			changeIdx = len(msgtx.TxOut) - 1
		}
		addrs := make(map[wire.OutPoint]WithdrawalAddress)
		for _, txIn := range msgtx.TxIn {
			prevOutpoint := txIn.PreviousOutPoint
			var c credit
			for _, input := range tx.inputs {
				if prevOutpoint == input.OutPoint {
					c = input
					break
				}
			}
			addrs[prevOutpoint] = c.addr
		}
		w.status.transactions[tx.ntxid()] = changeAwareTx{
			MsgTx:     msgtx,
			changeIdx: int32(changeIdx),
			addrs:     addrs,
		}
	}
	return nil
}

func (w *withdrawal) splitLastOutput() error {
	if len(w.current.outputs) == 0 {
		return newError(ErrPreconditionNotMet,
			"splitLastOutput requires current tx to have at least 1 output", nil)
	}

	tx := w.current
	output := tx.outputs[len(tx.outputs)-1]
	log.Debugf("Splitting tx output for %s", output.request)
	origAmount := output.amount
	spentAmount := tx.outputTotal() + tx.calculateFee() - output.amount
	// This is how much we have left after satisfying all outputs except the last
	// one. IOW, all we have left for the last output, so we set that as the
	// amount of the tx's last output.
	unspentAmount := tx.inputTotal() - spentAmount
	output.amount = unspentAmount
	log.Debugf("Updated output amount to %v", output.amount)

	// Create a new OutputRequest with the amount being the difference between
	// the original amount and what was left in the tx output above.
	request := output.request
	newRequest := OutputRequest{
		Server:      request.Server,
		Transaction: request.Transaction,
		Address:     request.Address,
		PkScript:    request.PkScript,
		Amount:      origAmount - output.amount}
	w.pushRequest(newRequest)
	log.Debugf("Created a new pending output request with amount %v", newRequest.Amount)

	w.status.outputs[request.outBailmentID()].status = outputStatusPartial
	return nil
}

// updateOutputsStatusAndNextInputAddr updates the status of outputs that were
// either partially fulfilled or split across multiple transactions and sets
// the nextInputAddr, according to the rules described in
// http://opentransactions.org/wiki/index.php/Update_Status.
func (w *withdrawal) updateOutputsStatusAndNextInputAddr(lastSeriesID uint32,
	dustThreshold btcutil.Amount, minConf int, store *wtxmgr.Store) error {
	missingAmount := btcutil.Amount(0)
	for _, output := range w.status.outputs {
		if len(output.outpoints) > 1 {
			output.status = outputStatusSplit
		}
		if output.status == outputStatusPartial {
			amountFulfilled := btcutil.Amount(0)
			for _, outpoint := range output.outpoints {
				amountFulfilled += outpoint.Amount()
			}
			missingAmount += output.request.Amount - amountFulfilled
		}
	}

	if missingAmount > 0 {
		log.Debugf("Updating status of partially fulfilled output requests. "+
			"Total missing amount: %v. Finding out how many series need to be thawed "+
			"before these requests can be fulfilled.", missingAmount)
		balance := btcutil.Amount(0)
		targetSeriesID := lastSeriesID
		for balance < missingAmount {
			targetSeriesID++
			if w.pool.Series(targetSeriesID) == nil {
				break
			}
			sBalance, err := w.pool.seriesBalance(targetSeriesID, dustThreshold, minConf, store)
			if err != nil {
				return err
			}
			log.Debugf("Found %v worth of eligible credits in series %d", sBalance, targetSeriesID)
			balance += sBalance
		}
		log.Debugf("Target seriesID for partial output requests: %d", targetSeriesID)
		for _, output := range w.status.outputs {
			if output.status == outputStatusPartial {
				output.status = fmt.Sprintf("%s-%d", outputStatusPartial, targetSeriesID)
			}
		}
	}

	if len(w.eligibleInputs) > 0 {
		nextInputAddr := w.peekInput().addr
		w.status.nextInputAddr = nextInputAddr.addressIdentifier
		log.Debugf("Withdrawal fulfilled with elibigle inputs still available; "+
			"setting nextInputAddr to %s", nextInputAddr)
	} else {
		w.status.nextInputAddr = &addressIdentifier{
			pool: w.pool, seriesID: lastSeriesID + 1, branch: Branch(0), index: Index(0)}
		log.Debugf("Withdrawal fulfilled but ran out of elibigle inputs; setting "+
			"nextInputAddr to %s", w.status.nextInputAddr)
	}
	return nil
}

// match returns true if the given arguments match the fields in this
// withdrawalInfo. For the requests slice, the order of the items does not
// matter.
func (wi *withdrawalInfo) match(requests []OutputRequest, startAddress WithdrawalAddress,
	lastSeriesID uint32, changeStart ChangeAddress, dustThreshold btcutil.Amount) bool {
	// Use reflect.DeepEqual to compare changeStart and startAddress as they're
	// structs that contain pointers and we want to compare their content and
	// not their address.
	if !reflect.DeepEqual(changeStart, wi.changeStart) {
		log.Debugf("withdrawal changeStart does not match: %v != %v", changeStart, wi.changeStart)
		return false
	}
	if !reflect.DeepEqual(startAddress, wi.startAddress) {
		log.Debugf("withdrawal startAddr does not match: %v != %v", startAddress, wi.startAddress)
		return false
	}
	if lastSeriesID != wi.lastSeriesID {
		log.Debugf("withdrawal lastSeriesID does not match: %v != %v", lastSeriesID,
			wi.lastSeriesID)
		return false
	}
	if dustThreshold != wi.dustThreshold {
		log.Debugf("withdrawal dustThreshold does not match: %v != %v", dustThreshold,
			wi.dustThreshold)
		return false
	}
	r1 := make([]OutputRequest, len(requests))
	copy(r1, requests)
	r2 := make([]OutputRequest, len(wi.requests))
	copy(r2, wi.requests)
	sort.Sort(byOutBailmentID(r1))
	sort.Sort(byOutBailmentID(r2))
	if !reflect.DeepEqual(r1, r2) {
		log.Debugf("withdrawal requests do not match: %v != %v", requests, wi.requests)
		return false
	}
	return true
}

// getWithdrawalStatus returns the existing WithdrawalStatus for the given
// withdrawal parameters, if one exists and has attributes matching all the
// arguments passed here. This function must be called with the address
// manager unlocked.
func getWithdrawalStatusMatching(p *Pool, roundID uint32, requests []OutputRequest,
	startAddress WithdrawalAddress, lastSeriesID uint32, changeStart ChangeAddress,
	dustThreshold btcutil.Amount) (*WithdrawalStatus, error) {

	wInfo, err := getWithdrawalInfo(p, roundID)
	if err != nil {
		return nil, err
	}
	if wInfo == nil {
		return nil, nil
	}
	log.Debugf("Found existing withdrawal for round %d, checking if parameters match", roundID)
	if wInfo.match(requests, startAddress, lastSeriesID, changeStart, dustThreshold) {
		return &wInfo.status, nil
	}
	return nil, nil
}

func getWithdrawalInfo(p *Pool, roundID uint32) (*withdrawalInfo, error) {
	var serialized []byte
	err := p.namespace.View(
		func(tx walletdb.Tx) error {
			serialized = getWithdrawal(tx, p.ID, roundID)
			return nil
		})
	if err != nil {
		return nil, err
	}
	if bytes.Equal(serialized, []byte{}) {
		return nil, nil
	}
	return deserializeWithdrawal(p, serialized)
}

// getRawSigs iterates over the inputs of each transaction given, constructing the
// raw signatures for them using the private keys available to us.
// It returns a map of ntxids to signature lists.
func getRawSigs(transactions map[Ntxid]changeAwareTx) (map[Ntxid]TxSigs, error) {
	sigs := make(map[Ntxid]TxSigs)
	for ntxid, tx := range transactions {
		txSigs := make(TxSigs, len(tx.TxIn))
		for inputIdx, input := range tx.TxIn {
			creditAddr := tx.addrs[input.PreviousOutPoint]
			redeemScript := creditAddr.script
			series := creditAddr.series()
			// The order of the raw signatures in the signature script must match the
			// order of the public keys in the redeem script, so we sort the public keys
			// here using the same API used to sort them in the redeem script and use
			// series.getPrivKeyFor() to lookup the corresponding private keys.
			pubKeys, err := branchOrder(series.publicKeys, creditAddr.Branch())
			if err != nil {
				return nil, err
			}
			txInSigs := newTxInSigs(series.reqSigs, len(pubKeys))
			for i, pubKey := range pubKeys {
				var sig RawSig
				privKey, err := series.getPrivKeyFor(pubKey)
				if err != nil {
					return nil, err
				}
				if privKey != nil {
					childKey, err := privKey.Child(uint32(creditAddr.Index()))
					if err != nil {
						return nil, newError(ErrKeyChain, "failed to derive private key", err)
					}
					ecPrivKey, err := childKey.ECPrivKey()
					if err != nil {
						return nil, newError(ErrKeyChain, "failed to obtain ECPrivKey", err)
					}
					log.Debugf("Generating raw sig for input %d of tx %s with privkey of %s",
						inputIdx, ntxid, pubKey.String())
					sig, err = txscript.RawTxInSignature(
						tx.MsgTx, inputIdx, redeemScript, txscript.SigHashAll, ecPrivKey)
					if err != nil {
						return nil, newError(ErrRawSigning, "failed to generate raw signature", err)
					}
				} else {
					log.Debugf("Not generating raw sig for input %d of %s because private key "+
						"for %s is not available: %v", inputIdx, ntxid, pubKey.String(), err)
					sig = emptyRawSig
				}
				txInSigs.Sigs[i] = sig
			}
			txSigs[inputIdx] = txInSigs
		}
		sigs[ntxid] = txSigs
	}
	return sigs, nil
}

// signTx signs every input of the given MsgTx by looking up (on the addr
// manager) the redeem script for each of them and constructing the signature
// script using that and the given raw signatures.
// This function must be called with the manager unlocked.
func signTx(msgtx *wire.MsgTx, sigs TxSigs, mgr *waddrmgr.Manager, store *wtxmgr.Store) error {
	// We use time.Now() here as we're not going to store the new TxRecord
	// anywhere -- we just need it to pass to store.PreviousPkScripts().
	rec, err := wtxmgr.NewTxRecordFromMsgTx(msgtx, time.Now())
	if err != nil {
		return newError(ErrTxSigning, "failed to construct TxRecord for signing", err)
	}
	pkScripts, err := store.PreviousPkScripts(rec, nil)
	if err != nil {
		return newError(ErrTxSigning, "failed to obtain pkScripts for signing", err)
	}
	if len(pkScripts) != len(sigs) {
		msg := fmt.Sprintf("number of pkScripts (%d) do not match number of sigs (%d)",
			len(pkScripts), len(sigs))
		return newError(ErrTxSigning, msg, nil)
	}
	for i, pkScript := range pkScripts {
		if err = signMultiSigUTXO(mgr, msgtx, i, pkScript, sigs[i]); err != nil {
			return err
		}
	}
	return nil
}

// getRedeemScript returns the redeem script for the given P2SH address. It must
// be called with the manager unlocked.
func getRedeemScript(mgr *waddrmgr.Manager, addr *btcutil.AddressScriptHash) ([]byte, error) {
	address, err := mgr.Address(addr)
	if err != nil {
		return nil, err
	}
	return address.(waddrmgr.ManagedScriptAddress).Script()
}

// signMultiSigUTXO signs the P2SH UTXO with the given index by constructing a
// script containing all given signatures plus the redeem (multi-sig) script. The
// redeem script is obtained by looking up the address of the given P2SH pkScript
// on the address manager.
// The order of the signatures must match that of the public keys in the multi-sig
// script as OP_CHECKMULTISIG expects that.
// This function must be called with the manager unlocked.
func signMultiSigUTXO(mgr *waddrmgr.Manager, tx *wire.MsgTx, idx int, pkScript []byte, sigs TxInSigs) error {
	class, addresses, _, err := txscript.ExtractPkScriptAddrs(pkScript, mgr.ChainParams())
	if err != nil {
		return newError(ErrTxSigning, "unparseable pkScript", err)
	}
	if class != txscript.ScriptHashTy {
		return newError(ErrTxSigning, fmt.Sprintf("pkScript is not P2SH: %s", class), nil)
	}
	redeemScript, err := getRedeemScript(mgr, addresses[0].(*btcutil.AddressScriptHash))
	if err != nil {
		return newError(ErrTxSigning, "unable to retrieve redeem script", err)
	}

	class, _, nRequired, err := txscript.ExtractPkScriptAddrs(redeemScript, mgr.ChainParams())
	if err != nil {
		return newError(ErrTxSigning, "unparseable redeem script", err)
	}
	if class != txscript.MultiSigTy {
		return newError(ErrTxSigning, fmt.Sprintf("redeem script is not multi-sig: %v", class), nil)
	}
	var nonEmptySigs []RawSig
	for _, sig := range sigs.Sigs {
		if !bytes.Equal(sig, emptyRawSig) {
			nonEmptySigs = append(nonEmptySigs, sig)
		}
	}
	if len(nonEmptySigs) < nRequired {
		errStr := fmt.Sprintf("not enough signatures; need %d but got only %d", nRequired,
			len(nonEmptySigs))
		return newError(ErrNotEnoughSigs, errStr, nil)
	}

	// Construct the unlocking script.
	// Start with an OP_0 because of the bug in bitcoind, then add nRequired signatures.
	unlockingScript := txscript.NewScriptBuilder().AddOp(txscript.OP_FALSE)
	for _, sig := range nonEmptySigs[:nRequired] {
		unlockingScript.AddData(sig)
	}

	// Combine the redeem script and the unlocking script to get the actual signature script.
	sigScript := unlockingScript.AddData(redeemScript)
	script, err := sigScript.Script()
	if err != nil {
		return newError(ErrTxSigning, "error building sigscript", err)
	}
	tx.TxIn[idx].SignatureScript = script

	if err := validateSigScript(tx, idx, pkScript); err != nil {
		return err
	}
	return nil
}

// validateSigScripts executes the signature script of the tx input with the
// given index, returning an error if it fails.
func validateSigScript(msgtx *wire.MsgTx, idx int, pkScript []byte) error {
	vm, err := txscript.NewEngine(pkScript, msgtx, idx, txscript.StandardVerifyFlags)
	if err != nil {
		return newError(ErrTxSigning, "cannot create script engine", err)
	}
	if err = vm.Execute(); err != nil {
		return newError(ErrTxSigning, "cannot validate tx signature", err)
	}
	return nil
}

// calculateTxSize returns an estimate of the serialized size (in bytes) of the
// given transaction. It assumes all tx inputs are P2SH multi-sig.
func calculateTxSize(tx *withdrawalTx) int {
	msgtx := tx.toMsgTx()
	// Assume that there will always be a change output, for simplicity. We
	// simulate that by simply copying the first output as all we care about is
	// the size of its serialized form, which should be the same for all of them
	// as they're either P2PKH or P2SH..
	if !tx.hasChange() {
		msgtx.AddTxOut(msgtx.TxOut[0])
	}
	// Craft a SignatureScript with dummy signatures for every input in this tx
	// so that we can use msgtx.SerializeSize() to get its size and don't need
	// to rely on estimations.
	for i, txin := range msgtx.TxIn {
		// 1 byte for the OP_FALSE opcode, then 73+1 bytes for each signature
		// with their OP_DATA opcode and finally the redeem script + 1 byte
		// for its OP_PUSHDATA opcode and N bytes for the redeem script's size.
		// Notice that we use 73 as the signature length as that's the maximum
		// length they may have:
		// https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
		addr := tx.inputs[i].addr
		redeemScriptLen := len(addr.script)
		n := wire.VarIntSerializeSize(uint64(redeemScriptLen))
		sigScriptLen := 1 + (74 * int(addr.series().reqSigs)) + redeemScriptLen + 1 + n
		txin.SignatureScript = bytes.Repeat([]byte{1}, sigScriptLen)
	}
	return msgtx.SerializeSize()
}
