// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightningnetwork/lnd/fn/v2"
)

// storeTxStage identifies expensive or externally controlled funding work that
// must execute with no Store callback active.
type storeTxStage uint8

const (
	storeTxStageCrypto storeTxStage = iota
	storeTxStageSigning
	storeTxStageVM
)

// storeTxObserver provides transaction-scope diagnostics for tests and
// benchmarks without changing transaction behavior.
type storeTxObserver struct {
	observe func(storeTxStage)
}

var activeStoreTxObserver atomic.Pointer[storeTxObserver]

// observeStoreTxStage reports one transaction-independent preparation stage.
func observeStoreTxStage(stage storeTxStage) {
	observer := activeStoreTxObserver.Load()
	if observer != nil && observer.observe != nil {
		observer.observe(stage)
	}
}

const (
	// maxStoreFundingAttempts bounds complete snapshot and preparation retries
	// when durable UTXOs or change indexes race the final write transaction.
	maxStoreFundingAttempts = 3

	// maxStoreCommitAttempts bounds retries of the database-only final plan.
	// No caller callback or cryptographic work is repeated by these retries.
	maxStoreCommitAttempts = 3
)

// storeChangePlan is the non-cryptographic surface exposed by waddrmgr's
// private prepared next-address plan.
type storeChangePlan interface {
	// Address returns the managed change address reserved by the plan.
	Address() waddrmgr.ManagedAddress

	// Commit persists the reserved change address.
	Commit(waddrmgr.ManagerReadWriteTx) error

	// Reconcile determines whether an ambiguous commit applied the plan.
	Reconcile(waddrmgr.ManagerReadStore) (bool, bool, bool, error)

	// Apply publishes the committed plan to in-memory manager state.
	Apply()
}

// storeTxSnapshot owns the transaction data needed to decorate one explicit
// funding input after the Store callback returns.
type storeTxSnapshot struct {
	tx      *wire.MsgTx
	credits []wtxmgr.CreditRecord
}

// storeFundingSnapshot owns UTXOs, transaction details, and address-manager
// rows read during one short Store view.
type storeFundingSnapshot struct {
	unspent      []wtxmgr.Credit
	transactions map[chainhash.Hash]storeTxSnapshot
	addresses    storeAddressSnapshot
}

// preparedStoreChange couples an out-of-transaction change source with the
// private address plan created only if txauthor actually needs change.
type preparedStoreChange struct {
	scope   waddrmgr.KeyScope
	account uint32
	source  *txauthor.ChangeSource
	plan    storeChangePlan
}

// copyStoreCredit detaches a UTXO script from backend-owned memory.
func copyStoreCredit(credit wtxmgr.Credit) wtxmgr.Credit {
	credit.PkScript = append([]byte(nil), credit.PkScript...)

	return credit
}

// readStoreFundingSnapshot copies all durable funding state without parsing
// scripts, deriving keys, invoking callbacks, or changing caller-owned values.
func (w *Wallet) readStoreFundingSnapshot(ctx context.Context,
	inputs []wire.OutPoint) (storeFundingSnapshot, error) {

	var snapshot storeFundingSnapshot
	err := w.store.View(ctx, func(tx walletstore.ReadTx) error {
		unspent, err := tx.Tx().UnspentOutputs()
		if err != nil {
			return err
		}
		snapshot.unspent = make([]wtxmgr.Credit, len(unspent))
		for i := range unspent {
			snapshot.unspent[i] = copyStoreCredit(unspent[i])
		}

		snapshot.addresses, err = readStoreAddressSnapshot(tx.Addr())
		if err != nil {
			return err
		}

		snapshot.transactions = make(
			map[chainhash.Hash]storeTxSnapshot, len(inputs),
		)
		for _, input := range inputs {
			if _, ok := snapshot.transactions[input.Hash]; ok {
				continue
			}

			details, err := tx.Tx().TxDetails(&input.Hash)
			if err != nil {
				return err
			}
			if details == nil {
				return fmt.Errorf("%v not found", input)
			}
			snapshot.transactions[input.Hash] = storeTxSnapshot{
				tx: details.MsgTx.Copy(),
				credits: append(
					[]wtxmgr.CreditRecord(nil), details.Credits...,
				),
			}
		}

		return nil
	}, func() {
		snapshot = storeFundingSnapshot{}
	})

	return snapshot, err
}

// accountState returns one detached account row from the funding snapshot.
func (s storeFundingSnapshot) accountState(scope waddrmgr.KeyScope,
	account uint32) (waddrmgr.AccountState, error) {

	state, ok := s.addresses.accounts[storeAccountKey{
		scope:   scope,
		account: account,
	}]
	if !ok {
		return waddrmgr.AccountState{}, fmt.Errorf(
			"account %d not found in scope %s", account, scope,
		)
	}

	return state, nil
}

// newPreparedStoreChange creates a lazy change source from a detached account
// row. Its NewScript closure performs all derivation outside Store callbacks.
func (w *Wallet) newPreparedStoreChange(snapshot storeFundingSnapshot,
	changeKeyScope *waddrmgr.KeyScope,
	account uint32) (*preparedStoreChange, error) {

	scope := waddrmgr.KeyScopeBIP0086
	if changeKeyScope != nil {
		scope = *changeKeyScope
	}
	changeAccount := account
	if account == waddrmgr.ImportedAddrAccount {
		changeAccount = waddrmgr.DefaultAccountNum
	}

	state, err := snapshot.accountState(scope, changeAccount)
	if err != nil {
		return nil, err
	}
	addrType := waddrmgr.ScopeAddrMap[scope].InternalAddrType
	if state.AddrSchema != nil {
		addrType = state.AddrSchema.InternalAddrType
	}

	var scriptSize int
	switch addrType {
	case waddrmgr.PubKeyHash:
		scriptSize = txsizes.P2PKHPkScriptSize

	case waddrmgr.NestedWitnessPubKey:
		scriptSize = txsizes.NestedP2WPKHPkScriptSize

	case waddrmgr.WitnessPubKey:
		scriptSize = txsizes.P2WPKHPkScriptSize

	case waddrmgr.TaprootPubKey:
		scriptSize = txsizes.P2TRPkScriptSize

	default:
		return nil, fmt.Errorf("unsupported address type: %v", addrType)
	}

	manager, err := w.Manager.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}
	change := &preparedStoreChange{
		scope:   scope,
		account: changeAccount,
	}
	change.source = &txauthor.ChangeSource{
		ScriptSize: scriptSize,
		NewScript: func() ([]byte, error) {
			if change.plan == nil {
				observeStoreTxStage(storeTxStageCrypto)
				plan, err := manager.PrepareNextInternalAddress(state)
				if err != nil {
					return nil, err
				}
				change.plan = plan
			}

			return txscript.PayToAddrScript(
				change.plan.Address().Address(),
			)
		},
	}

	return change, nil
}

// findEligibleOutputsFromSnapshot filters detached UTXOs after the Store view
// has closed, so caller policy and script parsing cannot extend its lifetime.
func (w *Wallet) findEligibleOutputsFromSnapshot(
	snapshot storeFundingSnapshot, keyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, blockStamp *waddrmgr.BlockStamp,
	allowUtxo func(wtxmgr.Credit) bool) []wtxmgr.Credit {

	eligible := make([]wtxmgr.Credit, 0, len(snapshot.unspent))
	for i := range snapshot.unspent {
		output := snapshot.unspent[i]
		if allowUtxo != nil && !allowUtxo(output) {
			continue
		}
		if !hasMinConfs(minconf, output.Height, blockStamp.Height) {
			continue
		}
		if output.FromCoinBase {
			target := int32(w.chainParams.CoinbaseMaturity)
			if !hasMinConfs(target, output.Height, blockStamp.Height) {
				continue
			}
		}
		if w.LockedOutpoint(output.OutPoint) {
			continue
		}

		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams,
		)
		if err != nil || len(addrs) != 1 {
			continue
		}
		_, ok := snapshot.addresses.material(
			addrs[0], keyScope, &account,
		)
		if !ok {
			continue
		}

		eligible = append(eligible, output)
	}

	return eligible
}

// storeInputSource chooses either the caller's exact UTXOs or coins arranged by
// the caller's strategy. Both callbacks run after the snapshot transaction.
func storeInputSource(eligible []wtxmgr.Credit,
	selectedUtxos []wire.OutPoint, strategy CoinSelectionStrategy,
	feeSatPerKb btcutil.Amount) (txauthor.InputSource, error) {

	if len(selectedUtxos) > 0 {
		dedupUtxos := fn.NewSet(selectedUtxos...)
		if len(dedupUtxos) != len(selectedUtxos) {
			return nil, errors.New("selected UTXOs contain duplicate values")
		}

		eligibleByOutpoint := make(
			map[wire.OutPoint]wtxmgr.Credit, len(eligible),
		)
		for _, output := range eligible {
			eligibleByOutpoint[output.OutPoint] = output
		}

		selected := make([]wtxmgr.Credit, 0, len(selectedUtxos))
		for _, outpoint := range selectedUtxos {
			output, ok := eligibleByOutpoint[outpoint]
			if !ok {
				return nil, fmt.Errorf("selected outpoint not eligible for "+
					"spending: %v", outpoint)
			}
			selected = append(selected, output)
		}

		return constantInputSource(selected), nil
	}

	coins := make([]Coin, len(eligible))
	for i := range eligible {
		coins[i] = Coin{
			TxOut: wire.TxOut{
				Value:    int64(eligible[i].Amount),
				PkScript: eligible[i].PkScript,
			},
			OutPoint: eligible[i].OutPoint,
		}
	}
	arranged, err := strategy.ArrangeCoins(coins, feeSatPerKb)
	if err != nil {
		return nil, err
	}

	return makeInputSource(arranged), nil
}

// selectedStoreCredits returns the exact detached UTXOs consumed by an authored
// transaction.
func selectedStoreCredits(authored *txauthor.AuthoredTx,
	unspent []wtxmgr.Credit) ([]wtxmgr.Credit, error) {

	byOutpoint := make(map[wire.OutPoint]wtxmgr.Credit, len(unspent))
	for _, credit := range unspent {
		byOutpoint[credit.OutPoint] = credit
	}

	selected := make([]wtxmgr.Credit, len(authored.Tx.TxIn))
	for i, input := range authored.Tx.TxIn {
		credit, ok := byOutpoint[input.PreviousOutPoint]
		if !ok {
			return nil, fmt.Errorf("selected outpoint disappeared from "+
				"snapshot: %v", input.PreviousOutPoint)
		}
		selected[i] = credit
	}

	return selected, nil
}

// sameStoreCredit reports whether every spend-relevant durable UTXO field is
// unchanged.
func sameStoreCredit(a, b wtxmgr.Credit) bool {
	return a.OutPoint == b.OutPoint && a.Block == b.Block &&
		a.Time.Equal(b.Time) && a.Amount == b.Amount &&
		bytes.Equal(a.PkScript, b.PkScript) &&
		a.Received.Equal(b.Received) && a.FromCoinBase == b.FromCoinBase
}

// revalidateStoreCredits requires every selected UTXO to remain exactly
// spendable in the final transaction snapshot.
func revalidateStoreCredits(store walletstore.TxReadStore,
	selected []wtxmgr.Credit) error {

	current, err := store.UnspentOutputs()
	if err != nil {
		return err
	}
	byOutpoint := make(map[wire.OutPoint]wtxmgr.Credit, len(current))
	for _, credit := range current {
		byOutpoint[credit.OutPoint] = credit
	}
	for _, expected := range selected {
		credit, ok := byOutpoint[expected.OutPoint]
		if !ok || !sameStoreCredit(credit, expected) {
			return &StorePlanStaleError{
				Operation: "transaction funding",
				Reason: fmt.Sprintf(
					"selected UTXO %v changed", expected.OutPoint,
				),
			}
		}
	}

	return nil
}

// commitStoreFundingPlan applies only exact prepared database state. Retryable
// Store failures repeat this database-only phase, never external callbacks.
func (w *Wallet) commitStoreFundingPlan(selected []wtxmgr.Credit,
	change *preparedStoreChange) error {

	for attempt := 0; attempt < maxStoreCommitAttempts; attempt++ {
		err := w.store.UpdateOnce(
			context.Background(), func(tx walletstore.ReadWriteTx) error {
				if err := revalidateStoreCredits(
					tx.Tx(), selected,
				); err != nil {

					return err
				}
				if change == nil || change.plan == nil {
					return nil
				}

				err := change.plan.Commit(tx.Addr())
				var conflict *waddrmgr.AddressPlanConflictError
				if errors.As(err, &conflict) {
					return &StorePlanStaleError{
						Operation: "transaction funding",
						Reason:    conflict.Error(),
					}
				}

				return err
			}, nil,
		)
		if err == nil {
			return nil
		}

		var retryable *walletstore.RetryableTransactionError
		if errors.As(err, &retryable) {
			continue
		}

		var ambiguous *walletstore.AmbiguousCommitError
		if !errors.As(err, &ambiguous) {
			return err
		}

		var (
			creditsCurrent bool
			durable        bool
			absent         bool
			exact          bool
		)
		viewErr := w.store.View(
			context.Background(), func(tx walletstore.ReadTx) error {
				creditErr := revalidateStoreCredits(tx.Tx(), selected)
				creditsCurrent = creditErr == nil
				if creditErr != nil {
					var stale *StorePlanStaleError
					if !errors.As(creditErr, &stale) {
						return creditErr
					}
				}

				if change == nil || change.plan == nil {
					durable = creditsCurrent
					return nil
				}

				var err error
				durable, absent, exact, err =
					change.plan.Reconcile(tx.Addr())
				return err
			}, func() {
				creditsCurrent = false
				durable = false
				absent = false
				exact = false
			},
		)
		if viewErr != nil {
			w.markStoreChangeStale(change)
			return &UnresolvedStoreCommitError{
				Operation: "transaction funding",
				Err: errors.Join(
					ambiguous, fmt.Errorf(
						"reconcile commit: %w", viewErr,
					),
				),
			}
		}

		switch {
		case durable:
			if exact && change != nil && change.plan != nil {
				ambiguous.ApplyCommitHooks()
				change.plan.Apply()
			} else {
				w.markStoreChangeStale(change)
			}

			return nil

		case absent && creditsCurrent:
			continue

		default:
			w.markStoreChangeStale(change)
			return &UnresolvedStoreCommitError{
				Operation: "transaction funding",
				Err:       ambiguous,
			}
		}
	}

	return &walletstore.RetryableTransactionError{
		Err: errors.New("transaction funding commit retries exhausted"),
	}
}

// markStoreChangeStale prevents uncertain change indexes from being reported
// through an optimistic manager cache.
func (w *Wallet) markStoreChangeStale(change *preparedStoreChange) {
	if change == nil || change.plan == nil {
		return
	}

	w.Manager.MarkAccountCacheStale(change.scope, change.account)
}

// copyTxOutputs owns output scripts before txauthor may reorder output
// pointers.
func copyTxOutputs(outputs []*wire.TxOut) []*wire.TxOut {
	result := make([]*wire.TxOut, len(outputs))
	for i, output := range outputs {
		result[i] = &wire.TxOut{
			Value:    output.Value,
			PkScript: append([]byte(nil), output.PkScript...),
		}
	}

	return result
}

// prepareStoreAuthoredTx performs policy callbacks, coin arrangement, change
// derivation, fee calculation, signing, and VM validation after snapshot exit.
func (w *Wallet) prepareStoreAuthoredTx(snapshot storeFundingSnapshot,
	outputs []*wire.TxOut, coinSelectKeyScope,
	changeKeyScope *waddrmgr.KeyScope, account uint32, minconf int32,
	feeSatPerKb btcutil.Amount, strategy CoinSelectionStrategy,
	selectedUtxos []wire.OutPoint,
	allowUtxo func(wtxmgr.Credit) bool, dryRun bool,
	blockStamp *waddrmgr.BlockStamp) (*txauthor.AuthoredTx,
	[]wtxmgr.Credit, *preparedStoreChange, error) {

	change, err := w.newPreparedStoreChange(
		snapshot, changeKeyScope, account,
	)
	if err != nil {
		return nil, nil, nil, err
	}
	eligible := w.findEligibleOutputsFromSnapshot(
		snapshot, coinSelectKeyScope, account, minconf, blockStamp,
		allowUtxo,
	)
	inputSource, err := storeInputSource(
		eligible, selectedUtxos, strategy, feeSatPerKb,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	authored, err := txauthor.NewUnsignedTransaction(
		copyTxOutputs(outputs), feeSatPerKb, inputSource, change.source,
	)
	if err != nil {
		return nil, nil, nil, err
	}
	if authored.ChangeIndex >= 0 {
		authored.RandomizeChangePosition()
	}
	selected, err := selectedStoreCredits(authored, snapshot.unspent)
	if err != nil {
		return nil, nil, nil, err
	}
	if dryRun {
		return authored, selected, change, nil
	}

	watchOnlyScope := waddrmgr.KeyScopeBIP0086
	if coinSelectKeyScope != nil {
		watchOnlyScope = *coinSelectKeyScope
	}
	watchOnly := w.Manager.WatchOnly() ||
		account == waddrmgr.ImportedAddrAccount
	if !watchOnly {
		state, err := snapshot.accountState(watchOnlyScope, account)
		if err != nil {
			return nil, nil, nil, err
		}
		watchOnly = len(state.EncryptedPrivKey) == 0
	}
	if !watchOnly {
		secrets := &detachedStoreSecretSource{
			wallet:   w,
			snapshot: snapshot.addresses,
			managed: make(
				map[[32]byte]waddrmgr.ManagedAddress,
			),
		}
		observeStoreTxStage(storeTxStageSigning)
		if err := authored.AddAllInputScripts(secrets); err != nil {
			return nil, nil, nil, err
		}
		observeStoreTxStage(storeTxStageVM)
		if err := validateMsgTx(
			authored.Tx, authored.PrevScripts,
			authored.PrevInputValues,
		); err != nil {

			return nil, nil, nil, err
		}
	}

	return authored, selected, change, nil
}

// cloneStorePsbt serializes a caller packet into an independently mutable
// packet while preserving all standard and unknown metadata.
func cloneStorePsbt(packet *psbt.Packet) (*psbt.Packet, error) {
	var buffer bytes.Buffer
	if err := packet.Serialize(&buffer); err != nil {
		return nil, err
	}

	return psbt.NewFromRawBytes(bytes.NewReader(buffer.Bytes()), false)
}

// storeManagedOutput resolves a wallet output from detached address rows.
func (w *Wallet) storeManagedOutput(snapshot storeAddressSnapshot,
	output *wire.TxOut) (waddrmgr.ManagedAddress, error) {

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		output.PkScript, w.chainParams,
	)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		managed, err := snapshot.resolve(w, addr)
		if err == nil {
			return managed, nil
		}
	}

	return nil, ErrNotMine
}

// storeBip32Derivation constructs PSBT key-origin metadata from a detached
// managed address without reading a Store.
func storeBip32Derivation(
	managed waddrmgr.ManagedPubKeyAddress) (*psbt.Bip32Derivation, error) {

	scope, path, known := managed.DerivationInfo()
	if !known {
		return nil, ErrNotMine
	}

	return &psbt.Bip32Derivation{
		PubKey:               managed.PubKey().SerializeCompressed(),
		MasterKeyFingerprint: path.MasterKeyFingerprint,
		Bip32Path: []uint32{
			scope.Purpose + hdkeychain.HardenedKeyStart,
			scope.Coin + hdkeychain.HardenedKeyStart,
			path.Account,
			path.Branch,
			path.Index,
		},
	}, nil
}

// explicitStoreCredits decorates a PSBT working copy and returns the exact
// detached UTXOs that its caller selected.
func (w *Wallet) explicitStoreCredits(packet *psbt.Packet,
	snapshot storeFundingSnapshot) ([]wtxmgr.Credit, error) {

	// Preserve the legacy explicit-input behavior, which replaces rather
	// than augments input metadata while decorating selected wallet UTXOs.
	packet.Inputs = make([]psbt.PInput, len(packet.UnsignedTx.TxIn))

	byOutpoint := make(
		map[wire.OutPoint]wtxmgr.Credit, len(snapshot.unspent),
	)
	for _, credit := range snapshot.unspent {
		byOutpoint[credit.OutPoint] = credit
	}

	credits := make([]wtxmgr.Credit, len(packet.UnsignedTx.TxIn))
	for index, input := range packet.UnsignedTx.TxIn {
		input.Witness = nil
		input.SignatureScript = nil

		details, ok := snapshot.transactions[input.PreviousOutPoint.Hash]
		if !ok {
			return nil, fmt.Errorf("%v not found", input.PreviousOutPoint)
		}
		outputIndex := input.PreviousOutPoint.Index
		if outputIndex >= uint32(len(details.tx.TxOut)) {
			return nil, fmt.Errorf("previous output %v is out of range",
				input.PreviousOutPoint)
		}
		owned := false
		for _, credit := range details.credits {
			if credit.Index == outputIndex {
				owned = true
				break
			}
		}
		if !owned {
			return nil, ErrNotMine
		}

		credit, ok := byOutpoint[input.PreviousOutPoint]
		if !ok {
			return nil, fmt.Errorf("selected input %v is not unspent: %w",
				input.PreviousOutPoint, ErrNotMine)
		}
		credits[index] = credit
		output := &wire.TxOut{
			Value:    int64(credit.Amount),
			PkScript: append([]byte(nil), credit.PkScript...),
		}
		managed, err := w.storeManagedOutput(snapshot.addresses, output)
		if err != nil {
			return nil, err
		}
		pubKeyAddr, witnessProgram, _, err := scriptForStoreOutput(
			output, managed, w.chainParams,
		)
		if err != nil {
			return nil, err
		}
		derivation, err := storeBip32Derivation(pubKeyAddr)
		if err != nil {
			return nil, err
		}

		if txscript.IsPayToTaproot(output.PkScript) {
			addInputInfoSegWitV1(
				&packet.Inputs[index], output, derivation,
			)
		} else {
			addInputInfoSegWitV0(
				&packet.Inputs[index], details.tx, output,
				derivation, pubKeyAddr, witnessProgram,
			)
		}
	}

	return credits, nil
}

// fundPsbtExplicitFromStore funds an explicit-input PSBT working copy and
// replaces the caller packet only after prepared change state commits.
func (w *Wallet) fundPsbtExplicitFromStore(packet *psbt.Packet,
	keyScope *waddrmgr.KeyScope, account uint32,
	feeSatPerKB btcutil.Amount,
	optFuncs ...TxCreateOption) (int32, error) {

	var lastConflict error
	for attempt := 0; attempt < maxStoreFundingAttempts; attempt++ {
		working, err := cloneStorePsbt(packet)
		if err != nil {
			return 0, err
		}
		inputs := make([]wire.OutPoint, len(working.UnsignedTx.TxIn))
		for i, input := range working.UnsignedTx.TxIn {
			inputs[i] = input.PreviousOutPoint
		}
		snapshot, err := w.readStoreFundingSnapshot(
			context.Background(), inputs,
		)
		if err != nil {
			return 0, err
		}
		credits, err := w.explicitStoreCredits(working, snapshot)
		if err != nil {
			return 0, fmt.Errorf("error fetching UTXO: %w", err)
		}

		opts := defaultTxCreateOptions()
		for _, optFunc := range optFuncs {
			optFunc(opts)
		}
		if opts.changeKeyScope == nil {
			opts.changeKeyScope = keyScope
		}
		change, err := w.newPreparedStoreChange(
			snapshot, opts.changeKeyScope, account,
		)
		if err != nil {
			return 0, err
		}
		authored, err := txauthor.NewUnsignedTransaction(
			copyTxOutputs(working.UnsignedTx.TxOut), feeSatPerKB,
			constantInputSource(credits), change.source,
		)
		if err != nil {
			return 0, fmt.Errorf("fee estimation not successful: %w", err)
		}

		var changeOutput *wire.TxOut
		if authored.ChangeIndex >= 0 {
			changeOutput = authored.Tx.TxOut[authored.ChangeIndex]
			working.UnsignedTx.TxOut = append(
				working.UnsignedTx.TxOut, changeOutput,
			)
			pubKeyAddr, ok := change.plan.Address().(waddrmgr.ManagedPubKeyAddress)
			if !ok {
				return 0, errors.New("change address is not a pubkey address")
			}
			outputInfo, err := createOutputInfo(changeOutput, pubKeyAddr)
			if err != nil {
				return 0, fmt.Errorf("error adding output info to change "+
					"output: %w", err)
			}
			working.Outputs = append(working.Outputs, *outputInfo)
		}

		if err := psbt.InPlaceSort(working); err != nil {
			return 0, fmt.Errorf("could not sort PSBT: %w", err)
		}
		changeIndex := int32(-1)
		if changeOutput != nil {
			for index, output := range working.UnsignedTx.TxOut {
				if psbt.TxOutsEqual(changeOutput, output) {
					changeIndex = int32(index)
					break
				}
			}
		}

		err = w.commitStoreFundingPlan(credits, change)
		var stale *StorePlanStaleError
		if errors.As(err, &stale) {
			lastConflict = err
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("could not add change address to "+
				"database: %w", err)
		}

		*packet = *working
		return changeIndex, nil
	}

	return 0, fmt.Errorf("PSBT funding conflicts exceeded %d attempts: %w",
		maxStoreFundingAttempts, lastConflict)
}

// txToOutputsFromStore creates a transaction from detached durable snapshots.
// Change watcher registration occurs only after a normal commit or after an
// ambiguous commit is proven durable. A watcher error therefore means the
// address remains durable even though this method returns an error.
func (w *Wallet) txToOutputsFromStore(outputs []*wire.TxOut,
	coinSelectKeyScope, changeKeyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, feeSatPerKb btcutil.Amount,
	strategy CoinSelectionStrategy, dryRun bool,
	selectedUtxos []wire.OutPoint,
	allowUtxo func(utxo wtxmgr.Credit) bool, chainClient chain.Interface,
	blockStamp *waddrmgr.BlockStamp) (*txauthor.AuthoredTx, error) {

	var lastConflict error
	for attempt := 0; attempt < maxStoreFundingAttempts; attempt++ {
		snapshot, err := w.readStoreFundingSnapshot(
			context.Background(), nil,
		)
		if err != nil {
			return nil, err
		}
		authored, selected, change, err := w.prepareStoreAuthoredTx(
			snapshot, outputs, coinSelectKeyScope, changeKeyScope,
			account, minconf, feeSatPerKb, strategy, selectedUtxos,
			allowUtxo, dryRun, blockStamp,
		)
		if err != nil {
			return nil, err
		}
		if dryRun {
			for _, input := range authored.Tx.TxIn {
				input.SignatureScript = nil
				input.Witness = nil
			}

			return authored, nil
		}

		err = w.commitStoreFundingPlan(selected, change)
		var stale *StorePlanStaleError
		if errors.As(err, &stale) {
			lastConflict = err
			continue
		}
		if err != nil {
			return nil, err
		}

		if authored.ChangeIndex >= 0 &&
			account == waddrmgr.ImportedAddrAccount {

			changeAmount := btcutil.Amount(
				authored.Tx.TxOut[authored.ChangeIndex].Value,
			)
			log.Warnf("Spend from imported account produced change: "+
				"moving %v from imported account into default account.",
				changeAmount)
		}
		if change.plan != nil {
			addr := change.plan.Address().Address()
			if err := chainClient.NotifyReceived(
				[]address.Address{addr},
			); err != nil {

				return nil, fmt.Errorf("change address %v is durable but "+
					"watcher registration failed: %w", addr, err)
			}
		}

		return authored, nil
	}

	return nil, fmt.Errorf("transaction funding conflicts exceeded %d "+
		"attempts: %w", maxStoreFundingAttempts, lastConflict)
}
