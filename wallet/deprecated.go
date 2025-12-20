//nolint:lll
package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// NextAccount creates the next account and returns its account number.  The
// name must be unique to the account.  In order to support automatic seed
// restoring, new accounts may not be created when all of the previous 100
// accounts have no transaction history (this is a deviation from the BIP0044
// spec, which allows no unused account gaps).
func (w *Wallet) NextAccount(scope waddrmgr.KeyScope, name string) (uint32, error) {
	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return 0, err
	}

	// Validate that the scope manager can add this new account.
	err = manager.CanAddAccount()
	if err != nil {
		return 0, err
	}

	var (
		account uint32
		props   *waddrmgr.AccountProperties
	)
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		var err error
		account, err = manager.NewAccount(addrmgrNs, name)
		if err != nil {
			return err
		}
		props, err = manager.AccountProperties(addrmgrNs, account)

		return err
	})
	if err != nil {
		log.Errorf("Cannot fetch new account properties for notification "+
			"after account creation: %v", err)
	} else {
		w.NtfnServer.notifyAccountProperties(props)
	}

	return account, err
}

// Accounts returns the current names, numbers, and total balances of all
// accounts in the wallet restricted to a particular key scope.  The current
// chain tip is included in the result for atomicity reasons.
//
// TODO(jrick): Is the chain tip really needed, since only the total balances
// are included?
func (w *Wallet) Accounts(scope waddrmgr.KeyScope) (*AccountsResult, error) {
	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var (
		accounts        []AccountResult
		syncBlockHash   *chainhash.Hash
		syncBlockHeight int32
	)
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.addrStore.SyncedTo()
		syncBlockHash = &syncBlock.Hash
		syncBlockHeight = syncBlock.Height
		unspent, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		err = manager.ForEachAccount(addrmgrNs, func(acct uint32) error {
			props, err := manager.AccountProperties(addrmgrNs, acct)
			if err != nil {
				return err
			}
			accounts = append(accounts, AccountResult{
				AccountProperties: *props,
				// TotalBalance set below
			})

			return nil
		})
		if err != nil {
			return err
		}
		m := make(map[uint32]*btcutil.Amount)
		for i := range accounts {
			a := &accounts[i]
			m[a.AccountNumber] = &a.TotalBalance
		}
		for i := range unspent {
			output := unspent[i]
			var outputAcct uint32
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, w.chainParams)
			if err == nil && len(addrs) > 0 {
				_, outputAcct, err = w.addrStore.AddrAccount(addrmgrNs, addrs[0])
			}
			if err == nil {
				amt, ok := m[outputAcct]
				if ok {
					*amt += output.Amount
				}
			}
		}

		return nil
	})

	return &AccountsResult{
		Accounts:           accounts,
		CurrentBlockHash:   *syncBlockHash,
		CurrentBlockHeight: syncBlockHeight,
	}, err
}

// RenameAccountDeprecated sets the name for an account number to newName.
func (w *Wallet) RenameAccountDeprecated(scope waddrmgr.KeyScope,
	account uint32, newName string) error {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return err
	}

	var props *waddrmgr.AccountProperties
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		err := manager.RenameAccount(addrmgrNs, account, newName)
		if err != nil {
			return err
		}
		props, err = manager.AccountProperties(addrmgrNs, account)

		return err
	})
	if err == nil {
		w.NtfnServer.notifyAccountProperties(props)
	}

	return err
}

// ScriptForOutputDeprecated returns the address, witness program and redeem
// script for a given UTXO. An error is returned if the UTXO does not
// belong to our wallet or it is not a managed pubKey address.
//
// Deprecated: Use AddressManager.ScriptForOutput instead.
func (w *Wallet) ScriptForOutputDeprecated(output *wire.TxOut) (
	waddrmgr.ManagedPubKeyAddress, []byte, []byte, error) {

	script, err := w.ScriptForOutput(context.Background(), *output)
	if err != nil {
		return nil, nil, nil, err
	}

	addr := script.Addr
	pubKeyAddr, ok := addr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, nil, nil, fmt.Errorf("%w: addr %s",
			ErrNotPubKeyAddress, addr.Address())
	}

	return pubKeyAddr, script.WitnessProgram, script.RedeemScript, nil
}

// ComputeInputScript generates a complete InputScript for the passed
// transaction with the signature as defined within the passed
// SignDescriptor. This method is capable of generating the proper input
// script for both regular p2wkh output and p2wkh outputs nested within a
// regular p2sh output.
func (w *Wallet) ComputeInputScript(tx *wire.MsgTx, output *wire.TxOut,
	inputIndex int, sigHashes *txscript.TxSigHashes,
	hashType txscript.SigHashType, tweaker PrivKeyTweaker) (wire.TxWitness,
	[]byte, error) {

	walletAddr, witnessProgram, sigScript, err :=
		w.ScriptForOutputDeprecated(
			output,
		)
	if err != nil {
		return nil, nil, err
	}

	privKey, err := walletAddr.PrivKey()
	if err != nil {
		return nil, nil, err
	}

	// If we need to maybe tweak our private key, do it now.
	if tweaker != nil {
		privKey, err = tweaker(privKey)
		if err != nil {
			return nil, nil, err
		}
	}

	// We need to produce a Schnorr signature for p2tr key spend addresses.
	if txscript.IsPayToTaproot(output.PkScript) {
		// We can now generate a valid witness which will allow us to
		// spend this output.
		witnessScript, err := txscript.TaprootWitnessSignature(
			tx, sigHashes, inputIndex, output.Value,
			output.PkScript, hashType, privKey,
		)
		if err != nil {
			return nil, nil, err
		}

		return witnessScript, nil, nil
	}

	// Generate a valid witness stack for the input.
	witnessScript, err := txscript.WitnessSignature(
		tx, sigHashes, inputIndex, output.Value, witnessProgram,
		hashType, privKey, true,
	)
	if err != nil {
		return nil, nil, err
	}

	return witnessScript, sigScript, nil
}

var (
	// ErrNotMine is an error denoting that a Wallet instance is unable to
	// spend a specified output.
	ErrNotMine = errors.New("the passed output does not belong to the " +
		"wallet")
)

// OutputSelectionPolicy describes the rules for selecting an output from the
// wallet.
type OutputSelectionPolicy struct {
	Account               uint32
	RequiredConfirmations int32
}

func (p *OutputSelectionPolicy) meetsRequiredConfs(txHeight,
	curHeight int32) bool {

	return hasMinConfs(
		//nolint:gosec
		uint32(p.RequiredConfirmations), txHeight, curHeight,
	)
}

// UnspentOutputs fetches all unspent outputs from the wallet that match rules
// described in the passed policy.
func (w *Wallet) UnspentOutputs(policy OutputSelectionPolicy) ([]*TransactionOutput, error) {
	var outputResults []*TransactionOutput
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.addrStore.SyncedTo()

		// TODO: actually stream outputs from the db instead of fetching
		// all of them at once.
		outputs, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}

		for _, output := range outputs {
			// Ignore outputs that haven't reached the required
			// number of confirmations.
			if !policy.meetsRequiredConfs(output.Height, syncBlock.Height) {
				continue
			}

			// Ignore outputs that are not controlled by the account.
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript,
				w.chainParams)
			if err != nil || len(addrs) == 0 {
				// Cannot determine which account this belongs
				// to without a valid address.  TODO: Fix this
				// by saving outputs per account, or accounts
				// per output.
				continue
			}

			_, outputAcct, err := w.addrStore.AddrAccount(
				addrmgrNs, addrs[0],
			)
			if err != nil {
				return err
			}
			if outputAcct != policy.Account {
				continue
			}

			// Stakebase isn't exposed by wtxmgr so those will be
			// OutputKindNormal for now.
			outputSource := OutputKindNormal
			if output.FromCoinBase {
				outputSource = OutputKindCoinbase
			}

			result := &TransactionOutput{
				OutPoint: output.OutPoint,
				Output: wire.TxOut{
					Value:    int64(output.Amount),
					PkScript: output.PkScript,
				},
				OutputKind:      outputSource,
				ContainingBlock: BlockIdentity(output.Block),
				ReceiveTime:     output.Received,
			}
			outputResults = append(outputResults, result)
		}

		return nil
	})
	return outputResults, err
}

// FetchInputInfo queries for the wallet's knowledge of the passed outpoint. If
// the wallet determines this output is under its control, then the original
// full transaction, the target txout, the derivation info and the number of
// confirmations are returned. Otherwise, a non-nil error value of ErrNotMine
// is returned instead.
//
// NOTE: This method is kept for compatibility.
func (w *Wallet) FetchInputInfo(prevOut *wire.OutPoint) (*wire.MsgTx,
	*wire.TxOut, *psbt.Bip32Derivation, int64, error) {

	tx, txOut, confs, err := w.FetchOutpointInfo(prevOut)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	derivation, err := w.FetchDerivationInfo(txOut.PkScript)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	return tx, txOut, derivation, confs, nil
}

// fetchOutputAddr attempts to fetch the managed address corresponding to the
// passed output script. This function is used to look up the proper key which
// should be used to sign a specified input.
func (w *Wallet) fetchOutputAddr(script []byte) (waddrmgr.ManagedAddress, error) {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(script, w.chainParams)
	if err != nil {
		return nil, err
	}

	// If the case of a multi-sig output, several address may be extracted.
	// Therefore, we simply select the key for the first address we know
	// of.
	for _, addr := range addrs {
		addr, err := w.AddressInfoDeprecated(addr)
		if err == nil {
			return addr, nil
		}
	}

	return nil, ErrNotMine
}

// FetchOutpointInfo queries for the wallet's knowledge of the passed outpoint.
// If the wallet determines this output is under its control, the original full
// transaction, the target txout and the number of confirmations are returned.
// Otherwise, a non-nil error value of ErrNotMine is returned instead.
func (w *Wallet) FetchOutpointInfo(prevOut *wire.OutPoint) (*wire.MsgTx,
	*wire.TxOut, int64, error) {

	// We manually look up the output within the tx store.
	txid := &prevOut.Hash
	txDetail, err := UnstableAPI(w).TxDetails(txid)
	if err != nil {
		return nil, nil, 0, err
	} else if txDetail == nil {
		return nil, nil, 0, ErrNotMine
	}

	// With the output retrieved, we'll make an additional check to ensure
	// we actually have control of this output. We do this because the
	// check above only guarantees that the transaction is somehow relevant
	// to us, like in the event of us being the sender of the transaction.
	numOutputs := uint32(len(txDetail.TxRecord.MsgTx.TxOut))
	if prevOut.Index >= numOutputs {
		return nil, nil, 0, fmt.Errorf("invalid output index %v for "+
			"transaction with %v outputs", prevOut.Index,
			numOutputs)
	}

	// Exit early if the output doesn't belong to our wallet. We know it's
	// our UTXO iff the `TxDetails` has a credit record on this output.
	if !hasOutput(txDetail, prevOut.Index) {
		return nil, nil, 0, ErrNotMine
	}

	pkScript := txDetail.TxRecord.MsgTx.TxOut[prevOut.Index].PkScript

	// Determine the number of confirmations the output currently has.
	_, currentHeight, err := w.chainClient.GetBestBlock()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("unable to retrieve current "+
			"height: %w", err)
	}

	confs := int64(0)
	if txDetail.Block.Height != -1 {
		confs = int64(currentHeight - txDetail.Block.Height)
	}

	return &txDetail.TxRecord.MsgTx, &wire.TxOut{
		Value:    txDetail.TxRecord.MsgTx.TxOut[prevOut.Index].Value,
		PkScript: pkScript,
	}, confs, nil
}

// FetchDerivationInfo queries for the wallet's knowledge of the passed
// pkScript and constructs the derivation info and returns it.
func (w *Wallet) FetchDerivationInfo(pkScript []byte) (*psbt.Bip32Derivation,
	error) {

	addr, err := w.fetchOutputAddr(pkScript)
	if err != nil {
		return nil, err
	}

	pubKeyAddr, ok := addr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, ErrNotMine
	}
	keyScope, derivationPath, _ := pubKeyAddr.DerivationInfo()

	derivation := &psbt.Bip32Derivation{
		PubKey:               pubKeyAddr.PubKey().SerializeCompressed(),
		MasterKeyFingerprint: derivationPath.MasterKeyFingerprint,
		Bip32Path: []uint32{
			keyScope.Purpose + hdkeychain.HardenedKeyStart,
			keyScope.Coin + hdkeychain.HardenedKeyStart,
			derivationPath.Account,
			derivationPath.Branch,
			derivationPath.Index,
		},
	}

	return derivation, nil
}

// hasOutpoint takes an output identified by its output index and determines
// whether the TxDetails contains this output. If the TxDetails doesn't have
// this output, it means this output doesn't belong to our wallet.
//
// TODO(yy): implement this method on `TxDetails` and update the package
// `wtxmgr` instead.
func hasOutput(t *wtxmgr.TxDetails, outputIndex uint32) bool {
	for _, cred := range t.Credits {
		if outputIndex == cred.Index {
			return true
		}
	}

	return false
}

// CreateSimpleTx creates a new signed transaction spending unspent outputs with
// at least minconf confirmations spending to any number of address/amount
// pairs. Only unspent outputs belonging to the given key scope and account will
// be selected, unless a key scope is not specified. In that case, inputs from all
// accounts may be selected, no matter what key scope they belong to. This is
// done to handle the default account case, where a user wants to fund a PSBT
// with inputs regardless of their type (NP2WKH, P2WKH, etc.). Change and an
// appropriate transaction fee are automatically included, if necessary. All
// transaction creation through this function is serialized to prevent the
// creation of many transactions which spend the same outputs.
//
// A set of functional options can be passed in to apply modifications to the
// tx creation process such as using a custom change scope, which otherwise
// defaults to the same as the specified coin selection scope.
//
// NOTE: The dryRun argument can be set true to create a tx that doesn't alter
// the database. A tx created with this set to true SHOULD NOT be broadcast.
func (w *Wallet) CreateSimpleTx(coinSelectKeyScope *waddrmgr.KeyScope,
	account uint32, outputs []*wire.TxOut, minconf int32,
	satPerKb btcutil.Amount, coinSelectionStrategy CoinSelectionStrategy,
	dryRun bool, optFuncs ...TxCreateOption) (*txauthor.AuthoredTx, error) {

	opts := defaultTxCreateOptions()
	for _, optFunc := range optFuncs {
		optFunc(opts)
	}

	// If the change scope isn't set, then it should be the same as the
	// coin selection scope in order to match existing behavior.
	if opts.changeKeyScope == nil {
		opts.changeKeyScope = coinSelectKeyScope
	}

	req := createTxRequest{
		coinSelectKeyScope:    coinSelectKeyScope,
		changeKeyScope:        opts.changeKeyScope,
		account:               account,
		outputs:               outputs,
		minconf:               minconf,
		feeSatPerKB:           satPerKb,
		coinSelectionStrategy: coinSelectionStrategy,
		dryRun:                dryRun,
		resp:                  make(chan createTxResponse),
		selectUtxos:           opts.selectUtxos,
		allowUtxo:             opts.allowUtxo,
	}
	w.createTxRequests <- req
	resp := <-req.resp
	return resp.tx, resp.err
}

// FundPsbtDeprecated creates a fully populated PSBT packet that contains
// enough inputs to fund the outputs specified in the passed in packet with the
// specified fee rate. If there is change left, a change output from the wallet
// is added and the index of the change output is returned. If no custom change
// scope is specified, we will use the coin selection scope (if not nil) or the
// BIP0086 scope by default. Otherwise, no additional output is created and the
// index -1 is returned.
//
// NOTE: If the packet doesn't contain any inputs, coin selection is performed
// automatically, only selecting inputs from the account based on the given key
// scope and account number. If a key scope is not specified, then inputs from
// accounts matching the account number provided across all key scopes may be
// selected. This is done to handle the default account case, where a user wants
// to fund a PSBT with inputs regardless of their type (NP2WKH, P2WKH, etc.). If
// the packet does contain any inputs, it is assumed that full coin selection
// happened externally and no additional inputs are added. If the specified
// inputs aren't enough to fund the outputs with the given fee rate, an error is
// returned.
//
// NOTE: A caller of the method should hold the global coin selection lock of
// the wallet. However, no UTXO specific lock lease is acquired for any of the
// selected/validated inputs by this method. It is in the caller's
// responsibility to lock the inputs before handing the partial transaction out.
func (w *Wallet) FundPsbtDeprecated(packet *psbt.Packet, keyScope *waddrmgr.KeyScope,
	minConfs int32, account uint32, feeSatPerKB btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy,
	optFuncs ...TxCreateOption) (int32, error) {

	// Make sure the packet is well formed. We only require there to be at
	// least one input or output.
	err := psbt.VerifyInputOutputLen(packet, false, false)
	if err != nil {
		return 0, err
	}

	if len(packet.UnsignedTx.TxIn) == 0 && len(packet.UnsignedTx.TxOut) == 0 {
		return 0, fmt.Errorf("PSBT packet must contain at least one " +
			"input or output")
	}

	txOut := packet.UnsignedTx.TxOut
	txIn := packet.UnsignedTx.TxIn

	// Make sure none of the outputs are dust.
	for _, output := range txOut {
		// When checking an output for things like dusty-ness, we'll
		// use the default mempool relay fee rather than the target
		// effective fee rate to ensure accuracy. Otherwise, we may
		// mistakenly mark small-ish, but not quite dust output as
		// dust.
		err := txrules.CheckOutput(output, txrules.DefaultRelayFeePerKb)
		if err != nil {
			return 0, err
		}
	}

	// Let's find out the amount to fund first.
	amt := int64(0)
	for _, output := range txOut {
		amt += output.Value
	}

	var tx *txauthor.AuthoredTx
	switch {
	// We need to do coin selection.
	case len(txIn) == 0:
		// We ask the underlying wallet to fund a TX for us. This
		// includes everything we need, specifically fee estimation and
		// change address creation.
		tx, err = w.CreateSimpleTx(
			keyScope, account, packet.UnsignedTx.TxOut, minConfs,
			feeSatPerKB, coinSelectionStrategy, false,
			optFuncs...,
		)
		if err != nil {
			return 0, fmt.Errorf("error creating funding TX: %w",
				err)
		}

		// Copy over the inputs now then collect all UTXO information
		// that we can and attach them to the PSBT as well. We don't
		// include the witness as the resulting PSBT isn't expected not
		// should be signed yet.
		packet.UnsignedTx.TxIn = tx.Tx.TxIn
		packet.Inputs = make([]psbt.PInput, len(packet.UnsignedTx.TxIn))

		for idx := range packet.UnsignedTx.TxIn {
			// We don't want to include the witness or any script
			// on the unsigned TX just yet.
			packet.UnsignedTx.TxIn[idx].Witness = wire.TxWitness{}
			packet.UnsignedTx.TxIn[idx].SignatureScript = nil
		}

		err := w.DecorateInputsDeprecated(packet, true)
		if err != nil {
			return 0, err
		}

	// If there are inputs, we need to check if they're sufficient and add
	// a change output if necessary.
	default:
		// Make sure all inputs provided are actually ours.
		packet.Inputs = make([]psbt.PInput, len(packet.UnsignedTx.TxIn))

		for idx := range packet.UnsignedTx.TxIn {
			// We don't want to include the witness or any script
			// on the unsigned TX just yet.
			packet.UnsignedTx.TxIn[idx].Witness = wire.TxWitness{}
			packet.UnsignedTx.TxIn[idx].SignatureScript = nil
		}

		err := w.DecorateInputsDeprecated(packet, true)
		if err != nil {
			return 0, err
		}

		// We can leverage the fee calculation of the txauthor package
		// if we provide the selected UTXOs as a coin source. We just
		// need to make sure we always return the full list of user-
		// selected UTXOs rather than a subset, otherwise our change
		// amount will be off (in case the user selected multiple UTXOs
		// that are large enough on their own). That's why we use our
		// own static input source creator instead of the more generic
		// makeInputSource() that selects a subset that is "large
		// enough".
		credits := make([]wtxmgr.Credit, len(txIn))
		for idx, in := range txIn {
			utxo := packet.Inputs[idx].WitnessUtxo
			credits[idx] = wtxmgr.Credit{
				OutPoint: in.PreviousOutPoint,
				Amount:   btcutil.Amount(utxo.Value),
				PkScript: utxo.PkScript,
			}
		}
		inputSource := constantInputSource(credits)

		// Build the TxCreateOption to retrieve the change scope.
		opts := defaultTxCreateOptions()
		for _, optFunc := range optFuncs {
			optFunc(opts)
		}

		if opts.changeKeyScope == nil {
			opts.changeKeyScope = keyScope
		}

		// The addrMgrWithChangeSource function of the wallet creates a
		// new change address. The address manager uses OnCommit on the
		// walletdb tx to update the in-memory state of the account
		// state. But because the commit happens _after_ the account
		// manager internal lock has been released, there is a chance
		// for the address index to be accessed concurrently, even
		// though the closure in OnCommit re-acquires the lock. To avoid
		// this issue, we surround the whole address creation process
		// with a lock.
		w.newAddrMtx.Lock()

		// We also need a change source which needs to be able to insert
		// a new change address into the database.
		err = walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
			_, changeSource, err := w.addrMgrWithChangeSource(
				dbtx, opts.changeKeyScope, account,
			)
			if err != nil {
				return err
			}

			// Ask the txauthor to create a transaction with our
			// selected coins. This will perform fee estimation and
			// add a change output if necessary.
			tx, err = txauthor.NewUnsignedTransaction(
				txOut, feeSatPerKB, inputSource, changeSource,
			)
			if err != nil {
				return fmt.Errorf("fee estimation not "+
					"successful: %w", err)
			}

			return nil
		})
		w.newAddrMtx.Unlock()

		if err != nil {
			return 0, fmt.Errorf("could not add change address to "+
				"database: %w", err)
		}
	}

	// If there is a change output, we need to copy it over to the PSBT now.
	var changeTxOut *wire.TxOut
	if tx.ChangeIndex >= 0 {
		changeTxOut = tx.Tx.TxOut[tx.ChangeIndex]
		packet.UnsignedTx.TxOut = append(
			packet.UnsignedTx.TxOut, changeTxOut,
		)

		addr, _, _, err := w.ScriptForOutputDeprecated(changeTxOut)
		if err != nil {
			return 0, fmt.Errorf("error querying wallet for "+
				"change addr: %w", err)
		}

		changeOutputInfo, err := createOutputInfo(changeTxOut, addr)
		if err != nil {
			return 0, fmt.Errorf("error adding output info to "+
				"change output: %w", err)
		}

		packet.Outputs = append(packet.Outputs, *changeOutputInfo)
	}

	// Now that we have the final PSBT ready, we can sort it according to
	// BIP 69. This will sort the wire inputs and outputs and move the
	// partial inputs and outputs accordingly.
	err = psbt.InPlaceSort(packet)
	if err != nil {
		return 0, fmt.Errorf("could not sort PSBT: %w", err)
	}

	// The change output index might have changed after the sorting. We need
	// to find our index again.
	changeIndex := int32(-1)
	if changeTxOut != nil {
		for idx, txOut := range packet.UnsignedTx.TxOut {
			if psbt.TxOutsEqual(changeTxOut, txOut) {
				changeIndex = int32(idx)
				break
			}
		}
	}

	return changeIndex, nil
}

// DecorateInputsDeprecated fetches the UTXO information of all inputs it can identify and
// adds the required information to the package's inputs. The failOnUnknown
// boolean controls whether the method should return an error if it cannot
// identify an input or if it should just skip it.
func (w *Wallet) DecorateInputsDeprecated(packet *psbt.Packet, failOnUnknown bool) error {
	for idx := range packet.Inputs {
		txIn := packet.UnsignedTx.TxIn[idx]

		tx, utxo, derivationPath, _, err := w.FetchInputInfo(
			&txIn.PreviousOutPoint,
		)

		switch {
		// If the error just means it's not an input our wallet controls
		// and the user doesn't care about that, then we can just skip
		// this input and continue.
		case errors.Is(err, ErrNotMine) && !failOnUnknown:
			continue

		case err != nil:
			return fmt.Errorf("error fetching UTXO: %w", err)
		}

		addr, witnessProgram, _, err := w.ScriptForOutputDeprecated(
			utxo,
		)
		if err != nil {
			return fmt.Errorf("error fetching UTXO script: %w", err)
		}

		switch {
		case txscript.IsPayToTaproot(utxo.PkScript):
			addInputInfoSegWitV1(
				&packet.Inputs[idx], utxo, derivationPath,
			)

		default:
			addInputInfoSegWitV0(
				&packet.Inputs[idx], tx, utxo, derivationPath,
				addr, witnessProgram,
			)
		}
	}

	return nil
}

// FinalizePsbtDeprecated expects a partial transaction with all inputs and outputs fully
// declared and tries to sign all inputs that belong to the wallet. Our wallet
// must be the last signer of the transaction. That means, if there are any
// unsigned non-witness inputs or inputs without UTXO information attached or
// inputs without witness data that do not belong to the wallet, this method
// will fail. If no error is returned, the PSBT is ready to be extracted and the
// final TX within to be broadcast.
//
// NOTE: This method does NOT publish the transaction after it's been finalized
// successfully.
func (w *Wallet) FinalizePsbtDeprecated(keyScope *waddrmgr.KeyScope, account uint32,
	packet *psbt.Packet) error {

	// Let's check that this is actually something we can and want to sign.
	// We need at least one input and one output. In addition each
	// input needs nonWitness Utxo or witness Utxo data specified.
	err := psbt.InputsReadyToSign(packet)
	if err != nil {
		return err
	}

	// Go through each input that doesn't have final witness data attached
	// to it already and try to sign it. We do expect that we're the last
	// ones to sign. If there is any input without witness data that we
	// cannot sign because it's not our UTXO, this will be a hard failure.
	tx := packet.UnsignedTx
	fetcher, err := PsbtPrevOutputFetcher(packet)
	if err != nil {
		return err
	}
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	for idx, txIn := range tx.TxIn {
		in := packet.Inputs[idx]

		// We can only sign if we have UTXO information available. We
		// can just continue here as a later step will fail with a more
		// precise error message.
		if in.WitnessUtxo == nil && in.NonWitnessUtxo == nil {
			continue
		}

		// Skip this input if it's got final witness data attached.
		if len(in.FinalScriptWitness) > 0 {
			continue
		}

		// We can only sign this input if it's ours, so we try to map it
		// to a coin we own. If we can't, then we'll continue as it
		// isn't our input.
		fullTx, txOut, _, _, err := w.FetchInputInfo(
			&txIn.PreviousOutPoint,
		)
		if err != nil {
			continue
		}

		// Find out what UTXO we are signing. Wallets _should_ always
		// provide the full non-witness UTXO for segwit v0.
		var signOutput *wire.TxOut
		if in.NonWitnessUtxo != nil {
			prevIndex := txIn.PreviousOutPoint.Index
			signOutput = in.NonWitnessUtxo.TxOut[prevIndex]

			if !psbt.TxOutsEqual(txOut, signOutput) {
				return fmt.Errorf("found UTXO %#v but it "+
					"doesn't match PSBT's input %v", txOut,
					signOutput)
			}

			if fullTx.TxHash() != txIn.PreviousOutPoint.Hash {
				return fmt.Errorf("found UTXO tx %v but it "+
					"doesn't match PSBT's input %v",
					fullTx.TxHash(),
					txIn.PreviousOutPoint.Hash)
			}
		}

		// Fall back to witness UTXO only for older wallets.
		if in.WitnessUtxo != nil {
			signOutput = in.WitnessUtxo

			if !psbt.TxOutsEqual(txOut, signOutput) {
				return fmt.Errorf("found UTXO %#v but it "+
					"doesn't match PSBT's input %v", txOut,
					signOutput)
			}
		}

		// Finally, if the input doesn't belong to a watch-only account,
		// then we'll sign it as is, and populate the input with the
		// witness and sigScript (if needed).
		watchOnly := false
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			ns := tx.ReadBucket(waddrmgrNamespaceKey)
			var err error
			if keyScope == nil {
				// If a key scope wasn't specified, then coin
				// selection was performed from the default
				// wallet accounts (NP2WKH, P2WKH, P2TR), so any
				// key scope provided doesn't impact the result
				// of this call.
				watchOnly, err = w.addrStore.IsWatchOnlyAccount(
					ns, waddrmgr.KeyScopeBIP0084, account,
				)
			} else {
				watchOnly, err = w.addrStore.IsWatchOnlyAccount(
					ns, *keyScope, account,
				)
			}
			return err
		})
		if err != nil {
			return fmt.Errorf("unable to determine if account is "+
				"watch-only: %w", err)
		}
		if watchOnly {
			continue
		}

		witness, sigScript, err := w.ComputeInputScript(
			tx, signOutput, idx, sigHashes, in.SighashType, nil,
		)
		if err != nil {
			return fmt.Errorf("error computing input script for "+
				"input %d: %w", idx, err)
		}

		// Serialize the witness format from the stack representation to
		// the wire representation.
		var witnessBytes bytes.Buffer
		err = psbt.WriteTxWitness(&witnessBytes, witness)
		if err != nil {
			return fmt.Errorf("error serializing witness: %w", err)
		}
		packet.Inputs[idx].FinalScriptWitness = witnessBytes.Bytes()
		packet.Inputs[idx].FinalScriptSig = sigScript
	}

	// Make sure the PSBT itself thinks it's finalized and ready to be
	// broadcast.
	err = psbt.MaybeFinalizeAll(packet)
	if err != nil {
		return fmt.Errorf("error finalizing PSBT: %w", err)
	}

	return nil
}

// StartDeprecated starts the goroutines necessary to manage a wallet.
//
// Deprecated: Use WalletController.Start instead.
func (w *Wallet) StartDeprecated() {
	w.quitMu.Lock()
	select {
	case <-w.quit:
		// Restart the wallet goroutines after shutdown finishes.
		w.WaitForShutdown()
		w.quit = make(chan struct{})
	default:
		// Ignore when the wallet is still running.
		if w.started {
			w.quitMu.Unlock()
			return
		}
		w.started = true
	}
	w.quitMu.Unlock()

	w.wg.Add(2)
	go w.txCreator()
	go w.walletLocker()
}

// StopDeprecated signals all wallet goroutines to shutdown.
//
// Deprecated: Use WalletController.Stop instead.
func (w *Wallet) StopDeprecated() {
	<-w.endRecovery()

	w.quitMu.Lock()
	quit := w.quit
	w.quitMu.Unlock()

	select {
	case <-quit:
	default:
		close(quit)
		w.chainClientLock.Lock()
		if w.chainClient != nil {
			w.chainClient.Stop()
			w.chainClient = nil
		}
		w.chainClientLock.Unlock()
	}
}

// UnlockDeprecated unlocks the wallet's address manager and relocks it after timeout has
// expired.  If the wallet is already unlocked and the new passphrase is
// correct, the current timeout is replaced with the new one.  The wallet will
// be locked if the passphrase is incorrect or any other error occurs during the
// unlock.
//
// Deprecated: Use WalletController.Unlock instead.
func (w *Wallet) UnlockDeprecated(passphrase []byte, lock <-chan time.Time) error {
	err := make(chan error, 1)
	w.unlockRequests <- unlockRequest{
		passphrase: passphrase,
		lockAfter:  lock,
		err:        err,
	}
	return <-err
}

// LockDeprecated locks the wallet's address manager.
//
// Deprecated: Use WalletController.Lock instead.
func (w *Wallet) LockDeprecated() {
	w.lockRequests <- struct{}{}
}

// AddressInfoDeprecated returns detailed information regarding a wallet
// address.
func (w *Wallet) AddressInfoDeprecated(a btcutil.Address) (
	waddrmgr.ManagedAddress, error) {

	var managedAddress waddrmgr.ManagedAddress
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error

		managedAddress, err = w.addrStore.Address(addrmgrNs, a)
		return err
	})
	return managedAddress, err
}

// SynchronizeRPC associates the wallet with the consensus RPC client,
// synchronizes the wallet with the latest changes to the blockchain, and
// continuously updates the wallet through RPC notifications.
//
// This method is unstable and will be removed when all syncing logic is moved
// outside of the wallet package.
func (w *Wallet) SynchronizeRPC(chainClient chain.Interface) {
	w.quitMu.Lock()
	select {
	case <-w.quit:
		w.quitMu.Unlock()
		return
	default:
	}
	w.quitMu.Unlock()

	// TODO: Ignoring the new client when one is already set breaks callers
	// who are replacing the client, perhaps after a disconnect.
	w.chainClientLock.Lock()
	if w.chainClient != nil {
		w.chainClientLock.Unlock()
		return
	}
	w.chainClient = chainClient

	// If the chain client is a NeutrinoClient instance, set a birthday so
	// we don't download all the filters as we go.
	switch cc := chainClient.(type) {
	case *chain.NeutrinoClient:
		cc.SetStartTime(w.addrStore.Birthday())
	case *chain.BitcoindClient:
		cc.SetBirthday(w.addrStore.Birthday())
	}
	w.chainClientLock.Unlock()

	// TODO: It would be preferable to either run these goroutines
	// separately from the wallet (use wallet mutator functions to
	// make changes from the RPC client) and not have to stop and
	// restart them each time the client disconnects and reconnets.
	w.wg.Add(4)
	go w.handleChainNotifications()
	go w.rescanBatchHandler()
	go w.rescanProgressHandler()
	go w.rescanRPCHandler()
}

// requireChainClient marks that a wallet method can only be completed when the
// consensus RPC server is set.  This function and all functions that call it
// are unstable and will need to be moved when the syncing code is moved out of
// the wallet.
func (w *Wallet) requireChainClient() (chain.Interface, error) {
	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()
	if chainClient == nil {
		return nil, errors.New("blockchain RPC is inactive")
	}
	return chainClient, nil
}

// ChainClient returns the optional consensus RPC client associated with the
// wallet.
//
// This function is unstable and will be removed once sync logic is moved out of
// the wallet.
func (w *Wallet) ChainClient() chain.Interface {
	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()
	return chainClient
}

// quitChan atomically reads the quit channel.
func (w *Wallet) quitChan() <-chan struct{} {
	w.quitMu.Lock()
	c := w.quit
	w.quitMu.Unlock()
	return c
}

// ShuttingDown returns whether the wallet is currently in the process of
// shutting down or not.
func (w *Wallet) ShuttingDown() bool {
	select {
	case <-w.quitChan():
		return true
	default:
		return false
	}
}

// WaitForShutdown blocks until all wallet goroutines have finished executing.
func (w *Wallet) WaitForShutdown() {
	w.chainClientLock.Lock()
	if w.chainClient != nil {
		w.chainClient.WaitForShutdown()
	}
	w.chainClientLock.Unlock()
	w.wg.Wait()
}

// SynchronizingToNetwork returns whether the wallet is currently synchronizing
// with the Bitcoin network.
func (w *Wallet) SynchronizingToNetwork() bool {
	// At the moment, RPC is the only synchronization method.  In the
	// future, when SPV is added, a separate check will also be needed, or
	// SPV could always be enabled if RPC was not explicitly specified when
	// creating the wallet.
	w.chainClientSyncMtx.Lock()
	syncing := w.chainClient != nil
	w.chainClientSyncMtx.Unlock()
	return syncing
}

// ChainSynced returns whether the wallet has been attached to a chain server
// and synced up to the best block on the main chain.
func (w *Wallet) ChainSynced() bool {
	w.chainClientSyncMtx.Lock()
	synced := w.chainClientSynced
	w.chainClientSyncMtx.Unlock()
	return synced
}

// SetChainSynced marks whether the wallet is connected to and currently in sync
// with the latest block notified by the chain server.
//
// NOTE: Due to an API limitation with rpcclient, this may return true after
// the client disconnected (and is attempting a reconnect).  This will be unknown
// until the reconnect notification is received, at which point the wallet can be
// marked out of sync again until after the next rescan completes.
func (w *Wallet) SetChainSynced(synced bool) {
	w.chainClientSyncMtx.Lock()
	w.chainClientSynced = synced
	w.chainClientSyncMtx.Unlock()
}

// activeData returns the currently-active receiving addresses and all unspent
// outputs.  This is primarely intended to provide the parameters for a
// rescan request.
func (w *Wallet) activeData(dbtx walletdb.ReadWriteTx) ([]btcutil.Address, []wtxmgr.Credit, error) {
	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	var addrs []btcutil.Address

	err := w.addrStore.ForEachRelevantActiveAddress(
		addrmgrNs, func(addr btcutil.Address) error {
			addrs = append(addrs, addr)
			return nil
		},
	)
	if err != nil {
		return nil, nil, err
	}

	// Before requesting the list of spendable UTXOs, we'll delete any
	// expired output locks.
	err = w.txStore.DeleteExpiredLockedOutputs(
		dbtx.ReadWriteBucket(wtxmgrNamespaceKey),
	)
	if err != nil {
		return nil, nil, err
	}

	unspent, err := w.txStore.OutputsToWatch(txmgrNs)
	return addrs, unspent, err
}

// syncWithChain brings the wallet up to date with the current chain server
// connection. It creates a rescan request and blocks until the rescan has
// finished. The birthday block can be passed in, if set, to ensure we can
// properly detect if it gets rolled back.
func (w *Wallet) syncWithChain(birthdayStamp *waddrmgr.BlockStamp) error {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	// Neutrino relies on the information given to it by the cfheader server
	// so it knows exactly whether it's synced up to the server's state or
	// not, even on dev chains. To recover a Neutrino wallet, we need to
	// make sure it's synced before we start scanning for addresses,
	// otherwise we might miss some if we only scan up to its current sync
	// point.
	neutrinoRecovery := chainClient.BackEnd() == "neutrino" &&
		w.recoveryWindow > 0

	// We'll wait until the backend is synced to ensure we get the latest
	// MaxReorgDepth blocks to store. We don't do this for development
	// environments as we can't guarantee a lively chain, except for
	// Neutrino, where the cfheader server tells us what it believes the
	// chain tip is.
	if !w.isDevEnv() || neutrinoRecovery {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return err
		}
		log.Debug("Chain backend synced to tip!")
	}

	// If we've yet to find our birthday block, we'll do so now.
	if birthdayStamp == nil {
		var err error
		birthdayStamp, err = locateBirthdayBlock(
			chainClient, w.addrStore.Birthday(),
		)
		if err != nil {
			return fmt.Errorf("unable to locate birthday block: %w",
				err)
		}

		// We'll also determine our initial sync starting height. This
		// is needed as the wallet can now begin storing blocks from an
		// arbitrary height, rather than all the blocks from genesis, so
		// we persist this height to ensure we don't store any blocks
		// before it.
		startHeight := birthdayStamp.Height

		// With the starting height obtained, get the remaining block
		// details required by the wallet.
		startHash, err := chainClient.GetBlockHash(int64(startHeight))
		if err != nil {
			return err
		}
		startHeader, err := chainClient.GetBlockHeader(startHash)
		if err != nil {
			return err
		}

		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			err := w.addrStore.SetSyncedTo(ns, &waddrmgr.BlockStamp{
				Hash:      *startHash,
				Height:    startHeight,
				Timestamp: startHeader.Timestamp,
			})
			if err != nil {
				return err
			}

			return w.addrStore.SetBirthdayBlock(
				ns, *birthdayStamp, true,
			)
		})
		if err != nil {
			return fmt.Errorf("unable to persist initial sync "+
				"data: %w", err)
		}
	}

	// If the wallet requested an on-chain recovery of its funds, we'll do
	// so now.
	if w.recoveryWindow > 0 {
		if err := w.recovery(chainClient, birthdayStamp); err != nil {
			return fmt.Errorf("unable to perform wallet recovery: "+
				"%w", err)
		}
	}

	// Compare previously-seen blocks against the current chain. If any of
	// these blocks no longer exist, rollback all of the missing blocks
	// before catching up with the rescan.
	rollback := false
	rollbackStamp := w.addrStore.SyncedTo()
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		for height := rollbackStamp.Height; true; height-- {
			hash, err := w.addrStore.BlockHash(addrmgrNs, height)
			if err != nil {
				return err
			}
			chainHash, err := chainClient.GetBlockHash(int64(height))
			if err != nil {
				return err
			}
			header, err := chainClient.GetBlockHeader(chainHash)
			if err != nil {
				return err
			}

			rollbackStamp.Hash = *chainHash
			rollbackStamp.Height = height
			rollbackStamp.Timestamp = header.Timestamp

			if bytes.Equal(hash[:], chainHash[:]) {
				break
			}
			rollback = true
		}

		// If a rollback did not happen, we can proceed safely.
		if !rollback {
			return nil
		}

		// Otherwise, we'll mark this as our new synced height.
		err := w.addrStore.SetSyncedTo(addrmgrNs, &rollbackStamp)
		if err != nil {
			return err
		}

		// If the rollback happened to go beyond our birthday stamp,
		// we'll need to find a new one by syncing with the chain again
		// until finding one.
		if rollbackStamp.Height <= birthdayStamp.Height &&
			rollbackStamp.Hash != birthdayStamp.Hash {

			err := w.addrStore.SetBirthdayBlock(
				addrmgrNs, rollbackStamp, true,
			)
			if err != nil {
				return err
			}
		}

		// Finally, we'll roll back our transaction store to reflect the
		// stale state. `Rollback` unconfirms transactions at and beyond
		// the passed height, so add one to the new synced-to height to
		// prevent unconfirming transactions in the synced-to block.
		return w.txStore.Rollback(txmgrNs, rollbackStamp.Height+1)
	})
	if err != nil {
		return err
	}

	// Request notifications for connected and disconnected blocks.
	//
	// TODO(jrick): Either request this notification only once, or when
	// rpcclient is modified to allow some notification request to not
	// automatically resent on reconnect, include the notifyblocks request
	// as well.  I am leaning towards allowing off all rpcclient
	// notification re-registrations, in which case the code here should be
	// left as is.
	if err := chainClient.NotifyBlocks(); err != nil {
		return err
	}

	// Finally, we'll trigger a wallet rescan and request notifications for
	// transactions sending to all wallet addresses and spending all wallet
	// UTXOs.
	var (
		addrs   []btcutil.Address
		unspent []wtxmgr.Credit
	)
	err = walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		addrs, unspent, err = w.activeData(dbtx)
		return err
	})
	if err != nil {
		return err
	}

	return w.rescanWithTarget(addrs, unspent, nil)
}

// isDevEnv determines whether the wallet is currently under a local developer
// environment, e.g. simnet or regtest.
func (w *Wallet) isDevEnv() bool {
	switch uint32(w.ChainParams().Net) {
	case uint32(chaincfg.RegressionNetParams.Net):
	case uint32(chaincfg.SimNetParams.Net):
	default:
		return false
	}
	return true
}

// waitUntilBackendSynced blocks until the chain backend considers itself
// "current".
func (w *Wallet) waitUntilBackendSynced(chainClient chain.Interface) error {
	// We'll poll every second to determine if our chain considers itself
	// "current".
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if chainClient.IsCurrent() {
				return nil
			}
		case <-w.quitChan():
			return ErrWalletShuttingDown
		}
	}
}

// recoverySyncer is used to synchronize wallet and address manager locking
// with the end of recovery. (*Wallet).recovery will store a recoverySyncer
// when invoked, and will close the done chan upon exit. Setting the quit flag
// will cause recovery to end after the current batch of blocks.
type recoverySyncer struct {
	done chan struct{}
	quit uint32 // atomic
}

// recovery attempts to recover any unspent outputs that pay to any of our
// addresses starting from our birthday, or the wallet's tip (if higher), which
// would indicate resuming a recovery after a restart.
func (w *Wallet) recovery(chainClient chain.Interface,
	birthdayBlock *waddrmgr.BlockStamp) error {

	log.Infof("RECOVERY MODE ENABLED -- rescanning for used addresses "+
		"with recovery_window=%d", w.recoveryWindow)

	// Wallet locking must synchronize with the end of recovery, since use of
	// keys in recovery is racy with manager IsLocked checks, which could
	// result in enrypting data with a zeroed key.
	syncer := &recoverySyncer{done: make(chan struct{})}
	w.recovering.Store(syncer)
	defer close(syncer.done)

	// We'll initialize the recovery manager with a default batch size of
	// 2000.
	recoveryMgr := NewRecoveryManager(
		w.recoveryWindow, recoveryBatchSize, w.chainParams,
	)

	// In the event that this recovery is being resumed, we will need to
	// repopulate all found addresses from the database. Ideally, for basic
	// recovery, we would only do so for the default scopes, but due to a
	// bug in which the wallet would create change addresses outside of the
	// default scopes, it's necessary to attempt all registered key scopes.
	scopedMgrs := make(map[waddrmgr.KeyScope]waddrmgr.AccountStore)
	for _, scopedMgr := range w.addrStore.ActiveScopedKeyManagers() {
		scopedMgrs[scopedMgr.Scope()] = scopedMgr
	}
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txMgrNS := tx.ReadBucket(wtxmgrNamespaceKey)

		credits, err := w.txStore.UnspentOutputs(txMgrNS)
		if err != nil {
			return err
		}
		addrMgrNS := tx.ReadBucket(waddrmgrNamespaceKey)
		return recoveryMgr.Resurrect(addrMgrNS, scopedMgrs, credits)
	})
	if err != nil {
		return err
	}

	// Fetch the best height from the backend to determine when we should
	// stop.
	_, bestHeight, err := chainClient.GetBestBlock()
	if err != nil {
		return err
	}

	// Now we can begin scanning the chain from the wallet's current tip to
	// ensure we properly handle restarts. Since the recovery process itself
	// acts as rescan, we'll also update our wallet's synced state along the
	// way to reflect the blocks we process and prevent rescanning them
	// later on.
	//
	// NOTE: We purposefully don't update our best height since we assume
	// that a wallet rescan will be performed from the wallet's tip, which
	// will be of bestHeight after completing the recovery process.
	var blocks []*waddrmgr.BlockStamp

	startHeight := w.addrStore.SyncedTo().Height + 1
	for height := startHeight; height <= bestHeight; height++ {
		if atomic.LoadUint32(&syncer.quit) == 1 {
			return errors.New("recovery: forced shutdown")
		}

		hash, err := chainClient.GetBlockHash(int64(height))
		if err != nil {
			return err
		}
		header, err := chainClient.GetBlockHeader(hash)
		if err != nil {
			return err
		}
		blocks = append(blocks, &waddrmgr.BlockStamp{
			Hash:      *hash,
			Height:    height,
			Timestamp: header.Timestamp,
		})

		// It's possible for us to run into blocks before our birthday
		// if our birthday is after our reorg safe height, so we'll make
		// sure to not add those to the batch.
		if height >= birthdayBlock.Height {
			recoveryMgr.AddToBlockBatch(
				hash, height, header.Timestamp,
			)
		}

		// We'll perform our recovery in batches of 2000 blocks.  It's
		// possible for us to reach our best height without exceeding
		// the recovery batch size, so we can proceed to commit our
		// state to disk.
		recoveryBatch := recoveryMgr.BlockBatch()
		if len(recoveryBatch) == recoveryBatchSize || height == bestHeight {
			err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				if err := w.recoverScopedAddresses(
					chainClient, tx, ns, recoveryBatch,
					recoveryMgr.State(), scopedMgrs,
				); err != nil {
					return err
				}

				// TODO: Any error here will roll back this
				// entire tx. This may cause the in memory sync
				// point to become desyncronized. Refactor so
				// that this cannot happen.
				for _, block := range blocks {
					err := w.addrStore.SetSyncedTo(
						ns, block,
					)
					if err != nil {
						return err
					}
				}

				return nil
			})
			if err != nil {
				return err
			}

			if len(recoveryBatch) > 0 {
				log.Infof("Recovered addresses from blocks "+
					"%d-%d", recoveryBatch[0].Height,
					recoveryBatch[len(recoveryBatch)-1].Height)
			}

			// Clear the batch of all processed blocks to reuse the
			// same memory for future batches.
			blocks = blocks[:0]
			recoveryMgr.ResetBlockBatch()
		}
	}

	return nil
}

// recoverScopedAddresses scans a range of blocks in attempts to recover any
// previously used addresses for a particular account derivation path. At a high
// level, the algorithm works as follows:
//
//  1. Ensure internal and external branch horizons are fully expanded.
//  2. Filter the entire range of blocks, stopping if a non-zero number of
//     address are contained in a particular block.
//  3. Record all internal and external addresses found in the block.
//  4. Record any outpoints found in the block that should be watched for spends
//  5. Trim the range of blocks up to and including the one reporting the addrs.
//  6. Repeat from (1) if there are still more blocks in the range.
//
// TODO(conner): parallelize/pipeline/cache intermediate network requests
func (w *Wallet) recoverScopedAddresses(
	chainClient chain.Interface,
	tx walletdb.ReadWriteTx,
	ns walletdb.ReadWriteBucket,
	batch []wtxmgr.BlockMeta,
	recoveryState *RecoveryState,
	scopedMgrs map[waddrmgr.KeyScope]waddrmgr.AccountStore) error {

	// If there are no blocks in the batch, we are done.
	if len(batch) == 0 {
		return nil
	}

	log.Infof("Scanning %d blocks for recoverable addresses", len(batch))

expandHorizons:
	for scope, scopedMgr := range scopedMgrs {
		scopeState := recoveryState.StateForScope(scope)
		err := expandScopeHorizons(ns, scopedMgr, scopeState)
		if err != nil {
			return err
		}
	}

	// With the internal and external horizons properly expanded, we now
	// construct the filter blocks request. The request includes the range
	// of blocks we intend to scan, in addition to the scope-index -> addr
	// map for all internal and external branches.
	filterReq := newFilterBlocksRequest(batch, scopedMgrs, recoveryState)

	// Initiate the filter blocks request using our chain backend. If an
	// error occurs, we are unable to proceed with the recovery.
	filterResp, err := chainClient.FilterBlocks(filterReq)
	if err != nil {
		return err
	}

	// If the filter response is empty, this signals that the rest of the
	// batch was completed, and no other addresses were discovered. As a
	// result, no further modifications to our recovery state are required
	// and we can proceed to the next batch.
	if filterResp == nil {
		return nil
	}

	// Otherwise, retrieve the block info for the block that detected a
	// non-zero number of address matches.
	block := batch[filterResp.BatchIndex]

	// Log any non-trivial findings of addresses or outpoints.
	logFilterBlocksResp(block, filterResp)

	// Report any external or internal addresses found as a result of the
	// appropriate branch recovery state. Adding indexes above the
	// last-found index of either will result in the horizons being expanded
	// upon the next iteration. Any found addresses are also marked used
	// using the scoped key manager.
	err = extendFoundAddresses(ns, filterResp, scopedMgrs, recoveryState)
	if err != nil {
		return err
	}

	// Update the global set of watched outpoints with any that were found
	// in the block.
	for outPoint, addr := range filterResp.FoundOutPoints {
		outPoint := outPoint
		recoveryState.AddWatchedOutPoint(&outPoint, addr)
	}

	// Finally, record all of the relevant transactions that were returned
	// in the filter blocks response. This ensures that these transactions
	// and their outputs are tracked when the final rescan is performed.
	for _, txn := range filterResp.RelevantTxns {
		txRecord, err := wtxmgr.NewTxRecordFromMsgTx(
			txn, filterResp.BlockMeta.Time,
		)
		if err != nil {
			return err
		}

		err = w.addRelevantTx(tx, txRecord, &filterResp.BlockMeta)
		if err != nil {
			return err
		}
	}

	// Update the batch to indicate that we've processed all block through
	// the one that returned found addresses.
	batch = batch[filterResp.BatchIndex+1:]

	// If this was not the last block in the batch, we will repeat the
	// filtering process again after expanding our horizons.
	if len(batch) > 0 {
		goto expandHorizons
	}

	return nil
}

// expandScopeHorizons ensures that the ScopeRecoveryState has an adequately
// sized look ahead for both its internal and external branches. The keys
// derived here are added to the scope's recovery state, but do not affect the
// persistent state of the wallet. If any invalid child keys are detected, the
// horizon will be properly extended such that our lookahead always includes the
// proper number of valid child keys.
func expandScopeHorizons(ns walletdb.ReadWriteBucket,
	scopedMgr waddrmgr.AccountStore,
	scopeState *ScopeRecoveryState) error {

	// Compute the current external horizon and the number of addresses we
	// must derive to ensure we maintain a sufficient recovery window for
	// the external branch.
	exHorizon, exWindow := scopeState.ExternalBranch.ExtendHorizon()
	count, childIndex := uint32(0), exHorizon
	for count < exWindow {
		keyPath := externalKeyPath(childIndex)
		addr, err := scopedMgr.DeriveFromKeyPath(ns, keyPath)
		switch {
		case err == hdkeychain.ErrInvalidChild:
			// Record the existence of an invalid child with the
			// external branch's recovery state. This also
			// increments the branch's horizon so that it accounts
			// for this skipped child index.
			scopeState.ExternalBranch.MarkInvalidChild(childIndex)
			childIndex++
			continue

		case err != nil:
			return err
		}

		// Register the newly generated external address and child index
		// with the external branch recovery state.
		scopeState.ExternalBranch.AddAddr(childIndex, addr.Address())

		childIndex++
		count++
	}

	// Compute the current internal horizon and the number of addresses we
	// must derive to ensure we maintain a sufficient recovery window for
	// the internal branch.
	inHorizon, inWindow := scopeState.InternalBranch.ExtendHorizon()
	count, childIndex = 0, inHorizon
	for count < inWindow {
		keyPath := internalKeyPath(childIndex)
		addr, err := scopedMgr.DeriveFromKeyPath(ns, keyPath)
		switch {
		case err == hdkeychain.ErrInvalidChild:
			// Record the existence of an invalid child with the
			// internal branch's recovery state. This also
			// increments the branch's horizon so that it accounts
			// for this skipped child index.
			scopeState.InternalBranch.MarkInvalidChild(childIndex)
			childIndex++
			continue

		case err != nil:
			return err
		}

		// Register the newly generated internal address and child index
		// with the internal branch recovery state.
		scopeState.InternalBranch.AddAddr(childIndex, addr.Address())

		childIndex++
		count++
	}

	return nil
}

// externalKeyPath returns the relative external derivation path /0/0/index.
func externalKeyPath(index uint32) waddrmgr.DerivationPath {
	return waddrmgr.DerivationPath{
		InternalAccount: waddrmgr.DefaultAccountNum,
		Account:         waddrmgr.DefaultAccountNum,
		Branch:          waddrmgr.ExternalBranch,
		Index:           index,
	}
}

// internalKeyPath returns the relative internal derivation path /0/1/index.
func internalKeyPath(index uint32) waddrmgr.DerivationPath {
	return waddrmgr.DerivationPath{
		InternalAccount: waddrmgr.DefaultAccountNum,
		Account:         waddrmgr.DefaultAccountNum,
		Branch:          waddrmgr.InternalBranch,
		Index:           index,
	}
}

// newFilterBlocksRequest constructs FilterBlocksRequests using our current
// block range, scoped managers, and recovery state.
func newFilterBlocksRequest(batch []wtxmgr.BlockMeta,
	scopedMgrs map[waddrmgr.KeyScope]waddrmgr.AccountStore,
	recoveryState *RecoveryState) *chain.FilterBlocksRequest {

	filterReq := &chain.FilterBlocksRequest{
		Blocks:           batch,
		ExternalAddrs:    make(map[waddrmgr.ScopedIndex]btcutil.Address),
		InternalAddrs:    make(map[waddrmgr.ScopedIndex]btcutil.Address),
		WatchedOutPoints: recoveryState.WatchedOutPoints(),
	}

	// Populate the external and internal addresses by merging the addresses
	// sets belong to all currently tracked scopes.
	for scope := range scopedMgrs {
		scopeState := recoveryState.StateForScope(scope)
		for index, addr := range scopeState.ExternalBranch.Addrs() {
			scopedIndex := waddrmgr.ScopedIndex{
				Scope: scope,
				Index: index,
			}
			filterReq.ExternalAddrs[scopedIndex] = addr
		}
		for index, addr := range scopeState.InternalBranch.Addrs() {
			scopedIndex := waddrmgr.ScopedIndex{
				Scope: scope,
				Index: index,
			}
			filterReq.InternalAddrs[scopedIndex] = addr
		}
	}

	return filterReq
}

// extendFoundAddresses accepts a filter blocks response that contains addresses
// found on chain, and advances the state of all relevant derivation paths to
// match the highest found child index for each branch.
func extendFoundAddresses(ns walletdb.ReadWriteBucket,
	filterResp *chain.FilterBlocksResponse,
	scopedMgrs map[waddrmgr.KeyScope]waddrmgr.AccountStore,
	recoveryState *RecoveryState) error {

	// Mark all recovered external addresses as used. This will be done only
	// for scopes that reported a non-zero number of external addresses in
	// this block.
	for scope, indexes := range filterResp.FoundExternalAddrs {
		// First, report all external child indexes found for this
		// scope. This ensures that the external last-found index will
		// be updated to include the maximum child index seen thus far.
		scopeState := recoveryState.StateForScope(scope)
		for index := range indexes {
			scopeState.ExternalBranch.ReportFound(index)
		}

		scopedMgr := scopedMgrs[scope]

		// Now, with all found addresses reported, derive and extend all
		// external addresses up to and including the current last found
		// index for this scope.
		exNextUnfound := scopeState.ExternalBranch.NextUnfound()

		exLastFound := exNextUnfound
		if exLastFound > 0 {
			exLastFound--
		}

		err := scopedMgr.ExtendExternalAddresses(
			ns, waddrmgr.DefaultAccountNum, exLastFound,
		)
		if err != nil {
			return err
		}

		// Finally, with the scope's addresses extended, we mark used
		// the external addresses that were found in the block and
		// belong to this scope.
		for index := range indexes {
			addr := scopeState.ExternalBranch.GetAddr(index)
			err := scopedMgr.MarkUsed(ns, addr)
			if err != nil {
				return err
			}
		}
	}

	// Mark all recovered internal addresses as used. This will be done only
	// for scopes that reported a non-zero number of internal addresses in
	// this block.
	for scope, indexes := range filterResp.FoundInternalAddrs {
		// First, report all internal child indexes found for this
		// scope. This ensures that the internal last-found index will
		// be updated to include the maximum child index seen thus far.
		scopeState := recoveryState.StateForScope(scope)
		for index := range indexes {
			scopeState.InternalBranch.ReportFound(index)
		}

		scopedMgr := scopedMgrs[scope]

		// Now, with all found addresses reported, derive and extend all
		// internal addresses up to and including the current last found
		// index for this scope.
		inNextUnfound := scopeState.InternalBranch.NextUnfound()

		inLastFound := inNextUnfound
		if inLastFound > 0 {
			inLastFound--
		}
		err := scopedMgr.ExtendInternalAddresses(
			ns, waddrmgr.DefaultAccountNum, inLastFound,
		)
		if err != nil {
			return err
		}

		// Finally, with the scope's addresses extended, we mark used
		// the internal addresses that were found in the blockand belong
		// to this scope.
		for index := range indexes {
			addr := scopeState.InternalBranch.GetAddr(index)
			err := scopedMgr.MarkUsed(ns, addr)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// logFilterBlocksResp provides useful logging information when filtering
// succeeded in finding relevant transactions.
func logFilterBlocksResp(block wtxmgr.BlockMeta,
	resp *chain.FilterBlocksResponse) {

	// Log the number of external addresses found in this block.
	var nFoundExternal int
	for _, indexes := range resp.FoundExternalAddrs {
		nFoundExternal += len(indexes)
	}
	if nFoundExternal > 0 {
		log.Infof("Recovered %d external addrs at height=%d hash=%v",
			nFoundExternal, block.Height, block.Hash)
	}

	// Log the number of internal addresses found in this block.
	var nFoundInternal int
	for _, indexes := range resp.FoundInternalAddrs {
		nFoundInternal += len(indexes)
	}
	if nFoundInternal > 0 {
		log.Infof("Recovered %d internal addrs at height=%d hash=%v",
			nFoundInternal, block.Height, block.Hash)
	}

	// Log the number of outpoints found in this block.
	nFoundOutPoints := len(resp.FoundOutPoints)
	if nFoundOutPoints > 0 {
		log.Infof("Found %d spends from watched outpoints at "+
			"height=%d hash=%v",
			nFoundOutPoints, block.Height, block.Hash)
	}
}

type (
	createTxRequest struct {
		coinSelectKeyScope    *waddrmgr.KeyScope
		changeKeyScope        *waddrmgr.KeyScope
		account               uint32
		outputs               []*wire.TxOut
		minconf               int32
		feeSatPerKB           btcutil.Amount
		coinSelectionStrategy CoinSelectionStrategy
		dryRun                bool
		resp                  chan createTxResponse
		selectUtxos           []wire.OutPoint
		allowUtxo             func(wtxmgr.Credit) bool
	}
	createTxResponse struct {
		tx  *txauthor.AuthoredTx
		err error
	}
)

// txCreator is responsible for the input selection and creation of
// transactions.  These functions are the responsibility of this method
// (designed to be run as its own goroutine) since input selection must be
// serialized, or else it is possible to create double spends by choosing the
// same inputs for multiple transactions.  Along with input selection, this
// method is also responsible for the signing of transactions, since we don't
// want to end up in a situation where we run out of inputs as multiple
// transactions are being created.  In this situation, it would then be possible
// for both requests, rather than just one, to fail due to not enough available
// inputs.
func (w *Wallet) txCreator() {
	quit := w.quitChan()
out:
	for {
		select {
		case txr := <-w.createTxRequests:
			// If the wallet can be locked because it contains
			// private key material, we need to prevent it from
			// doing so while we are assembling the transaction.
			release := func() {}
			if !w.addrStore.WatchOnly() {
				heldUnlock, err := w.holdUnlock()
				if err != nil {
					txr.resp <- createTxResponse{nil, err}
					continue
				}

				release = heldUnlock.release
			}

			tx, err := w.txToOutputs(
				txr.outputs, txr.coinSelectKeyScope,
				txr.changeKeyScope, txr.account, txr.minconf,
				txr.feeSatPerKB, txr.coinSelectionStrategy,
				txr.dryRun, txr.selectUtxos, txr.allowUtxo,
			)

			release()
			txr.resp <- createTxResponse{tx, err}
		case <-quit:
			break out
		}
	}
	w.wg.Done()
}

// txCreateOptions is a set of optional arguments to modify the tx creation
// process. This can be used to do things like use a custom coin selection
// scope, which otherwise will default to the specified coin selection scope.
type txCreateOptions struct {
	changeKeyScope *waddrmgr.KeyScope
	selectUtxos    []wire.OutPoint
	allowUtxo      func(wtxmgr.Credit) bool
}

// TxCreateOption is a set of optional arguments to modify the tx creation
// process. This can be used to do things like use a custom coin selection
// scope, which otherwise will default to the specified coin selection scope.
type TxCreateOption func(*txCreateOptions)

// defaultTxCreateOptions is the default set of options.
func defaultTxCreateOptions() *txCreateOptions {
	return &txCreateOptions{}
}

// WithCustomChangeScope can be used to specify a change scope for the change
// address. If unspecified, then the same scope will be used for both inputs
// and the change addr. Not specifying any scope at all (nil) will use all
// available coins and the default change scope (P2TR).
func WithCustomChangeScope(changeScope *waddrmgr.KeyScope) TxCreateOption {
	return func(opts *txCreateOptions) {
		opts.changeKeyScope = changeScope
	}
}

// WithCustomSelectUtxos is used to specify the inputs to be used while
// creating txns.
func WithCustomSelectUtxos(utxos []wire.OutPoint) TxCreateOption {
	return func(opts *txCreateOptions) {
		opts.selectUtxos = utxos
	}
}

// WithUtxoFilter is used to restrict the selection of the internal wallet
// inputs by further external conditions. Utxos which pass the filter are
// considered when creating the transaction.
func WithUtxoFilter(allowUtxo func(utxo wtxmgr.Credit) bool) TxCreateOption {
	return func(opts *txCreateOptions) {
		opts.allowUtxo = allowUtxo
	}
}

type (
	unlockRequest struct {
		passphrase []byte
		lockAfter  <-chan time.Time // nil prevents the timeout.
		err        chan error
	}

	changePassphraseRequest struct {
		old, new []byte
		private  bool
		err      chan error
	}

	changePassphrasesRequest struct {
		publicOld, publicNew   []byte
		privateOld, privateNew []byte
		err                    chan error
	}

	// heldUnlock is a tool to prevent the wallet from automatically
	// locking after some timeout before an operation which needed
	// the unlocked wallet has finished.  Any acquired heldUnlock
	// *must* be released (preferably with a defer) or the wallet
	// will forever remain unlocked.
	heldUnlock chan struct{}
)

// endRecovery tells (*Wallet).recovery to stop, if running, and returns a
// channel that will be closed when the recovery routine exits.
func (w *Wallet) endRecovery() <-chan struct{} {
	if recoverySyncI := w.recovering.Load(); recoverySyncI != nil {
		recoverySync := recoverySyncI.(*recoverySyncer)

		// If recovery is still running, it will end early with an error
		// once we set the quit flag.
		atomic.StoreUint32(&recoverySync.quit, 1)

		return recoverySync.done
	}
	c := make(chan struct{})
	close(c)
	return c
}

// walletLocker manages the locked/unlocked state of a wallet.
func (w *Wallet) walletLocker() {
	var timeout <-chan time.Time
	holdChan := make(heldUnlock)
	quit := w.quitChan()
out:
	for {
		select {
		case req := <-w.unlockRequests:
			err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
				addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

				return w.addrStore.Unlock(
					addrmgrNs, req.passphrase,
				)
			})
			if err != nil {
				req.err <- err
				continue
			}
			timeout = req.lockAfter
			if timeout == nil {
				log.Info("The wallet has been unlocked without a time limit")
			} else {
				log.Info("The wallet has been temporarily unlocked")
			}
			req.err <- nil
			continue

		case req := <-w.changePassphrase:
			err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

				return w.addrStore.ChangePassphrase(
					addrmgrNs, req.old, req.new, req.private,
					&waddrmgr.DefaultScryptOptions,
				)
			})
			req.err <- err
			continue

		case req := <-w.changePassphrases:
			err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

				err := w.addrStore.ChangePassphrase(
					addrmgrNs, req.publicOld, req.publicNew,
					false, &waddrmgr.DefaultScryptOptions,
				)
				if err != nil {
					return err
				}

				return w.addrStore.ChangePassphrase(
					addrmgrNs, req.privateOld, req.privateNew,
					true, &waddrmgr.DefaultScryptOptions,
				)
			})
			req.err <- err
			continue

		case req := <-w.holdUnlockRequests:
			if w.addrStore.IsLocked() {
				close(req)
				continue
			}

			req <- holdChan
			<-holdChan // Block until the lock is released.

			// If, after holding onto the unlocked wallet for some
			// time, the timeout has expired, lock it now instead
			// of hoping it gets unlocked next time the top level
			// select runs.
			select {
			case <-timeout:
				// Let the top level select fallthrough so the
				// wallet is locked.
			default:
				continue
			}

		case w.lockState <- w.addrStore.IsLocked():
			continue

		case <-quit:
			break out

		case <-w.lockRequests:
		case <-timeout:
		}

		// Select statement fell through by an explicit lock or the
		// timer expiring.  Lock the manager here.

		// We can't lock the manager if recovery is active because we use
		// cryptoKeyPriv and cryptoKeyScript in recovery.
		<-w.endRecovery()

		timeout = nil

		err := w.addrStore.Lock()
		if err != nil && !waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			log.Errorf("Could not lock wallet: %v", err)
		} else {
			log.Info("The wallet has been locked")
		}
	}
	w.wg.Done()
}

// Locked returns whether the account manager for a wallet is locked.
func (w *Wallet) Locked() bool {
	return <-w.lockState
}

// holdUnlock prevents the wallet from being locked.  The heldUnlock object
// *must* be released, or the wallet will forever remain unlocked.
//
// TODO: To prevent the above scenario, perhaps closures should be passed
// to the walletLocker goroutine and disallow callers from explicitly

// handling the locking mechanism.
func (w *Wallet) holdUnlock() (heldUnlock, error) {
	req := make(chan heldUnlock)
	w.holdUnlockRequests <- req
	hl, ok := <-req
	if !ok {
		// TODO(davec): This should be defined and exported from
		// waddrmgr.
		return nil, waddrmgr.ManagerError{
			ErrorCode:   waddrmgr.ErrLocked,
			Description: "address manager is locked",
		}
	}
	return hl, nil
}

// release releases the hold on the unlocked-state of the wallet and allows the
// wallet to be locked again.  If a lock timeout has already expired, the
// wallet is locked again as soon as release is called.
func (c heldUnlock) release() {
	c <- struct{}{}
}

// ChangePrivatePassphrase attempts to change the passphrase for a wallet from
// old to new.  Changing the passphrase is synchronized with all other address
// manager locking and unlocking.  The lock state will be the same as it was
// before the password change.
func (w *Wallet) ChangePrivatePassphrase(old, new []byte) error {
	err := make(chan error, 1)
	w.changePassphrase <- changePassphraseRequest{
		old:     old,
		new:     new,
		private: true,
		err:     err,
	}
	return <-err
}

// ChangePublicPassphrase modifies the public passphrase of the wallet.
func (w *Wallet) ChangePublicPassphrase(old, new []byte) error {
	err := make(chan error, 1)
	w.changePassphrase <- changePassphraseRequest{
		old:     old,
		new:     new,
		private: false,
		err:     err,
	}
	return <-err
}

// ChangePassphrases modifies the public and private passphrase of the wallet
// atomically.
func (w *Wallet) ChangePassphrases(publicOld, publicNew, privateOld,
	privateNew []byte) error {

	err := make(chan error, 1)
	w.changePassphrases <- changePassphrasesRequest{
		publicOld:  publicOld,
		publicNew:  publicNew,
		privateOld: privateOld,
		privateNew: privateNew,
		err:        err,
	}
	return <-err
}

// walletDeprecated encapsulates the legacy state and communication channels
// that are being phased out in favor of the modern Controller and Syncer
// architecture.
//
// Embedding this struct in the Wallet allows old logic to continue functioning
// while clearly marking the fields as legacy. Access to these fields should
// ideally be restricted to methods moved to this file.
type walletDeprecated struct {
	// Deprecated fields.
	//
	// NOTE: Listing below are deprecated fields and will be removed once
	// the sqlization series is finished.
	started bool
	quit    chan struct{}
	quitMu  sync.Mutex

	chainClient        chain.Interface
	chainClientLock    sync.Mutex
	chainClientSynced  bool
	chainClientSyncMtx sync.Mutex

	newAddrMtx sync.Mutex

	lockedOutpoints    map[wire.OutPoint]struct{}
	lockedOutpointsMtx sync.Mutex

	chainParams *chaincfg.Params

	recovering atomic.Value

	// Channels for rescan processing.  Requests are added and merged with
	// any waiting requests, before being sent to another goroutine to
	// call the rescan RPC.
	rescanAddJob        chan *RescanJob
	rescanBatch         chan *rescanBatch
	rescanNotifications chan any // From chain server
	rescanProgress      chan *RescanProgressMsg
	rescanFinished      chan *RescanFinishedMsg

	// Channels for the manager locker.
	unlockRequests     chan unlockRequest
	lockRequests       chan struct{}
	holdUnlockRequests chan chan heldUnlock
	lockState          chan bool
	changePassphrase   chan changePassphraseRequest
	changePassphrases  chan changePassphrasesRequest

	// Channel for transaction creation requests.
	createTxRequests chan createTxRequest

	// rescanFinishedChan is a channel used to signal the completion of a
	// rescan operation from the main loop to the rescan loop.
	rescanFinishedChan chan *chain.RescanFinished

	// syncRetryInterval is the amount of time to wait between re-tries on
	// errors during initial sync.
	syncRetryInterval time.Duration
}
