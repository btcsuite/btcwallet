//nolint:lll
package wallet

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
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

// FinalizePsbt expects a partial transaction with all inputs and outputs fully
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
