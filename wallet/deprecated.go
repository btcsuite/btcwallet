//nolint:lll
package wallet

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/netparams"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightningnetwork/lnd/fn/v2"
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

// AccountAddresses returns the addresses for every created address for an
// account.
func (w *Wallet) AccountAddresses(account uint32) (addrs []btcutil.Address, err error) {
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		return w.addrStore.ForEachAccountAddress(
			addrmgrNs, account,
			func(maddr waddrmgr.ManagedAddress) error {
				addrs = append(addrs, maddr.Address())
				return nil
			})
	})
	return
}

// AccountManagedAddresses returns the managed addresses for every created
// address for an account.
func (w *Wallet) AccountManagedAddresses(scope waddrmgr.KeyScope,
	accountNum uint32) ([]waddrmgr.ManagedAddress, error) {

	scopedMgr, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	addrs := make([]waddrmgr.ManagedAddress, 0)

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		return scopedMgr.ForEachAccountAddress(
			addrmgrNs, accountNum,
			func(a waddrmgr.ManagedAddress) error {
				addrs = append(addrs, a)

				return nil
			},
		)
	},
	)
	if err != nil {
		return nil, err
	}

	return addrs, nil
}

// CalculateBalance sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance.
//
// If confirmations is 0, all UTXOs, even those not present in a
// block (height -1), will be used to get the balance.  Otherwise,
// a UTXO must be in a block.  If confirmations is 1 or greater,
// the balance will be calculated based on how many how many blocks
// include a UTXO.
func (w *Wallet) CalculateBalance(confirms int32) (btcutil.Amount, error) {
	var balance btcutil.Amount
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		var err error

		blk := w.addrStore.SyncedTo()
		balance, err = w.txStore.Balance(txmgrNs, confirms, blk.Height)

		return err
	})
	return balance, err
}

// Balances records total, spendable (by policy), and immature coinbase
// reward balance amounts.
type Balances struct {
	Total          btcutil.Amount
	Spendable      btcutil.Amount
	ImmatureReward btcutil.Amount
}

// CalculateAccountBalances sums the amounts of all unspent transaction
// outputs to the given account of a wallet and returns the balance.
//
// This function is much slower than it needs to be since transactions outputs
// are not indexed by the accounts they credit to, and all unspent transaction
// outputs must be iterated.
func (w *Wallet) CalculateAccountBalances(account uint32, confirms int32) (Balances, error) {
	var bals Balances
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// Get current block.  The block height used for calculating
		// the number of tx confirmations.
		syncBlock := w.addrStore.SyncedTo()

		unspent, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		for i := range unspent {
			output := &unspent[i]

			var outputAcct uint32
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				output.PkScript, w.chainParams)
			if err == nil && len(addrs) > 0 {
				_, outputAcct, err = w.addrStore.AddrAccount(
					addrmgrNs, addrs[0],
				)
			}
			if err != nil || outputAcct != account {
				continue
			}

			bals.Total += output.Amount
			if output.FromCoinBase && !hasMinConfs(
				uint32(w.chainParams.CoinbaseMaturity),
				output.Height, syncBlock.Height,
			) {

				bals.ImmatureReward += output.Amount
			} else if hasMinConfs(
				//nolint:gosec
				uint32(confirms), output.Height,
				syncBlock.Height,
			) {

				bals.Spendable += output.Amount
			}
		}
		return nil
	})
	return bals, err
}

// CurrentAddress gets the most recently requested Bitcoin payment address
// from a wallet for a particular key-chain scope.  If the address has already
// been used (there is at least one transaction spending to it in the
// blockchain or btcd mempool), the next chained address is returned.
func (w *Wallet) CurrentAddress(account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	// The address manager uses OnCommit on the walletdb tx to update the
	// in-memory state of the account state. But because the commit happens
	// _after_ the account manager internal lock has been released, there
	// is a chance for the address index to be accessed concurrently, even
	// though the closure in OnCommit re-acquires the lock. To avoid this
	// issue, we surround the whole address creation process with a lock.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var (
		addr  btcutil.Address
		props *waddrmgr.AccountProperties
	)
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		maddr, err := manager.LastExternalAddress(addrmgrNs, account)
		if err != nil {
			// If no address exists yet, create the first external
			// address.
			if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
				addr, props, err = w.newAddressDeprecated(
					addrmgrNs, account, scope,
				)
			}
			return err
		}

		// Get next chained address if the last one has already been
		// used.
		if maddr.Used(addrmgrNs) {
			addr, props, err = w.newAddressDeprecated(
				addrmgrNs, account, scope,
			)
			return err
		}

		addr = maddr.Address()
		return nil
	})
	if err != nil {
		return nil, err
	}

	// If the props have been initially, then we had to create a new address
	// to satisfy the query. Notify the rpc server about the new address.
	if props != nil {
		err = chainClient.NotifyReceived([]btcutil.Address{addr})
		if err != nil {
			return nil, err
		}

		w.NtfnServer.notifyAccountProperties(props)
	}

	return addr, nil
}

// PubKeyForAddress looks up the associated public key for a P2PKH address.
func (w *Wallet) PubKeyForAddress(a btcutil.Address) (*btcec.PublicKey, error) {
	var pubKey *btcec.PublicKey
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		managedAddr, err := w.addrStore.Address(addrmgrNs, a)
		if err != nil {
			return err
		}
		managedPubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			return errors.New("address does not have an associated public key")
		}
		pubKey = managedPubKeyAddr.PubKey()
		return nil
	})
	return pubKey, err
}

// LabelTransaction adds a label to the transaction with the hash provided. The
// call will fail if the label is too long, or if the transaction already has
// a label and the overwrite boolean is not set.
func (w *Wallet) LabelTransaction(hash chainhash.Hash, label string,
	overwrite bool) error {

	// Check that the transaction is known to the wallet, and fail if it is
	// unknown. If the transaction is known, check whether it already has
	// a label.
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		dbTx, err := w.txStore.TxDetails(txmgrNs, &hash)
		if err != nil {
			return err
		}

		// If the transaction looked up is nil, it was not found. We
		// do not allow labelling of unknown transactions so we fail.
		if dbTx == nil {
			return ErrUnknownTransaction
		}

		_, err = w.txStore.FetchTxLabel(txmgrNs, hash)
		return err
	})

	switch err {
	// If no labels have been written yet, we can silence the error.
	// Likewise if there is no label, we do not need to do any overwrite
	// checks.
	case wtxmgr.ErrNoLabelBucket:
	case wtxmgr.ErrTxLabelNotFound:

	// If we successfully looked up a label, fail if the overwrite param
	// is not set.
	case nil:
		if !overwrite {
			return ErrTxLabelExists
		}

	// In another unrelated error occurred, return it.
	default:
		return err
	}

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		return w.txStore.PutTxLabel(txmgrNs, hash, label)
	})
}

// HaveAddress returns whether the wallet is the owner of the address a.
func (w *Wallet) HaveAddress(a btcutil.Address) (bool, error) {
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		_, err := w.addrStore.Address(addrmgrNs, a)
		return err
	})
	if err == nil {
		return true, nil
	}
	if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
		return false, nil
	}
	return false, err
}

// AccountOfAddress finds the account that an address is associated with.
func (w *Wallet) AccountOfAddress(a btcutil.Address) (uint32, error) {
	var account uint32
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error

		_, account, err = w.addrStore.AddrAccount(addrmgrNs, a)
		return err
	})
	return account, err
}

// DumpPrivKeys returns the WIF-encoded private keys for all addresses with
// private keys in a wallet.
func (w *Wallet) DumpPrivKeys() ([]string, error) {
	var privkeys []string
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		// Iterate over each active address, appending the private key to
		return w.addrStore.ForEachActiveAddress(
			addrmgrNs, func(addr btcutil.Address) error {
				ma, err := w.addrStore.Address(addrmgrNs, addr)
				if err != nil {
					return err
				}

				// Only those addresses with keys needed.
				pka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
				if !ok {
					return nil
				}

				wif, err := pka.ExportPrivKey()
				if err != nil {
					// It would be nice to zero out the
					// array here. However, since strings
					// in go are immutable, and we have no
					// control over the caller I don't
					// think we can. :(
					return err
				}

				privkeys = append(privkeys, wif.String())

				return nil
			})
	})
	return privkeys, err
}

// DumpWIFPrivateKey returns the WIF encoded private key for a
// single wallet address.
func (w *Wallet) DumpWIFPrivateKey(addr btcutil.Address) (string, error) {
	var maddr waddrmgr.ManagedAddress
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		waddrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		// Get private key from wallet if it exists.
		var err error

		maddr, err = w.addrStore.Address(waddrmgrNs, addr)
		return err
	})
	if err != nil {
		return "", err
	}

	pka, ok := maddr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return "", fmt.Errorf("address %s is not a key type", addr)
	}

	wif, err := pka.ExportPrivKey()
	if err != nil {
		return "", err
	}
	return wif.String(), nil
}

// LockOutpoint marks an outpoint as locked, that is, it should not be used as
// an input for newly created transactions.
func (w *Wallet) LockOutpoint(op wire.OutPoint) {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	w.lockedOutpoints[op] = struct{}{}
}

// UnlockOutpoint marks an outpoint as unlocked, that is, it may be used as an
// input for newly created transactions.
func (w *Wallet) UnlockOutpoint(op wire.OutPoint) {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	delete(w.lockedOutpoints, op)
}

// ResetLockedOutpoints resets the set of locked outpoints so all may be used
// as inputs for new transactions.
func (w *Wallet) ResetLockedOutpoints() {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	w.lockedOutpoints = map[wire.OutPoint]struct{}{}
}

// LockedOutpoints returns a slice of currently locked outpoints.  This is
// intended to be used by marshaling the result as a JSON array for
// listlockunspent RPC results.
func (w *Wallet) LockedOutpoints() []btcjson.TransactionInput {
	w.lockedOutpointsMtx.Lock()
	defer w.lockedOutpointsMtx.Unlock()

	locked := make([]btcjson.TransactionInput, len(w.lockedOutpoints))
	i := 0
	for op := range w.lockedOutpoints {
		locked[i] = btcjson.TransactionInput{
			Txid: op.Hash.String(),
			Vout: op.Index,
		}
		i++
	}
	return locked
}

// LeaseOutputDeprecated locks an output to the given ID, preventing it from
// being available for coin selection. The absolute time of the lock's
// expiration is
// returned. The expiration of the lock can be extended by successive
// invocations of this call.
//
// Outputs can be unlocked before their expiration through `UnlockOutput`.
// Otherwise, they are unlocked lazily through calls which iterate through all
// known outputs, e.g., `CalculateBalance`, `ListUnspent`.
//
// If the output is not known, ErrUnknownOutput is returned. If the output has
// already been locked to a different ID, then ErrOutputAlreadyLocked is
// returned.
//
// NOTE: This differs from LockOutpoint in that outputs are locked for a limited
// amount of time and their locks are persisted to disk.
//
// Deprecated: Use UtxoManager.LeaseOutput instead.
func (w *Wallet) LeaseOutputDeprecated(id wtxmgr.LockID, op wire.OutPoint,
	duration time.Duration) (time.Time, error) {

	var expiry time.Time
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		var err error

		expiry, err = w.txStore.LockOutput(ns, id, op, duration)
		return err
	})
	return expiry, err
}

// ReleaseOutputDeprecated unlocks an output, allowing it to be available for
// coin selection if it remains unspent. The ID should match the one used to
// originally lock the output.
//
// Deprecated: Use UtxoManager.ReleaseOutput instead.
func (w *Wallet) ReleaseOutputDeprecated(
	id wtxmgr.LockID, op wire.OutPoint) error {

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		return w.txStore.UnlockOutput(ns, id, op)
	})
}

// resendUnminedTxs iterates through all transactions that spend from wallet
// credits that are not known to have been mined into a block, and attempts
// to send each to the chain server for relay.
func (w *Wallet) resendUnminedTxs() {
	var txs []*wire.MsgTx
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		var err error

		txs, err = w.txStore.UnminedTxs(txmgrNs)
		return err
	})
	if err != nil {
		log.Errorf("Unable to retrieve unconfirmed transactions to "+
			"resend: %v", err)
		return
	}

	for _, tx := range txs {
		txHash, err := w.publishTransaction(tx)
		if err != nil {
			log.Debugf("Unable to rebroadcast transaction %v: %v",
				tx.TxHash(), err)
			continue
		}

		log.Debugf("Successfully rebroadcast unconfirmed transaction %v",
			txHash)
	}
}

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses in a wallet.
func (w *Wallet) SortedActivePaymentAddresses() ([]string, error) {
	var addrStrs []string
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		return w.addrStore.ForEachActiveAddress(
			addrmgrNs, func(addr btcutil.Address) error {
				addrStrs = append(
					addrStrs, addr.EncodeAddress(),
				)

				return nil
			})
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(addrStrs)
	return addrStrs, nil
}

// NewAddressDeprecated returns the next external chained address for a wallet.
func (w *Wallet) NewAddressDeprecated(account uint32,
	scope waddrmgr.KeyScope) (btcutil.Address, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// The address manager uses OnCommit on the walletdb tx to update the
	// in-memory state of the account state. But because the commit happens
	// _after_ the account manager internal lock has been released, there
	// is a chance for the address index to be accessed concurrently, even
	// though the closure in OnCommit re-acquires the lock. To avoid this
	// issue, we surround the whole address creation process with a lock.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var (
		addr  btcutil.Address
		props *waddrmgr.AccountProperties
	)
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		var err error

		addr, props, err = w.newAddressDeprecated(
			addrmgrNs, account, scope,
		)
		return err
	})
	if err != nil {
		return nil, err
	}

	// Notify the rpc server about the newly created address.
	err = chainClient.NotifyReceived([]btcutil.Address{addr})
	if err != nil {
		return nil, err
	}

	w.NtfnServer.notifyAccountProperties(props)

	return addr, nil
}

// NewChangeAddress returns a new change address for a wallet.
func (w *Wallet) NewChangeAddress(account uint32,
	scope waddrmgr.KeyScope) (btcutil.Address, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// The address manager uses OnCommit on the walletdb tx to update the
	// in-memory state of the account state. But because the commit happens
	// _after_ the account manager internal lock has been released, there
	// is a chance for the address index to be accessed concurrently, even
	// though the closure in OnCommit re-acquires the lock. To avoid this
	// issue, we surround the whole address creation process with a lock.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var addr btcutil.Address
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		var err error
		addr, err = w.newChangeAddress(addrmgrNs, account, scope)
		return err
	})
	if err != nil {
		return nil, err
	}

	// Notify the rpc server about the newly created address.
	err = chainClient.NotifyReceived([]btcutil.Address{addr})
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// newChangeAddress returns a new change address for the wallet.
//
// NOTE: This method requires the caller to use the backend's NotifyReceived
// method in order to detect when an on-chain transaction pays to the address
// being created.
func (w *Wallet) newChangeAddress(addrmgrNs walletdb.ReadWriteBucket,
	account uint32, scope waddrmgr.KeyScope) (btcutil.Address, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	// Get next chained change address from wallet for account.
	addrs, err := manager.NextInternalAddresses(addrmgrNs, account, 1)
	if err != nil {
		return nil, err
	}

	return addrs[0].Address(), nil
}

// AccountTotalReceivedResult is a single result for the
// Wallet.TotalReceivedForAccounts method.
type AccountTotalReceivedResult struct {
	AccountNumber    uint32
	AccountName      string
	TotalReceived    btcutil.Amount
	LastConfirmation int32
}

// TotalReceivedForAccounts iterates through a wallet's transaction history,
// returning the total amount of Bitcoin received for all accounts.
func (w *Wallet) TotalReceivedForAccounts(scope waddrmgr.KeyScope,
	minConf int32) ([]AccountTotalReceivedResult, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var results []AccountTotalReceivedResult
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.addrStore.SyncedTo()

		err := manager.ForEachAccount(addrmgrNs, func(account uint32) error {
			accountName, err := manager.AccountName(addrmgrNs, account)
			if err != nil {
				return err
			}
			results = append(results, AccountTotalReceivedResult{
				AccountNumber: account,
				AccountName:   accountName,
			})
			return nil
		})
		if err != nil {
			return err
		}

		var stopHeight int32

		if minConf > 0 {
			stopHeight = syncBlock.Height - minConf + 1
		} else {
			stopHeight = -1
		}

		//nolint:lll
		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			for i := range details {
				detail := &details[i]
				for _, cred := range detail.Credits {
					pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
					var outputAcct uint32
					_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, w.chainParams)
					if err == nil && len(addrs) > 0 {
						_, outputAcct, err = w.addrStore.AddrAccount(addrmgrNs, addrs[0])
					}
					if err == nil {
						acctIndex := int(outputAcct)
						if outputAcct == waddrmgr.ImportedAddrAccount {
							acctIndex = len(results) - 1
						}
						res := &results[acctIndex]
						res.TotalReceived += cred.Amount

						confs := calcConf(
							detail.Block.Height,
							syncBlock.Height,
						)
						res.LastConfirmation = confs
					}
				}
			}
			return false, nil
		}

		return w.txStore.RangeTransactions(
			txmgrNs, 0, stopHeight, rangeFn,
		)
	})
	return results, err
}

// TotalReceivedForAddr iterates through a wallet's transaction history,
// returning the total amount of bitcoins received for a single wallet
// address.
func (w *Wallet) TotalReceivedForAddr(addr btcutil.Address, minConf int32) (btcutil.Amount, error) {
	var amount btcutil.Amount
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.addrStore.SyncedTo()

		var (
			addrStr    = addr.EncodeAddress()
			stopHeight int32
		)

		if minConf > 0 {
			stopHeight = syncBlock.Height - minConf + 1
		} else {
			stopHeight = -1
		}
		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			for i := range details {
				detail := &details[i]
				for _, cred := range detail.Credits {
					pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
					_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
						w.chainParams)
					// An error creating addresses from the output script only
					// indicates a non-standard script, so ignore this credit.
					if err != nil {
						continue
					}
					for _, a := range addrs {
						if addrStr == a.EncodeAddress() {
							amount += cred.Amount
							break
						}
					}
				}
			}
			return false, nil
		}

		return w.txStore.RangeTransactions(
			txmgrNs, 0, stopHeight, rangeFn,
		)
	})
	return amount, err
}

// SendOutputs creates and sends payment transactions. Coin selection is
// performed by the wallet, choosing inputs that belong to the given key scope
// and account, unless a key scope is not specified. In that case, inputs from
// accounts matching the account number provided across all key scopes may be
// selected. This is done to handle the default account case, where a user wants
// to fund a PSBT with inputs regardless of their type (NP2WKH, P2WKH, etc.). It
// returns the transaction upon success.
func (w *Wallet) SendOutputs(outputs []*wire.TxOut, keyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, satPerKb btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy, label string) (*wire.MsgTx,
	error) {

	return w.sendOutputs(
		outputs, keyScope, account, minconf, satPerKb,
		coinSelectionStrategy, label,
	)
}

// SendOutputsWithInput creates and sends payment transactions using the
// provided selected utxos. It returns the transaction upon success.
func (w *Wallet) SendOutputsWithInput(outputs []*wire.TxOut,
	keyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, satPerKb btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy, label string,
	selectedUtxos []wire.OutPoint) (*wire.MsgTx, error) {

	return w.sendOutputs(outputs, keyScope, account, minconf, satPerKb,
		coinSelectionStrategy, label, selectedUtxos...)
}

// sendOutputs creates and sends payment transactions. It returns the
// transaction upon success.
func (w *Wallet) sendOutputs(outputs []*wire.TxOut, keyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, satPerKb btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy, label string,
	selectedUtxos ...wire.OutPoint) (*wire.MsgTx, error) {

	// If the key scope wasn't specified, then we'll default to the BIP0084
	// key scope for this account.
	if keyScope == nil {
		keyScope = &waddrmgr.KeyScopeBIP0084
	}

	// Create a transaction which spends from the wallet.
	var (
		tx  *txauthor.AuthoredTx
		err error
	)
	// We'll specify the WithCustomSelectUtxos functional option if we were
	// passed a set of utxos to spend.
	var opts []TxCreateOption
	if len(selectedUtxos) != 0 {
		opts = append(opts, WithCustomSelectUtxos(selectedUtxos))
	}

	tx, err = w.CreateSimpleTx(
		keyScope, account, outputs, minconf, satPerKb,
		coinSelectionStrategy, false, opts...,
	)
	if err != nil {
		return nil, err
	}

	// If there is a label we should write, get the namespace key
	// and record it in the tx store.
	//
	// TODO(yy): We should remove this `label` parameter from the function
	// signature and instead let the caller use `LabelTransaction` to label
	// the transaction after it's been published.
	if len(label) != 0 {
		err := walletdb.Update(w.db, func(txmgr walletdb.ReadWriteTx) error {
			ns := txmgr.ReadWriteBucket(wtxmgrNamespaceKey)
			return w.txStore.PutTxLabel(ns, tx.Tx.TxHash(), label)
		})
		if err != nil {
			return nil, err
		}
	}

	// And publish it.
	return nil, w.PublishTransaction(tx.Tx, label)
}

// SignatureError records the underlying error when validating a transaction
// input signature.
type SignatureError struct {
	InputIndex uint32
	Error      error
}

// SignTransaction uses secrets of the wallet, as well as additional secrets
// passed in by the caller, to create and add input signatures to a transaction.
//
// Transaction input script validation is used to confirm that all signatures
// are valid.  For any invalid input, a SignatureError is added to the returns.
// The final error return is reserved for unexpected or fatal errors, such as
// being unable to determine a previous output script to redeem.
//
// The transaction pointed to by tx is modified by this function.
func (w *Wallet) SignTransaction(tx *wire.MsgTx, hashType txscript.SigHashType,
	additionalPrevScripts map[wire.OutPoint][]byte,
	additionalKeysByAddress map[string]*btcutil.WIF,
	p2shRedeemScriptsByAddress map[string][]byte) ([]SignatureError, error) {

	var signErrors []SignatureError
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		inputFetcher := txscript.NewMultiPrevOutFetcher(nil)
		for i, txIn := range tx.TxIn {
			prevOutScript, ok := additionalPrevScripts[txIn.PreviousOutPoint]
			if !ok {
				prevHash := &txIn.PreviousOutPoint.Hash
				prevIndex := txIn.PreviousOutPoint.Index

				txDetails, err := w.txStore.TxDetails(
					txmgrNs, prevHash,
				)
				if err != nil {
					return fmt.Errorf("cannot query previous transaction "+
						"details for %v: %w", txIn.PreviousOutPoint, err)
				}
				if txDetails == nil {
					return fmt.Errorf("%v not found",
						txIn.PreviousOutPoint)
				}
				prevOutScript = txDetails.MsgTx.TxOut[prevIndex].PkScript
			}
			inputFetcher.AddPrevOut(txIn.PreviousOutPoint, &wire.TxOut{
				PkScript: prevOutScript,
			})

			// Set up our callbacks that we pass to txscript so it can
			// look up the appropriate keys and scripts by address.
			//
			//nolint:lll
			getKey := txscript.KeyClosure(func(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
				if len(additionalKeysByAddress) != 0 {
					addrStr := addr.EncodeAddress()
					wif, ok := additionalKeysByAddress[addrStr]
					if !ok {
						return nil, false,
							errors.New("no key for address")
					}
					return wif.PrivKey, wif.CompressPubKey, nil
				}

				address, err := w.addrStore.Address(addrmgrNs, addr)
				if err != nil {
					return nil, false, err
				}

				pka, ok := address.(waddrmgr.ManagedPubKeyAddress)
				if !ok {
					return nil, false, fmt.Errorf("address %v is not "+
						"a pubkey address", address.Address().EncodeAddress())
				}

				key, err := pka.PrivKey()
				if err != nil {
					return nil, false, err
				}

				return key, pka.Compressed(), nil
			})
			//nolint:lll
			getScript := txscript.ScriptClosure(func(addr btcutil.Address) ([]byte, error) {
				// If keys were provided then we can only use the
				// redeem scripts provided with our inputs, too.
				if len(additionalKeysByAddress) != 0 {
					addrStr := addr.EncodeAddress()
					script, ok := p2shRedeemScriptsByAddress[addrStr]
					if !ok {
						return nil, errors.New("no script for address")
					}
					return script, nil
				}

				address, err := w.addrStore.Address(addrmgrNs, addr)
				if err != nil {
					return nil, err
				}

				// If we found the address, we check to see if it's
				// a p2sh address, if so, then we'll verify that it
				// is one that we know the redeem script for.
				shAddr, ok := address.(waddrmgr.ManagedScriptAddress)
				if !ok {
					return nil, errors.New("address is not a " +
						"p2sh address")
				}

				return shAddr.Script()
			})

			// SigHashSingle inputs can only be signed if there's a
			// corresponding output. However this could be already signed,
			// so we always verify the output.
			if (hashType&txscript.SigHashSingle) !=
				txscript.SigHashSingle || i < len(tx.TxOut) {

				script, err := txscript.SignTxOutput(w.ChainParams(),
					tx, i, prevOutScript, hashType, getKey,
					getScript, txIn.SignatureScript)
				// Failure to sign isn't an error, it just means that
				// the tx isn't complete.
				if err != nil {
					signErrors = append(signErrors, SignatureError{
						InputIndex: uint32(i),
						Error:      err,
					})
					continue
				}
				txIn.SignatureScript = script
			}

			// Either it was already signed or we just signed it.
			// Find out if it is completely satisfied or still needs more.
			vm, err := txscript.NewEngine(
				prevOutScript, tx, i,
				txscript.StandardVerifyFlags, nil, nil, 0,
				inputFetcher,
			)
			if err == nil {
				err = vm.Execute()
			}
			if err != nil {
				signErrors = append(signErrors, SignatureError{
					InputIndex: uint32(i),
					Error:      err,
				})
			}
		}
		return nil
	})
	return signErrors, err
}

// ErrDoubleSpend is an error returned from PublishTransaction in case the
// published transaction failed to propagate since it was double spending a
// confirmed transaction or a transaction in the mempool.
type ErrDoubleSpend struct {
	backendError error
}

// Error returns the string representation of ErrDoubleSpend.
//
// NOTE: Satisfies the error interface.
func (e *ErrDoubleSpend) Error() string {
	return fmt.Sprintf("double spend: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrDoubleSpend) Unwrap() error {
	return e.backendError
}

// ErrMempoolFee is an error returned from PublishTransaction in case the
// published transaction failed to propagate since it did not match the
// current mempool fee requirement.
type ErrMempoolFee struct {
	backendError error
}

// Error returns the string representation of ErrMempoolFee.
//
// NOTE: Satisfies the error interface.
func (e *ErrMempoolFee) Error() string {
	return fmt.Sprintf("mempool fee not met: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrMempoolFee) Unwrap() error {
	return e.backendError
}

// ErrAlreadyConfirmed is an error returned from PublishTransaction in case
// a transaction is already confirmed in the blockchain.
type ErrAlreadyConfirmed struct {
	backendError error
}

// Error returns the string representation of ErrAlreadyConfirmed.
//
// NOTE: Satisfies the error interface.
func (e *ErrAlreadyConfirmed) Error() string {
	return fmt.Sprintf("tx already confirmed: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrAlreadyConfirmed) Unwrap() error {
	return e.backendError
}

// ErrInMempool is an error returned from PublishTransaction in case a
// transaction is already in the mempool.
type ErrInMempool struct {
	backendError error
}

// Error returns the string representation of ErrInMempool.
//
// NOTE: Satisfies the error interface.
func (e *ErrInMempool) Error() string {
	return fmt.Sprintf("tx already in mempool: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrInMempool) Unwrap() error {
	return e.backendError
}

// PublishTransaction sends the transaction to the consensus RPC server so it
// can be propagated to other nodes and eventually mined.
//
// This function is unstable and will be removed once syncing code is moved out
// of the wallet.
func (w *Wallet) PublishTransaction(tx *wire.MsgTx, label string) error {
	_, err := w.reliablyPublishTransaction(tx, label)
	return err
}

// reliablyPublishTransaction is a superset of publishTransaction which contains
// the primary logic required for publishing a transaction, updating the
// relevant database state, and finally possible removing the transaction from
// the database (along with cleaning up all inputs used, and outputs created) if
// the transaction is rejected by the backend.
func (w *Wallet) reliablyPublishTransaction(tx *wire.MsgTx,
	label string) (*chainhash.Hash, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// As we aim for this to be general reliable transaction broadcast API,
	// we'll write this tx to disk as an unconfirmed transaction. This way,
	// upon restarts, we'll always rebroadcast it, and also add it to our
	// set of records.
	txRec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	if err != nil {
		return nil, err
	}

	// Along the way, we'll extract our relevant destination addresses from
	// the transaction.
	var ourAddrs []btcutil.Address
	err = walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
		addrmgrNs := dbTx.ReadWriteBucket(waddrmgrNamespaceKey)
		for _, txOut := range tx.TxOut {
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				txOut.PkScript, w.chainParams,
			)
			if err != nil {
				// Non-standard outputs can safely be skipped
				// because they're not supported by the wallet.
				log.Warnf("Non-standard pkScript=%x in tx=%v",
					txOut.PkScript, tx.TxHash())

				continue
			}
			for _, addr := range addrs {
				// Skip any addresses which are not relevant to
				// us.
				_, err := w.addrStore.Address(addrmgrNs, addr)
				if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				ourAddrs = append(ourAddrs, addr)
			}
		}

		// If there is a label we should write, get the namespace key
		// and record it in the tx store.
		if len(label) != 0 {
			txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)

			err = w.txStore.PutTxLabel(txmgrNs, tx.TxHash(), label)
			if err != nil {
				return err
			}
		}

		return w.addRelevantTx(dbTx, txRec, nil)
	})
	if err != nil {
		return nil, err
	}

	// We'll also ask to be notified of the transaction once it confirms
	// on-chain. This is done outside of the database transaction to prevent
	// backend interaction within it.
	if err := chainClient.NotifyReceived(ourAddrs); err != nil {
		return nil, err
	}

	return w.publishTransaction(tx)
}

// publishTransaction attempts to send an unconfirmed transaction to the
// wallet's current backend. In the event that sending the transaction fails for
// whatever reason, it will be removed from the wallet's unconfirmed transaction
// store.
func (w *Wallet) publishTransaction(tx *wire.MsgTx) (*chainhash.Hash, error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	txid := tx.TxHash()
	_, rpcErr := chainClient.SendRawTransaction(tx, false)
	if rpcErr == nil {
		return &txid, nil
	}

	switch {
	case errors.Is(rpcErr, chain.ErrTxAlreadyInMempool):
		log.Infof("%v: tx already in mempool", txid)
		return &txid, nil

	case errors.Is(rpcErr, chain.ErrTxAlreadyKnown),
		errors.Is(rpcErr, chain.ErrTxAlreadyConfirmed):

		dbErr := walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
			txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)
			txRec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
			if err != nil {
				return err
			}

			return w.txStore.RemoveUnminedTx(txmgrNs, txRec)
		})
		if dbErr != nil {
			log.Warnf("Unable to remove confirmed transaction %v "+
				"from unconfirmed store: %v", tx.TxHash(), dbErr)
		}

		log.Infof("%v: tx already confirmed", txid)

		return &txid, nil

	}

	// Log the causing error, even if we know how to handle it.
	log.Infof("%v: broadcast failed because of: %v", txid, rpcErr)

	// If the transaction was rejected for whatever other reason, then
	// we'll remove it from the transaction store, as otherwise, we'll
	// attempt to continually re-broadcast it, and the UTXO state of the
	// wallet won't be accurate.
	dbErr := walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)
		txRec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
		if err != nil {
			return err
		}

		return w.txStore.RemoveUnminedTx(txmgrNs, txRec)
	})
	if dbErr != nil {
		log.Warnf("Unable to remove invalid transaction %v: %v",
			tx.TxHash(), dbErr)
	} else {
		log.Infof("Removed invalid transaction: %v", tx.TxHash())

		// The serialized transaction is for logging only, don't fail
		// on the error.
		var txRaw bytes.Buffer
		_ = tx.Serialize(&txRaw)

		// Optionally log the tx in debug when the size is manageable.
		if txRaw.Len() < 1_000_000 {
			log.Debugf("Removed invalid transaction: %v \n hex=%x",
				newLogClosure(func() string {
					return spew.Sdump(tx)
				}), txRaw.Bytes())
		} else {
			log.Debug("Removed invalid transaction due to size " +
				"too large")
		}
	}

	return nil, rpcErr
}

// CreateDeprecated creates an new wallet, writing it to an empty database.
// If the passed root key is non-nil, it is used.  Otherwise, a secure
// random seed of the recommended length is generated.
//
// Deprecated: Use wallet.Create instead.
func CreateDeprecated(db walletdb.DB, pubPass, privPass []byte,
	rootKey *hdkeychain.ExtendedKey, params *chaincfg.Params,
	birthday time.Time) error {

	return create(
		db, pubPass, privPass, rootKey, params, birthday, false, nil,
	)
}

// AccountNumber returns the account number for an account name under a
// particular key scope.
func (w *Wallet) AccountNumber(scope waddrmgr.KeyScope, accountName string) (uint32, error) {
	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return 0, err
	}

	var account uint32
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		account, err = manager.LookupAccount(addrmgrNs, accountName)
		return err
	})
	return account, err
}

// AccountName returns the name of an account.
func (w *Wallet) AccountName(scope waddrmgr.KeyScope, accountNumber uint32) (string, error) {
	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return "", err
	}

	var accountName string
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		accountName, err = manager.AccountName(addrmgrNs, accountNumber)
		return err
	})
	return accountName, err
}

// AccountProperties returns the properties of an account, including address
// indexes and name. It first fetches the desynced information from the address
// manager, then updates the indexes based on the address pools.
func (w *Wallet) AccountProperties(scope waddrmgr.KeyScope, acct uint32) (*waddrmgr.AccountProperties, error) {
	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var props *waddrmgr.AccountProperties
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		waddrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error
		props, err = manager.AccountProperties(waddrmgrNs, acct)
		return err
	})
	return props, err
}

// AccountPropertiesByName returns the properties of an account by its name. It
// first fetches the desynced information from the address manager, then updates
// the indexes based on the address pools.
func (w *Wallet) AccountPropertiesByName(scope waddrmgr.KeyScope,
	name string) (*waddrmgr.AccountProperties, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var props *waddrmgr.AccountProperties
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		waddrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		acct, err := manager.LookupAccount(waddrmgrNs, name)
		if err != nil {
			return err
		}
		props, err = manager.AccountProperties(waddrmgrNs, acct)
		return err
	})
	return props, err
}

// LookupAccount returns the corresponding key scope and account number for the
// account with the given name.
func (w *Wallet) LookupAccount(name string) (waddrmgr.KeyScope, uint32, error) {
	var (
		keyScope waddrmgr.KeyScope
		account  uint32
	)
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		var err error

		keyScope, account, err = w.addrStore.LookupAccount(ns, name)
		return err
	})

	return keyScope, account, err
}

// CreditCategory describes the type of wallet transaction output.  The category
// of "sent transactions" (debits) is always "send", and is not expressed by
// this type.
//
// TODO: This is a requirement of the RPC server and should be moved.
type CreditCategory byte

// These constants define the possible credit categories.
const (
	CreditReceive CreditCategory = iota
	CreditGenerate
	CreditImmature
)

// String returns the category as a string.  This string may be used as the
// JSON string for categories as part of listtransactions and gettransaction
// RPC responses.
func (c CreditCategory) String() string {
	switch c {
	case CreditReceive:
		return "receive"
	case CreditGenerate:
		return "generate"
	case CreditImmature:
		return "immature"
	default:
		return "unknown"
	}
}

// RecvCategory returns the category of received credit outputs from a
// transaction record.  The passed block chain height is used to distinguish
// immature from mature coinbase outputs.
//
// TODO: This is intended for use by the RPC server and should be moved out of
// this package at a later time.
func RecvCategory(details *wtxmgr.TxDetails, syncHeight int32, net *chaincfg.Params) CreditCategory {
	if blockchain.IsCoinBaseTx(&details.MsgTx) {
		if hasMinConfs(uint32(net.CoinbaseMaturity),
			details.Block.Height, syncHeight) {

			return CreditGenerate
		}
		return CreditImmature
	}
	return CreditReceive
}

// listTransactions creates a object that may be marshalled to a response result
// for a listtransactions RPC.
//
// TODO: This should be moved to the legacyrpc package.
func listTransactions(tx walletdb.ReadTx, details *wtxmgr.TxDetails,
	addrMgr waddrmgr.AddrStore, syncHeight int32,
	net *chaincfg.Params) []btcjson.ListTransactionsResult {

	addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

	var (
		blockHashStr  string
		blockTime     int64
		confirmations int64
	)
	if details.Block.Height != -1 {
		blockHashStr = details.Block.Hash.String()
		blockTime = details.Block.Time.Unix()
		confirmations = int64(
			calcConf(details.Block.Height, syncHeight),
		)
	}

	results := []btcjson.ListTransactionsResult{}
	txHashStr := details.Hash.String()
	received := details.Received.Unix()
	generated := blockchain.IsCoinBaseTx(&details.MsgTx)
	recvCat := RecvCategory(details, syncHeight, net).String()

	send := len(details.Debits) != 0

	// Fee can only be determined if every input is a debit.
	var feeF64 float64
	if len(details.Debits) == len(details.MsgTx.TxIn) {
		var debitTotal btcutil.Amount
		for _, deb := range details.Debits {
			debitTotal += deb.Amount
		}
		var outputTotal btcutil.Amount
		for _, output := range details.MsgTx.TxOut {
			outputTotal += btcutil.Amount(output.Value)
		}
		// Note: The actual fee is debitTotal - outputTotal.  However,
		// this RPC reports negative numbers for fees, so the inverse
		// is calculated.
		feeF64 = (outputTotal - debitTotal).ToBTC()
	}

outputs:
	for i, output := range details.MsgTx.TxOut {
		// Determine if this output is a credit, and if so, determine
		// its spentness.
		var isCredit bool
		var spentCredit bool
		for _, cred := range details.Credits {
			if cred.Index == uint32(i) {
				// Change outputs are ignored.
				if cred.Change {
					continue outputs
				}

				isCredit = true
				spentCredit = cred.Spent
				break
			}
		}

		var address string
		var accountName string
		_, addrs, _, _ := txscript.ExtractPkScriptAddrs(output.PkScript, net)
		if len(addrs) == 1 {
			addr := addrs[0]
			address = addr.EncodeAddress()
			mgr, account, err := addrMgr.AddrAccount(addrmgrNs, addrs[0])
			if err == nil {
				accountName, err = mgr.AccountName(addrmgrNs, account)
				if err != nil {
					accountName = ""
				}
			}
		}

		amountF64 := btcutil.Amount(output.Value).ToBTC()
		result := btcjson.ListTransactionsResult{
			// Fields left zeroed:
			//   InvolvesWatchOnly
			//   BlockIndex
			//
			// Fields set below:
			//   Account (only for non-"send" categories)
			//   Category
			//   Amount
			//   Fee
			Address:         address,
			Vout:            uint32(i),
			Confirmations:   confirmations,
			Generated:       generated,
			BlockHash:       blockHashStr,
			BlockTime:       blockTime,
			TxID:            txHashStr,
			WalletConflicts: []string{},
			Time:            received,
			TimeReceived:    received,
		}

		// Add a received/generated/immature result if this is a credit.
		// If the output was spent, create a second result under the
		// send category with the inverse of the output amount.  It is
		// therefore possible that a single output may be included in
		// the results set zero, one, or two times.
		//
		// Since credits are not saved for outputs that are not
		// controlled by this wallet, all non-credits from transactions
		// with debits are grouped under the send category.

		if send || spentCredit {
			result.Category = "send"
			result.Amount = -amountF64
			result.Fee = &feeF64
			results = append(results, result)
		}
		if isCredit {
			result.Account = accountName
			result.Category = recvCat
			result.Amount = amountF64
			result.Fee = nil
			results = append(results, result)
		}
	}
	return results
}

// ListSinceBlock returns a slice of objects with details about transactions
// since the given block. If the block is -1 then all transactions are included.
// This is intended to be used for listsinceblock RPC replies.
func (w *Wallet) ListSinceBlock(start, end, syncHeight int32) ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			for _, detail := range details {
				detail := detail

				jsonResults := listTransactions(
					tx, &detail, w.addrStore, syncHeight,
					w.chainParams,
				)
				txList = append(txList, jsonResults...)
			}
			return false, nil
		}

		return w.txStore.RangeTransactions(txmgrNs, start, end, rangeFn)
	})
	return txList, err
}

// ListTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listtransactions RPC
// replies.
func (w *Wallet) ListTransactions(from, count int) ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}

	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// Get current block.  The block height used for calculating
		// the number of tx confirmations.
		syncBlock := w.addrStore.SyncedTo()

		// Need to skip the first from transactions, and after those, only
		// include the next count transactions.
		skipped := 0
		n := 0

		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			// Iterate over transactions at this height in reverse order.
			// This does nothing for unmined transactions, which are
			// unsorted, but it will process mined transactions in the
			// reverse order they were marked mined.
			for i := len(details) - 1; i >= 0; i-- {
				if from > skipped {
					skipped++
					continue
				}

				n++
				if n > count {
					return true, nil
				}

				jsonResults := listTransactions(
					tx, &details[i], w.addrStore,
					syncBlock.Height, w.chainParams,
				)
				txList = append(txList, jsonResults...)

				if len(jsonResults) > 0 {
					n++
				}
			}

			return false, nil
		}

		// Return newer results first by starting at mempool height and working
		// down to the genesis block.
		return w.txStore.RangeTransactions(txmgrNs, -1, 0, rangeFn)
	})
	return txList, err
}

// ListAddressTransactions returns a slice of objects with details about
// recorded transactions to or from any address belonging to a set.  This is
// intended to be used for listaddresstransactions RPC replies.
func (w *Wallet) ListAddressTransactions(pkHashes map[string]struct{}) ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// Get current block.  The block height used for calculating
		// the number of tx confirmations.
		syncBlock := w.addrStore.SyncedTo()
		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
		loopDetails:
			for i := range details {
				detail := &details[i]

				for _, cred := range detail.Credits {
					pkScript := detail.MsgTx.TxOut[cred.Index].PkScript
					_, addrs, _, err := txscript.ExtractPkScriptAddrs(
						pkScript, w.chainParams)
					if err != nil || len(addrs) != 1 {
						continue
					}
					apkh, ok := addrs[0].(*btcutil.AddressPubKeyHash)
					if !ok {
						continue
					}
					_, ok = pkHashes[string(apkh.ScriptAddress())]
					if !ok {
						continue
					}

					jsonResults := listTransactions(
						tx, detail, w.addrStore,
						syncBlock.Height, w.chainParams,
					)
					txList = append(txList, jsonResults...)
					continue loopDetails
				}
			}
			return false, nil
		}

		return w.txStore.RangeTransactions(txmgrNs, 0, -1, rangeFn)
	})
	return txList, err
}

// ListAllTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listalltransactions RPC
// replies.
func (w *Wallet) ListAllTransactions() ([]btcjson.ListTransactionsResult, error) {
	txList := []btcjson.ListTransactionsResult{}
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// Get current block.  The block height used for calculating
		// the number of tx confirmations.
		syncBlock := w.addrStore.SyncedTo()

		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			// Iterate over transactions at this height in reverse order.
			// This does nothing for unmined transactions, which are
			// unsorted, but it will process mined transactions in the
			// reverse order they were marked mined.
			for i := len(details) - 1; i >= 0; i-- {
				jsonResults := listTransactions(
					tx, &details[i], w.addrStore,
					syncBlock.Height, w.chainParams,
				)
				txList = append(txList, jsonResults...)
			}
			return false, nil
		}

		// Return newer results first by starting at mempool height and
		// working down to the genesis block.
		return w.txStore.RangeTransactions(txmgrNs, -1, 0, rangeFn)
	})
	return txList, err
}

// GetTransactions returns transaction results between a starting and ending
// block.  Blocks in the block range may be specified by either a height or a
// hash.
//
// Because this is a possibly lenghtly operation, a cancel channel is provided
// to cancel the task.  If this channel unblocks, the results created thus far
// will be returned.
//
// Transaction results are organized by blocks in ascending order and unmined
// transactions in an unspecified order.  Mined transactions are saved in a
// Block structure which records properties about the block.
func (w *Wallet) GetTransactions(startBlock, endBlock *BlockIdentifier,
	accountName string, cancel <-chan struct{}) (*GetTransactionsResult, error) {

	var start, end int32 = 0, -1

	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()

	// TODO: Fetching block heights by their hashes is inherently racy
	// because not all block headers are saved but when they are for SPV the
	// db can be queried directly without this.
	if startBlock != nil {
		if startBlock.hash == nil {
			start = startBlock.height
		} else {
			if chainClient == nil {
				return nil, errors.New("no chain server client")
			}
			switch client := chainClient.(type) {
			case *chain.RPCClient:
				startHeader, err := client.GetBlockHeaderVerbose(
					startBlock.hash,
				)
				if err != nil {
					return nil, err
				}
				start = startHeader.Height
			case *chain.BitcoindClient:
				var err error
				start, err = client.GetBlockHeight(startBlock.hash)
				if err != nil {
					return nil, err
				}
			case *chain.NeutrinoClient:
				var err error
				start, err = client.GetBlockHeight(startBlock.hash)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	if endBlock != nil {
		if endBlock.hash == nil {
			end = endBlock.height
		} else {
			if chainClient == nil {
				return nil, errors.New("no chain server client")
			}
			switch client := chainClient.(type) {
			case *chain.RPCClient:
				endHeader, err := client.GetBlockHeaderVerbose(
					endBlock.hash,
				)
				if err != nil {
					return nil, err
				}
				end = endHeader.Height
			case *chain.BitcoindClient:
				var err error
				start, err = client.GetBlockHeight(endBlock.hash)
				if err != nil {
					return nil, err
				}
			case *chain.NeutrinoClient:
				var err error
				end, err = client.GetBlockHeight(endBlock.hash)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	var res GetTransactionsResult
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		rangeFn := func(details []wtxmgr.TxDetails) (bool, error) {
			// TODO: probably should make RangeTransactions not reuse the
			// details backing array memory.
			dets := make([]wtxmgr.TxDetails, len(details))
			copy(dets, details)
			details = dets

			txs := make([]TransactionSummary, 0, len(details))
			for i := range details {
				txs = append(txs, makeTxSummary(dbtx, w, &details[i]))
			}

			if details[0].Block.Height != -1 {
				blockHash := details[0].Block.Hash
				res.MinedTransactions = append(res.MinedTransactions, Block{
					Hash:         &blockHash,
					Height:       details[0].Block.Height,
					Timestamp:    details[0].Block.Time.Unix(),
					Transactions: txs,
				})
			} else {
				res.UnminedTransactions = txs
			}

			select {
			case <-cancel:
				return true, nil
			default:
				return false, nil
			}
		}

		return w.txStore.RangeTransactions(txmgrNs, start, end, rangeFn)
	})
	return &res, err
}

// GetTransaction returns detailed data of a transaction given its id. In
// addition it returns properties about its block.
func (w *Wallet) GetTransaction(txHash chainhash.Hash) (*GetTransactionResult,
	error) {

	var res GetTransactionResult
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		txDetail, err := w.txStore.TxDetails(txmgrNs, &txHash)
		if err != nil {
			return err
		}

		// If the transaction was not found we return an error.
		if txDetail == nil {
			return fmt.Errorf("%w: txid %v", ErrNoTx, txHash)
		}

		res = GetTransactionResult{
			Summary:       makeTxSummary(dbtx, w, txDetail),
			BlockHash:     nil,
			Height:        -1,
			Confirmations: 0,
			Timestamp:     0,
		}

		// If it is a confirmed transaction we set the corresponding
		// block height, timestamp, hash, and confirmations.
		if txDetail.Block.Height != -1 {
			res.Height = txDetail.Block.Height
			res.Timestamp = txDetail.Block.Time.Unix()
			res.BlockHash = &txDetail.Block.Hash

			bestBlock := w.SyncedTo()
			blockHeight := txDetail.Block.Height
			res.Confirmations = calcConf(
				blockHeight, bestBlock.Height,
			)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// AccountBalances returns all accounts in the wallet and their balances.
// Balances are determined by excluding transactions that have not met
// requiredConfs confirmations.
func (w *Wallet) AccountBalances(scope waddrmgr.KeyScope,
	requiredConfs int32) ([]AccountBalanceResult, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	var results []AccountBalanceResult
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.addrStore.SyncedTo()

		// Fill out all account info except for the balances.
		lastAcct, err := manager.LastAccount(addrmgrNs)
		if err != nil {
			return err
		}
		results = make([]AccountBalanceResult, lastAcct+2)
		for i := range results[:len(results)-1] {
			accountName, err := manager.AccountName(addrmgrNs, uint32(i))
			if err != nil {
				return err
			}
			results[i].AccountNumber = uint32(i)
			results[i].AccountName = accountName
		}
		results[len(results)-1].AccountNumber = waddrmgr.ImportedAddrAccount
		results[len(results)-1].AccountName = waddrmgr.ImportedAddrAccountName

		// Fetch all unspent outputs, and iterate over them tallying each
		// account's balance where the output script pays to an account address
		// and the required number of confirmations is met.
		unspentOutputs, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		for i := range unspentOutputs {
			output := &unspentOutputs[i]
			if !hasMinConfs(
				//nolint:gosec
				uint32(requiredConfs), output.Height,
				syncBlock.Height,
			) {

				continue
			}

			if output.FromCoinBase && !hasMinConfs(
				uint32(w.ChainParams().CoinbaseMaturity),
				output.Height, syncBlock.Height,
			) {

				continue
			}
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, w.chainParams)
			if err != nil || len(addrs) == 0 {
				continue
			}
			outputAcct, err := manager.AddrAccount(addrmgrNs, addrs[0])
			if err != nil {
				continue
			}
			switch {
			case outputAcct == waddrmgr.ImportedAddrAccount:
				results[len(results)-1].AccountBalance += output.Amount
			case outputAcct > lastAcct:
				return errors.New("waddrmgr.Manager.AddrAccount returned account " +
					"beyond recorded last account")
			default:
				results[outputAcct].AccountBalance += output.Amount
			}
		}
		return nil
	})
	return results, err
}

// ListUnspentDeprecated returns a slice of objects representing the
// unspent wallet transactions fitting the given criteria. The confirmations
// will be more than
// minconf, less than maxconf and if addresses is populated only the addresses
// contained within it will be considered.  If we know nothing about a
// transaction an empty array will be returned.
//
// Deprecated: Use UtxoManager.ListUnspent instead.
//
//nolint:funlen
func (w *Wallet) ListUnspentDeprecated(minconf, maxconf int32,
	accountName string) ([]*btcjson.ListUnspentResult, error) {

	var results []*btcjson.ListUnspentResult
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.addrStore.SyncedTo()

		filter := accountName != ""

		unspent, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}
		sort.Sort(sort.Reverse(creditSlice(unspent)))

		defaultAccountName := "default"

		results = make([]*btcjson.ListUnspentResult, 0, len(unspent))
		for i := range unspent {
			output := unspent[i]

			// Outputs with fewer confirmations than the minimum or
			// more confs than the maximum are excluded.
			confs := calcConf(output.Height, syncBlock.Height)
			if confs < minconf || confs > maxconf {
				continue
			}

			// Only mature coinbase outputs are included.
			if output.FromCoinBase {
				target := uint32(
					w.ChainParams().CoinbaseMaturity,
				)
				if !hasMinConfs(
					target, output.Height, syncBlock.Height,
				) {

					continue
				}
			}

			// Exclude locked outputs from the result set.
			if w.LockedOutpoint(output.OutPoint) {
				continue
			}

			// Lookup the associated account for the output.  Use the
			// default account name in case there is no associated account
			// for some reason, although this should never happen.
			//
			// This will be unnecessary once transactions and outputs are
			// grouped under the associated account in the db.
			outputAcctName := defaultAccountName
			sc, addrs, _, err := txscript.ExtractPkScriptAddrs(
				output.PkScript, w.chainParams)
			if err != nil {
				continue
			}
			if len(addrs) > 0 {
				smgr, acct, err := w.addrStore.AddrAccount(
					addrmgrNs, addrs[0],
				)
				if err == nil {
					s, err := smgr.AccountName(addrmgrNs, acct)
					if err == nil {
						outputAcctName = s
					}
				}
			}

			if filter && outputAcctName != accountName {
				continue
			}

			// At the moment watch-only addresses are not supported, so all
			// recorded outputs that are not multisig are "spendable".
			// Multisig outputs are only "spendable" if all keys are
			// controlled by this wallet.
			//
			// TODO: Each case will need updates when watch-only addrs
			// is added.  For P2PK, P2PKH, and P2SH, the address must be
			// looked up and not be watching-only.  For multisig, all
			// pubkeys must belong to the manager with the associated
			// private key (currently it only checks whether the pubkey
			// exists, since the private key is required at the moment).
			var spendable bool
		scSwitch:
			switch sc {
			case txscript.PubKeyHashTy:
				spendable = true
			case txscript.PubKeyTy:
				spendable = true
			case txscript.WitnessV0ScriptHashTy:
				spendable = true
			case txscript.WitnessV0PubKeyHashTy:
				spendable = true
			case txscript.MultiSigTy:
				for _, a := range addrs {
					_, err := w.addrStore.Address(
						addrmgrNs, a,
					)
					if err == nil {
						continue
					}
					if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
						break scSwitch
					}
					return err
				}
				spendable = true
			}

			result := &btcjson.ListUnspentResult{
				TxID:          output.OutPoint.Hash.String(),
				Vout:          output.OutPoint.Index,
				Account:       outputAcctName,
				ScriptPubKey:  hex.EncodeToString(output.PkScript),
				Amount:        output.Amount.ToBTC(),
				Confirmations: int64(confs),
				Spendable:     spendable,
			}

			// BUG: this should be a JSON array so that all
			// addresses can be included, or removed (and the
			// caller extracts addresses from the pkScript).
			if len(addrs) > 0 {
				result.Address = addrs[0].EncodeAddress()
			}

			results = append(results, result)
		}
		return nil
	})
	return results, err
}

// ListLeasedOutputsDeprecated returns a list of objects representing the
// currently locked utxos.
//
// Deprecated: Use UtxoManager.ListLeasedOutputs instead.
func (w *Wallet) ListLeasedOutputsDeprecated() (
	[]*ListLeasedOutputResult, error) {

	var results []*ListLeasedOutputResult
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)

		outputs, err := w.txStore.ListLockedOutputs(ns)
		if err != nil {
			return err
		}

		for _, output := range outputs {
			details, err := w.txStore.TxDetails(
				ns, &output.Outpoint.Hash,
			)
			if err != nil {
				return err
			}

			if details == nil {
				log.Infof("unable to find tx details for "+
					"%v:%v", output.Outpoint.Hash,
					output.Outpoint.Index)
				continue
			}

			txOut := details.MsgTx.TxOut[output.Outpoint.Index]

			result := &ListLeasedOutputResult{
				LockedOutput: output,
				Value:        txOut.Value,
				PkScript:     txOut.PkScript,
			}

			results = append(results, result)
		}

		return nil
	})
	return results, err
}

// BlockIdentifier identifies a block by either a height or a hash.
type BlockIdentifier struct {
	height int32
	hash   *chainhash.Hash
}

// NewBlockIdentifierFromHeight constructs a BlockIdentifier for a block height.
func NewBlockIdentifierFromHeight(height int32) *BlockIdentifier {
	return &BlockIdentifier{height: height}
}

// NewBlockIdentifierFromHash constructs a BlockIdentifier for a block hash.
func NewBlockIdentifierFromHash(hash *chainhash.Hash) *BlockIdentifier {
	return &BlockIdentifier{hash: hash}
}

// GetTransactionsResult is the result of the wallet's GetTransactions method.
// See GetTransactions for more details.
type GetTransactionsResult struct {
	MinedTransactions   []Block
	UnminedTransactions []TransactionSummary
}

// GetTransactionResult returns a summary of the transaction along with
// other block properties.
type GetTransactionResult struct {
	Summary       TransactionSummary
	Height        int32
	BlockHash     *chainhash.Hash
	Confirmations int32
	Timestamp     int64
}

// AccountBalanceResult is a single result for the Wallet.AccountBalances method.
type AccountBalanceResult struct {
	AccountNumber  uint32
	AccountName    string
	AccountBalance btcutil.Amount
}

// creditSlice satisifies the sort.Interface interface to provide sorting
// transaction credits from oldest to newest.  Credits with the same receive
// time and mined in the same block are not guaranteed to be sorted by the order
// they appear in the block.  Credits from the same transaction are sorted by
// output index.
type creditSlice []wtxmgr.Credit

func (s creditSlice) Len() int {
	return len(s)
}

func (s creditSlice) Less(i, j int) bool {
	switch {
	// If both credits are from the same tx, sort by output index.
	case s[i].OutPoint.Hash == s[j].OutPoint.Hash:
		return s[i].OutPoint.Index < s[j].OutPoint.Index

	// If both transactions are unmined, sort by their received date.
	case s[i].Height == -1 && s[j].Height == -1:
		return s[i].Received.Before(s[j].Received)

	// Unmined (newer) txs always come last.
	case s[i].Height == -1:
		return false
	case s[j].Height == -1:
		return true

	// If both txs are mined in different blocks, sort by block height.
	default:
		return s[i].Height < s[j].Height
	}
}

func (s creditSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// ListLeasedOutputResult is a single result for the Wallet.ListLeasedOutputs method.
// See that method for more details.
type ListLeasedOutputResult struct {
	*wtxmgr.LockedOutput
	Value    int64
	PkScript []byte
}

func (w *Wallet) newAddressDeprecated(addrmgrNs walletdb.ReadWriteBucket,
	account uint32, scope waddrmgr.KeyScope) (btcutil.Address,
	*waddrmgr.AccountProperties, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, nil, err
	}

	// Get next address from wallet.
	addrs, err := manager.NextExternalAddresses(addrmgrNs, account, 1)
	if err != nil {
		return nil, nil, err
	}

	props, err := manager.AccountProperties(addrmgrNs, account)
	if err != nil {
		log.Errorf("Cannot fetch account properties for notification "+
			"after deriving next external address: %v", err)

		return nil, nil, err
	}

	return addrs[0].Address(), props, nil
}

// AddScopeManager creates a new scoped key manager from the root manager.
func (w *Wallet) AddScopeManager(scope waddrmgr.KeyScope,
	addrSchema waddrmgr.ScopeAddrSchema) (
	waddrmgr.AccountStore, error) {

	var scopedManager waddrmgr.AccountStore

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		manager, err := w.addrStore.NewScopedKeyManager(
			addrmgrNs, scope, addrSchema,
		)
		scopedManager = manager

		return err
	})
	if err != nil {
		return nil, err
	}

	return scopedManager, nil
}

// InitAccounts creates a number of accounts specified by `num`, with account
// number ranges from 1 to `num`.
func (w *Wallet) InitAccounts(scope *waddrmgr.ScopedKeyManager,
	watchOnly bool, num uint32) error {

	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// Generate all accounts that we could ever need. This includes
		// all key families.
		for account := uint32(1); account <= num; account++ {
			// Otherwise, we'll check if the account already exists,
			// if so, we can once again bail early.
			_, err := scope.AccountName(addrmgrNs, account)
			if err == nil {
				continue
			}

			// If we reach this point, then the account hasn't yet
			// been created, so we'll need to create it before we
			// can proceed.
			err = scope.NewRawAccount(addrmgrNs, account)
			if err != nil {
				return err
			}
		}

		// If this is the first startup with remote signing and wallet
		// migration turned on and the wallet wasn't previously
		// migrated, we can do that now that we made sure all accounts
		// that we need were derived correctly.
		if watchOnly {
			log.Infof("Migrating wallet to watch-only mode, " +
				"purging all private key material")

			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			return w.addrStore.ConvertToWatchingOnly(ns)
		}

		return nil
	})
}

// DeriveFromKeyPath derives a private key using the given derivation path.
func (w *Wallet) DeriveFromKeyPath(scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	scopedMgr, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, fmt.Errorf("error fetching manager for scope %v: "+
			"%w", scope, err)
	}

	// Let's see if we can hit the private key cache.
	privKey, err := scopedMgr.DeriveFromKeyPathCache(path)
	if err == nil {
		return privKey, nil
	}

	// The key wasn't in the cache, let's fully derive it now.
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		addr, err := scopedMgr.DeriveFromKeyPath(addrmgrNs, path)
		if err != nil {
			return fmt.Errorf("error deriving private key: %w", err)
		}

		mpka, ok := addr.(waddrmgr.ManagedPubKeyAddress)
		if !ok {
			err := fmt.Errorf("managed address type for %v is "+
				"`%T` but want waddrmgr.ManagedPubKeyAddress",
				addr, addr)

			return err
		}

		privKey, err = mpka.PrivKey()

		return err
	})
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// DeriveFromKeyPathAddAccount derives a private key using the given derivation
// path. The account will be created if it doesn't exist.
func (w *Wallet) DeriveFromKeyPathAddAccount(scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	scopedMgr, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, fmt.Errorf("error fetching manager for scope %v: "+
			"%w", scope, err)
	}

	// Let's see if we can hit the private key cache.
	privKey, err := scopedMgr.DeriveFromKeyPathCache(path)
	if err == nil {
		return privKey, nil
	}

	derivePrivKey := func(addrmgrNs walletdb.ReadWriteBucket) error {
		addr, err := scopedMgr.DeriveFromKeyPath(addrmgrNs, path)

		// Exit early if there's no error.
		if err == nil {
			key, ok := addr.(waddrmgr.ManagedPubKeyAddress)
			if !ok {
				return nil
			}

			// Overwrite the returned private key variable.
			privKey, err = key.PrivKey()

			return err
		}

		return err
	}

	// The key wasn't in the cache, let's fully derive it now.
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := derivePrivKey(addrmgrNs)

		// Exit early if there's no error.
		if err == nil {
			return nil
		}

		// Exit with the error if it's not account not found.
		if !waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return fmt.Errorf("error deriving private key: %w", err)
		}

		// If we've reached this point, then the account doesn't yet
		// exist, so we'll create it now to ensure we can sign.
		err = scopedMgr.NewRawAccount(addrmgrNs, path.Account)
		if err != nil {
			return err
		}

		// Now that we know the account exists, we'll attempt to
		// re-derive the private key.
		return derivePrivKey(addrmgrNs)
	})
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func (w *Wallet) handleChainNotifications() {
	defer w.wg.Done()

	chainClient, err := w.requireChainClient()
	if err != nil {
		log.Errorf("handleChainNotifications called without RPC client")
		return
	}

	catchUpHashes := func(w *Wallet, client chain.Interface,
		height int32) error {
		// TODO(aakselrod): There's a race condition here, which
		// happens when a reorg occurs between the
		// rescanProgress notification and the last GetBlockHash
		// call. The solution when using btcd is to make btcd
		// send blockconnected notifications with each block
		// the way Neutrino does, and get rid of the loop. The
		// other alternative is to check the final hash and,
		// if it doesn't match the original hash returned by
		// the notification, to roll back and restart the
		// rescan.
		log.Infof("Catching up block hashes to height %d, this"+
			" might take a while", height)
		err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			startBlock := w.addrStore.SyncedTo()

			for i := startBlock.Height + 1; i <= height; i++ {
				hash, err := client.GetBlockHash(int64(i))
				if err != nil {
					return err
				}
				header, err := chainClient.GetBlockHeader(hash)
				if err != nil {
					return err
				}

				bs := waddrmgr.BlockStamp{
					Height:    i,
					Hash:      *hash,
					Timestamp: header.Timestamp,
				}

				err = w.addrStore.SetSyncedTo(ns, &bs)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Errorf("Failed to update address manager "+
				"sync state for height %d: %v", height, err)
		}

		log.Info("Done catching up block hashes")
		return err
	}

	waitForSync := func(birthdayBlock *waddrmgr.BlockStamp) error {
		// We start with a retry delay of 0 to execute the first attempt
		// immediately.
		var retryDelay time.Duration
		for {
			select {
			case <-time.After(retryDelay):
				// Set the delay to the configured value in case
				// we actually need to re-try.
				retryDelay = w.syncRetryInterval

				// Sync may be interrupted by actions such as
				// locking the wallet. Try again after waiting a
				// bit.
				err = w.syncWithChain(birthdayBlock)
				if err != nil {
					if w.ShuttingDown() {
						return ErrWalletShuttingDown
					}

					log.Errorf("Unable to synchronize "+
						"wallet to chain, trying "+
						"again in %s: %v",
						w.syncRetryInterval, err)

					continue
				}

				return nil

			case <-w.quitChan():
				return ErrWalletShuttingDown
			}
		}
	}

	for {
		select {
		case n, ok := <-chainClient.Notifications():
			if !ok {
				return
			}

			var notificationName string
			var err error
			switch n := n.(type) {
			case chain.ClientConnected:
				// Before attempting to sync with our backend,
				// we'll make sure that our birthday block has
				// been set correctly to potentially prevent
				// missing relevant events.
				birthdayStore := &walletBirthdayStore{
					db:      w.db,
					manager: w.addrStore,
				}
				birthdayBlock, err := birthdaySanityCheck(
					chainClient, birthdayStore,
				)
				if err != nil && !waddrmgr.IsError(
					err, waddrmgr.ErrBirthdayBlockNotSet,
				) {

					log.Errorf("Unable to sanity check "+
						"wallet birthday block: %v",
						err)
				}

				err = waitForSync(birthdayBlock)
				if err != nil {
					log.Infof("Stopped waiting for wallet "+
						"sync due to error: %v", err)

					return
				}

			case chain.BlockConnected:
				err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
					return w.connectBlock(tx, wtxmgr.BlockMeta(n))
				})
				notificationName = "block connected"
			case chain.BlockDisconnected:
				err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
					return w.disconnectBlock(tx, wtxmgr.BlockMeta(n))
				})
				notificationName = "block disconnected"
			case chain.RelevantTx:
				err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
					return w.addRelevantTx(tx, n.TxRecord, n.Block)
				})
				notificationName = "relevant transaction"
			case chain.FilteredBlockConnected:
				// Atomically update for the whole block.
				if len(n.RelevantTxs) > 0 {
					err = walletdb.Update(w.db, func(
						tx walletdb.ReadWriteTx) error {
						var err error
						for _, rec := range n.RelevantTxs {
							err = w.addRelevantTx(tx, rec,
								n.Block)
							if err != nil {
								return err
							}
						}
						return nil
					})
				}
				notificationName = "filtered block connected"

			// The following require some database maintenance, but also
			// need to be reported to the wallet's rescan goroutine.
			case *chain.RescanProgress:
				err = catchUpHashes(w, chainClient, n.Height)
				notificationName = "rescan progress"
				select {
				case w.rescanNotifications <- n:
				case <-w.quitChan():
					return
				}
			case *chain.RescanFinished:
				err = catchUpHashes(w, chainClient, n.Height)
				notificationName = "rescan finished"
				w.SetChainSynced(true)
				select {
				case w.rescanNotifications <- n:
				case <-w.quitChan():
					return
				}
			}
			if err != nil {
				// If we received a block connected notification
				// while rescanning, then we can ignore logging
				// the error as we'll properly catch up once we
				// process the RescanFinished notification.
				if notificationName == "block connected" &&
					waddrmgr.IsError(err, waddrmgr.ErrBlockNotFound) &&
					!w.ChainSynced() {

					log.Debugf("Received block connected "+
						"notification for height %v "+
						"while rescanning",
						n.(chain.BlockConnected).Height)
					continue
				}

				log.Errorf("Unable to process chain backend "+
					"%v notification: %v", notificationName,
					err)
			}
		case <-w.quit:
			return
		}
	}
}

// connectBlock handles a chain server notification by marking a wallet
// that's currently in-sync with the chain server as being synced up to
// the passed block.
func (w *Wallet) connectBlock(dbtx walletdb.ReadWriteTx, b wtxmgr.BlockMeta) error {
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	bs := waddrmgr.BlockStamp{
		Height:    b.Height,
		Hash:      b.Hash,
		Timestamp: b.Time,
	}

	err := w.addrStore.SetSyncedTo(addrmgrNs, &bs)
	if err != nil {
		return err
	}

	// Notify interested clients of the connected block.
	//
	// TODO: move all notifications outside of the database transaction.
	w.NtfnServer.notifyAttachedBlock(dbtx, &b)
	return nil
}

// disconnectBlock handles a chain server reorganize by rolling back all
// block history from the reorged block for a wallet in-sync with the chain
// server.
func (w *Wallet) disconnectBlock(dbtx walletdb.ReadWriteTx, b wtxmgr.BlockMeta) error {
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	if !w.ChainSynced() {
		return nil
	}

	// Disconnect the removed block and all blocks after it if we know about
	// the disconnected block. Otherwise, the block is in the future.
	//nolint:nestif
	if b.Height <= w.addrStore.SyncedTo().Height {
		hash, err := w.addrStore.BlockHash(addrmgrNs, b.Height)
		if err != nil {
			return err
		}
		if bytes.Equal(hash[:], b.Hash[:]) {
			bs := waddrmgr.BlockStamp{
				Height: b.Height - 1,
			}

			hash, err = w.addrStore.BlockHash(addrmgrNs, bs.Height)
			if err != nil {
				return err
			}
			b.Hash = *hash

			client := w.ChainClient()
			header, err := client.GetBlockHeader(hash)
			if err != nil {
				return err
			}

			bs.Timestamp = header.Timestamp

			err = w.addrStore.SetSyncedTo(addrmgrNs, &bs)
			if err != nil {
				return err
			}

			err = w.txStore.Rollback(txmgrNs, b.Height)
			if err != nil {
				return err
			}
		}
	}

	// Notify interested clients of the disconnected block.
	w.NtfnServer.notifyDetachedBlock(&b.Hash)

	return nil
}

func (w *Wallet) addRelevantTx(dbtx walletdb.ReadWriteTx, rec *wtxmgr.TxRecord,
	block *wtxmgr.BlockMeta) error {

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	// At the moment all notified transactions are assumed to actually be
	// relevant.  This assumption will not hold true when SPV support is
	// added, but until then, simply insert the transaction because there
	// should either be one or more relevant inputs or outputs.
	exists, err := w.txStore.InsertTxCheckIfExists(txmgrNs, rec, block)
	if err != nil {
		return err
	}

	// If the transaction has already been recorded, we can return early.
	// Note: Returning here is safe as we're within the context of an atomic
	// database transaction, so we don't need to worry about the MarkUsed
	// calls below.
	if exists {
		return nil
	}

	// Check every output to determine whether it is controlled by a wallet
	// key.  If so, mark the output as a credit.
	for i, output := range rec.MsgTx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript,
			w.chainParams)
		if err != nil {
			// Non-standard outputs are skipped.
			log.Warnf("Cannot extract non-std pkScript=%x",
				output.PkScript)

			continue
		}

		for _, addr := range addrs {
			ma, err := w.addrStore.Address(addrmgrNs, addr)

			switch {
			// Missing addresses are skipped.
			case waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound):
				continue

			// Other errors should be propagated.
			case err != nil:
				return err
			}

			// Prevent addresses from non-default scopes to be
			// detected here. We don't watch funds sent to
			// non-default scopes in other places either, so
			// detecting them here would mean we'd also not properly
			// detect them as spent later.
			scopedManager, _, err := w.addrStore.AddrAccount(
				addrmgrNs, addr,
			)
			if err != nil {
				return err
			}
			if !waddrmgr.IsDefaultScope(scopedManager.Scope()) {
				log.Debugf("Skipping non-default scope "+
					"address %v", addr)

				continue
			}

			// TODO: Credits should be added with the
			// account they belong to, so wtxmgr is able to
			// track per-account balances.
			err = w.txStore.AddCredit(
				txmgrNs, rec, block, uint32(i), ma.Internal(),
			)
			if err != nil {
				return err
			}

			err = w.addrStore.MarkUsed(addrmgrNs, addr)
			if err != nil {
				return err
			}
			log.Debugf("Marked address %v used", addr)
		}
	}

	// Send notification of mined or unmined transaction to any interested
	// clients.
	//
	// TODO: Avoid the extra db hits.
	if block == nil {
		w.NtfnServer.notifyUnminedTransaction(dbtx, txmgrNs, rec.Hash)
	} else {
		w.NtfnServer.notifyMinedTransaction(
			dbtx, txmgrNs, rec.Hash, block,
		)
	}

	return nil
}

// chainConn is an interface that abstracts the chain connection logic required
// to perform a wallet's birthday block sanity check.
type chainConn interface {
	// GetBestBlock returns the hash and height of the best block known to
	// the backend.
	GetBestBlock() (*chainhash.Hash, int32, error)

	// GetBlockHash returns the hash of the block with the given height.
	GetBlockHash(int64) (*chainhash.Hash, error)

	// GetBlockHeader returns the header for the block with the given hash.
	GetBlockHeader(*chainhash.Hash) (*wire.BlockHeader, error)
}

// birthdayStore is an interface that abstracts the wallet's sync-related
// information required to perform a birthday block sanity check.
type birthdayStore interface {
	// Birthday returns the birthday timestamp of the wallet.
	Birthday() time.Time

	// BirthdayBlock returns the birthday block of the wallet. The boolean
	// returned should signal whether the wallet has already verified the
	// correctness of its birthday block.
	BirthdayBlock() (waddrmgr.BlockStamp, bool, error)

	// SetBirthdayBlock updates the birthday block of the wallet to the
	// given block. The boolean can be used to signal whether this block
	// should be sanity checked the next time the wallet starts.
	//
	// NOTE: This should also set the wallet's synced tip to reflect the new
	// birthday block. This will allow the wallet to rescan from this point
	// to detect any potentially missed events.
	SetBirthdayBlock(waddrmgr.BlockStamp) error
}

// walletBirthdayStore is a wrapper around the wallet's database and address
// manager that satisfies the birthdayStore interface.
type walletBirthdayStore struct {
	db      walletdb.DB
	manager waddrmgr.AddrStore
}

var _ birthdayStore = (*walletBirthdayStore)(nil)

// Birthday returns the birthday timestamp of the wallet.
func (s *walletBirthdayStore) Birthday() time.Time {
	return s.manager.Birthday()
}

// BirthdayBlock returns the birthday block of the wallet.
func (s *walletBirthdayStore) BirthdayBlock() (waddrmgr.BlockStamp, bool, error) {
	var (
		birthdayBlock         waddrmgr.BlockStamp
		birthdayBlockVerified bool
	)

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		var err error
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		birthdayBlock, birthdayBlockVerified, err = s.manager.BirthdayBlock(ns)
		return err
	})

	return birthdayBlock, birthdayBlockVerified, err
}

// SetBirthdayBlock updates the birthday block of the wallet to the
// given block. The boolean can be used to signal whether this block
// should be sanity checked the next time the wallet starts.
//
// NOTE: This should also set the wallet's synced tip to reflect the new
// birthday block. This will allow the wallet to rescan from this point
// to detect any potentially missed events.
func (s *walletBirthdayStore) SetBirthdayBlock(block waddrmgr.BlockStamp) error {
	return walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		err := s.manager.SetBirthdayBlock(ns, block, true)
		if err != nil {
			return err
		}
		return s.manager.SetSyncedTo(ns, &block)
	})
}

// birthdaySanityCheck is a helper function that ensures a birthday block
// correctly reflects the birthday timestamp within a reasonable timestamp
// delta. It's intended to be run after the wallet establishes its connection
// with the backend, but before it begins syncing. This is done as the second
// part to the wallet's address manager migration where we populate the birthday
// block to ensure we do not miss any relevant events throughout rescans.
// waddrmgr.ErrBirthdayBlockNotSet is returned if the birthday block has not
// been set yet.
func birthdaySanityCheck(chainConn chainConn,
	birthdayStore birthdayStore) (*waddrmgr.BlockStamp, error) {

	// We'll start by fetching our wallet's birthday timestamp and block.
	birthdayTimestamp := birthdayStore.Birthday()
	birthdayBlock, birthdayBlockVerified, err := birthdayStore.BirthdayBlock()
	if err != nil {
		return nil, err
	}

	// If the birthday block has already been verified to be correct, we can
	// exit our sanity check to prevent potentially fetching a better
	// candidate.
	if birthdayBlockVerified {
		log.Debugf("Birthday block has already been verified: "+
			"height=%d, hash=%v", birthdayBlock.Height,
			birthdayBlock.Hash)

		return &birthdayBlock, nil
	}

	// Otherwise, we'll attempt to locate a better one now that we have
	// access to the chain.
	newBirthdayBlock, err := locateBirthdayBlock(chainConn, birthdayTimestamp)
	if err != nil {
		return nil, err
	}

	if err := birthdayStore.SetBirthdayBlock(*newBirthdayBlock); err != nil {
		return nil, err
	}

	return newBirthdayBlock, nil
}

// secretSource is an implementation of txauthor.SecretSource for the wallet's
// address manager.
type secretSource struct {
	waddrmgr.AddrStore

	addrmgrNs walletdb.ReadBucket
}

func (s secretSource) GetKey(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
	ma, err := s.Address(s.addrmgrNs, addr)
	if err != nil {
		return nil, false, err
	}

	mpka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		e := fmt.Errorf("managed address type for %v is `%T` but "+
			"want waddrmgr.ManagedPubKeyAddress", addr, ma)
		return nil, false, e
	}
	privKey, err := mpka.PrivKey()
	if err != nil {
		return nil, false, err
	}
	return privKey, ma.Compressed(), nil
}

func (s secretSource) GetScript(addr btcutil.Address) ([]byte, error) {
	ma, err := s.Address(s.addrmgrNs, addr)
	if err != nil {
		return nil, err
	}

	msa, ok := ma.(waddrmgr.ManagedScriptAddress)
	if !ok {
		e := fmt.Errorf("managed address type for %v is `%T` but "+
			"want waddrmgr.ManagedScriptAddress", addr, ma)
		return nil, e
	}
	return msa.Script()
}

// txToOutputs creates a signed transaction which includes each output from
// outputs. Previous outputs to redeem are chosen from the passed account's
// UTXO set and minconf policy. An additional output may be added to return
// change to the wallet. This output will have an address generated from the
// given key scope and account. If a key scope is not specified, the address
// will always be generated from the P2WKH key scope. An appropriate fee is
// included based on the wallet's current relay fee. The wallet must be
// unlocked to create the transaction.
//
// NOTE: The dryRun argument can be set true to create a tx that doesn't alter
// the database. A tx created with this set to true will intentionally have no
// input scripts added and SHOULD NOT be broadcasted.
func (w *Wallet) txToOutputs(outputs []*wire.TxOut,
	coinSelectKeyScope, changeKeyScope *waddrmgr.KeyScope,
	account uint32, minconf int32, feeSatPerKb btcutil.Amount,
	strategy CoinSelectionStrategy, dryRun bool,
	selectedUtxos []wire.OutPoint,
	allowUtxo func(utxo wtxmgr.Credit) bool) (
	*txauthor.AuthoredTx, error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// Get current block's height and hash.
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	// Fall back to default coin selection strategy if none is supplied.
	if strategy == nil {
		strategy = CoinSelectionLargest
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
	defer w.newAddrMtx.Unlock()

	var tx *txauthor.AuthoredTx
	err = walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		addrmgrNs, changeSource, err := w.addrMgrWithChangeSource(
			dbtx, changeKeyScope, account,
		)
		if err != nil {
			return err
		}

		eligible, err := w.findEligibleOutputs(
			dbtx, coinSelectKeyScope, account,
			//nolint:gosec
			uint32(minconf),
			bs, allowUtxo,
		)
		if err != nil {
			return err
		}

		var inputSource txauthor.InputSource
		if len(selectedUtxos) > 0 {
			dedupUtxos := fn.NewSet(selectedUtxos...)
			if len(dedupUtxos) != len(selectedUtxos) {
				return errors.New("selected UTXOs contain " +
					"duplicate values")
			}

			eligibleByOutpoint := make(
				map[wire.OutPoint]wtxmgr.Credit,
			)

			for _, e := range eligible {
				eligibleByOutpoint[e.OutPoint] = e
			}

			var eligibleSelectedUtxo []wtxmgr.Credit
			for _, outpoint := range selectedUtxos {
				e, ok := eligibleByOutpoint[outpoint]

				if !ok {
					return fmt.Errorf("selected outpoint "+
						"not eligible for "+
						"spending: %v", outpoint)
				}
				eligibleSelectedUtxo = append(
					eligibleSelectedUtxo, e,
				)
			}

			inputSource = constantInputSource(eligibleSelectedUtxo)

		} else {
			// Wrap our coins in a type that implements the
			// SelectableCoin interface, so we can arrange them
			// according to the selected coin selection strategy.
			wrappedEligible := make([]Coin, len(eligible))
			for i := range eligible {
				wrappedEligible[i] = Coin{
					TxOut: wire.TxOut{
						Value: int64(
							eligible[i].Amount,
						),
						PkScript: eligible[i].PkScript,
					},
					OutPoint: eligible[i].OutPoint,
				}
			}

			arrangedCoins, err := strategy.ArrangeCoins(
				wrappedEligible, feeSatPerKb,
			)
			if err != nil {
				return err
			}
			inputSource = makeInputSource(arrangedCoins)
		}

		tx, err = txauthor.NewUnsignedTransaction(
			outputs, feeSatPerKb, inputSource, changeSource,
		)
		if err != nil {
			return err
		}

		// Randomize change position, if change exists, before signing.
		// This doesn't affect the serialize size, so the change amount
		// will still be valid.
		if tx.ChangeIndex >= 0 {
			tx.RandomizeChangePosition()
		}

		// If a dry run was requested, we return now before adding the
		// input scripts, and don't commit the database transaction.
		// By returning an error, we make sure the walletdb.Update call
		// rolls back the transaction. But we'll react to this specific
		// error outside of the DB transaction so we can still return
		// the produced chain TX.
		if dryRun {
			return walletdb.ErrDryRunRollBack
		}

		// Before committing the transaction, we'll sign our inputs. If
		// the inputs are part of a watch-only account, there's no
		// private key information stored, so we'll skip signing such.
		var watchOnly bool
		if coinSelectKeyScope == nil {
			// If a key scope wasn't specified, then coin selection
			// was performed from the default wallet accounts
			// (NP2WKH, P2WKH, P2TR), so any key scope provided
			// doesn't impact the result of this call.
			watchOnly, err = w.addrStore.IsWatchOnlyAccount(
				addrmgrNs, waddrmgr.KeyScopeBIP0086, account,
			)
		} else {
			watchOnly, err = w.addrStore.IsWatchOnlyAccount(
				addrmgrNs, *coinSelectKeyScope, account,
			)
		}
		if err != nil {
			return err
		}
		if !watchOnly {
			err = tx.AddAllInputScripts(
				secretSource{w.addrStore, addrmgrNs},
			)
			if err != nil {
				return err
			}

			err = validateMsgTx(
				tx.Tx, tx.PrevScripts, tx.PrevInputValues,
			)
			if err != nil {
				return err
			}
		}

		if tx.ChangeIndex >= 0 && account == waddrmgr.ImportedAddrAccount {
			changeAmount := btcutil.Amount(
				tx.Tx.TxOut[tx.ChangeIndex].Value,
			)
			log.Warnf("Spend from imported account produced "+
				"change: moving %v from imported account into "+
				"default account.", changeAmount)
		}

		// Finally, we'll request the backend to notify us of the
		// transaction that pays to the change address, if there is one,
		// when it confirms.
		if tx.ChangeIndex >= 0 {
			changePkScript := tx.Tx.TxOut[tx.ChangeIndex].PkScript
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				changePkScript, w.chainParams,
			)
			if err != nil {
				return err
			}
			if err := chainClient.NotifyReceived(addrs); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil && !errors.Is(err, walletdb.ErrDryRunRollBack) {
		return nil, err
	}

	return tx, nil
}

// validateMsgTx verifies transaction input scripts for tx.  All previous output
// scripts from outputs redeemed by the transaction, in the same order they are
// spent, must be passed in the prevScripts slice.
func validateMsgTx(tx *wire.MsgTx, prevScripts [][]byte,
	inputValues []btcutil.Amount) error {

	inputFetcher, err := txauthor.TXPrevOutFetcher(
		tx, prevScripts, inputValues,
	)
	if err != nil {
		return err
	}

	hashCache := txscript.NewTxSigHashes(tx, inputFetcher)
	for i, prevScript := range prevScripts {
		vm, err := txscript.NewEngine(
			prevScript, tx, i, txscript.StandardVerifyFlags, nil,
			hashCache, int64(inputValues[i]), inputFetcher,
		)
		if err != nil {
			return fmt.Errorf("cannot create script engine: %w", err)
		}
		err = vm.Execute()
		if err != nil {
			return fmt.Errorf("cannot validate transaction: %w", err)
		}
	}
	return nil
}

const (
	// accountPubKeyDepth is the maximum depth of an extended key for an
	// account public key.
	accountPubKeyDepth = 3

	// pubKeyDepth is the depth of an extended key for a derived public key.
	pubKeyDepth = 5
)

// keyScopeFromPubKey returns the corresponding wallet key scope for the given
// extended public key. The address type can usually be inferred from the key's
// version, but may be required for certain keys to map them into the proper
// scope.
func keyScopeFromPubKey(pubKey *hdkeychain.ExtendedKey,
	addrType *waddrmgr.AddressType) (waddrmgr.KeyScope,
	*waddrmgr.ScopeAddrSchema, error) {

	switch waddrmgr.HDVersion(binary.BigEndian.Uint32(pubKey.Version())) {
	// For BIP-0044 keys, an address type must be specified as we intend to
	// not support importing BIP-0044 keys into the wallet using the legacy
	// pay-to-pubkey-hash (P2PKH) scheme. A nested witness address type will
	// force the standard BIP-0049 derivation scheme (nested witness pubkeys
	// everywhere), while a witness address type will force the standard
	// BIP-0084 derivation scheme.
	case waddrmgr.HDVersionMainNetBIP0044, waddrmgr.HDVersionTestNetBIP0044,
		waddrmgr.HDVersionSimNetBIP0044:

		if addrType == nil {
			return waddrmgr.KeyScope{}, nil, errors.New("address " +
				"type must be specified for account public " +
				"key with legacy version")
		}

		switch *addrType {
		case waddrmgr.NestedWitnessPubKey:
			return waddrmgr.KeyScopeBIP0049Plus,
				&waddrmgr.KeyScopeBIP0049AddrSchema, nil

		case waddrmgr.WitnessPubKey:
			return waddrmgr.KeyScopeBIP0084, nil, nil

		case waddrmgr.TaprootPubKey:
			return waddrmgr.KeyScopeBIP0086, nil, nil

		default:
			return waddrmgr.KeyScope{}, nil,
				fmt.Errorf("unsupported address type %v",
					*addrType)
		}

	// For BIP-0049 keys, we'll need to make a distinction between the
	// traditional BIP-0049 address schema (nested witness pubkeys
	// everywhere) and our own BIP-0049Plus address schema (nested
	// externally, witness internally).
	case waddrmgr.HDVersionMainNetBIP0049, waddrmgr.HDVersionTestNetBIP0049:
		if addrType == nil {
			return waddrmgr.KeyScope{}, nil, errors.New("address " +
				"type must be specified for account public " +
				"key with BIP-0049 version")
		}

		switch *addrType {
		case waddrmgr.NestedWitnessPubKey:
			return waddrmgr.KeyScopeBIP0049Plus,
				&waddrmgr.KeyScopeBIP0049AddrSchema, nil

		case waddrmgr.WitnessPubKey:
			return waddrmgr.KeyScopeBIP0049Plus, nil, nil

		default:
			return waddrmgr.KeyScope{}, nil,
				fmt.Errorf("unsupported address type %v",
					*addrType)
		}

	// BIP-0086 does not have its own SLIP-0132 HD version byte set (yet?).
	// So we either expect a user to import it with a BIP-0084 or BIP-0044
	// encoding.
	case waddrmgr.HDVersionMainNetBIP0084, waddrmgr.HDVersionTestNetBIP0084:
		if addrType == nil {
			return waddrmgr.KeyScope{}, nil, errors.New("address " +
				"type must be specified for account public " +
				"key with BIP-0084 version")
		}

		switch *addrType {
		case waddrmgr.WitnessPubKey:
			return waddrmgr.KeyScopeBIP0084, nil, nil

		case waddrmgr.TaprootPubKey:
			return waddrmgr.KeyScopeBIP0086, nil, nil

		default:
			return waddrmgr.KeyScope{}, nil,
				errors.New("address type mismatch")
		}

	default:
		return waddrmgr.KeyScope{}, nil, fmt.Errorf("unknown version %x",
			pubKey.Version())
	}
}

// isPubKeyForNet determines if the given public key is for the current network
// the wallet is operating under.
func (w *Wallet) isPubKeyForNet(pubKey *hdkeychain.ExtendedKey) bool {
	version := waddrmgr.HDVersion(binary.BigEndian.Uint32(pubKey.Version()))
	switch w.chainParams.Net {
	case wire.MainNet:
		return version == waddrmgr.HDVersionMainNetBIP0044 ||
			version == waddrmgr.HDVersionMainNetBIP0049 ||
			version == waddrmgr.HDVersionMainNetBIP0084

	case wire.TestNet, wire.TestNet3, wire.TestNet4,
		netparams.SigNetWire(w.chainParams):

		return version == waddrmgr.HDVersionTestNetBIP0044 ||
			version == waddrmgr.HDVersionTestNetBIP0049 ||
			version == waddrmgr.HDVersionTestNetBIP0084

	// For simnet, we'll also allow the mainnet versions since simnet
	// doesn't have defined versions for some of our key scopes, and the
	// mainnet versions are usually used as the default regardless of the
	// network/key scope.
	case wire.SimNet:
		return version == waddrmgr.HDVersionSimNetBIP0044 ||
			version == waddrmgr.HDVersionMainNetBIP0049 ||
			version == waddrmgr.HDVersionMainNetBIP0084

	default:
		return false
	}
}

// validateExtendedPubKey ensures a sane derived public key is provided.
func (w *Wallet) validateExtendedPubKey(pubKey *hdkeychain.ExtendedKey,
	isAccountKey bool) error {

	// Private keys are not allowed.
	if pubKey.IsPrivate() {
		return errors.New("private keys cannot be imported")
	}

	// The public key must have a version corresponding to the current
	// chain.
	if !w.isPubKeyForNet(pubKey) {
		return fmt.Errorf("expected extended public key for current "+
			"network %v", w.chainParams.Name)
	}

	// Verify the extended public key's depth and child index based on
	// whether it's an account key or not.
	if isAccountKey {
		if pubKey.Depth() != accountPubKeyDepth {
			return errors.New("invalid account key, must be of the " +
				"form m/purpose'/coin_type'/account'")
		}
		if pubKey.ChildIndex() < hdkeychain.HardenedKeyStart {
			return errors.New("invalid account key, must be hardened")
		}
	} else {
		if pubKey.Depth() != pubKeyDepth {
			return errors.New("invalid account key, must be of the " +
				"form m/purpose'/coin_type'/account'/change/" +
				"address_index")
		}
		if pubKey.ChildIndex() >= hdkeychain.HardenedKeyStart {
			return errors.New("invalid pulic key, must not be " +
				"hardened")
		}
	}

	return nil
}

// ImportAccountDeprecated imports an account backed by an account extended
// public key.
// The master key fingerprint denotes the fingerprint of the root key
// corresponding to the account public key (also known as the key with
// derivation path m/). This may be required by some hardware wallets for proper
// identification and signing.
//
// The address type can usually be inferred from the key's version, but may be
// required for certain keys to map them into the proper scope.
//
// For BIP-0044 keys, an address type must be specified as we intend to not
// support importing BIP-0044 keys into the wallet using the legacy
// pay-to-pubkey-hash (P2PKH) scheme. A nested witness address type will force
// the standard BIP-0049 derivation scheme, while a witness address type will
// force the standard BIP-0084 derivation scheme.
//
// For BIP-0049 keys, an address type must also be specified to make a
// distinction between the traditional BIP-0049 address schema (nested witness
// pubkeys everywhere) and our own BIP-0049Plus address schema (nested
// externally, witness internally).
func (w *Wallet) ImportAccountDeprecated(
	name string, accountPubKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32, addrType *waddrmgr.AddressType) (
	*waddrmgr.AccountProperties, error) {

	var accountProps *waddrmgr.AccountProperties
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		var err error
		accountProps, err = w.importAccount(
			ns, name, accountPubKey, masterKeyFingerprint, addrType,
		)
		return err
	})
	return accountProps, err
}

// ImportAccountWithScope imports an account backed by an account extended
// public key for a specific key scope which is known in advance.
// The master key fingerprint denotes the fingerprint of the root key
// corresponding to the account public key (also known as the key with
// derivation path m/). This may be required by some hardware wallets for proper
// identification and signing.
func (w *Wallet) ImportAccountWithScope(name string,
	accountPubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32,
	keyScope waddrmgr.KeyScope, addrSchema waddrmgr.ScopeAddrSchema) (
	*waddrmgr.AccountProperties, error) {

	var accountProps *waddrmgr.AccountProperties
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		var err error
		accountProps, err = w.importAccountScope(
			ns, name, accountPubKey, masterKeyFingerprint, keyScope,
			&addrSchema,
		)
		return err
	})
	return accountProps, err
}

// importAccount is the internal implementation of ImportAccount -- one should
// reference its documentation for this method.
func (w *Wallet) importAccount(ns walletdb.ReadWriteBucket, name string,
	accountPubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32,
	addrType *waddrmgr.AddressType) (*waddrmgr.AccountProperties, error) {

	// Ensure we have a valid account public key.
	if err := w.validateExtendedPubKey(accountPubKey, true); err != nil {
		return nil, err
	}

	// Determine what key scope the account public key should belong to and
	// whether it should use a custom address schema.
	keyScope, addrSchema, err := keyScopeFromPubKey(accountPubKey, addrType)
	if err != nil {
		return nil, err
	}

	return w.importAccountScope(
		ns, name, accountPubKey, masterKeyFingerprint, keyScope,
		addrSchema,
	)
}

// importAccountScope imports a watch-only account for a given scope.
func (w *Wallet) importAccountScope(ns walletdb.ReadWriteBucket, name string,
	accountPubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32,
	keyScope waddrmgr.KeyScope, addrSchema *waddrmgr.ScopeAddrSchema) (
	*waddrmgr.AccountProperties, error) {

	scopedMgr, err := w.addrStore.FetchScopedKeyManager(keyScope)
	if err != nil {
		scopedMgr, err = w.addrStore.NewScopedKeyManager(
			ns, keyScope, *addrSchema,
		)
		if err != nil {
			return nil, err
		}
	}

	account, err := scopedMgr.NewAccountWatchingOnly(
		ns, name, accountPubKey, masterKeyFingerprint, addrSchema,
	)
	if err != nil {
		return nil, err
	}
	return scopedMgr.AccountProperties(ns, account)
}

// ImportAccountDryRun serves as a dry run implementation of ImportAccount. This
// method also returns the first N external and internal addresses, which can be
// presented to users to confirm whether the account has been imported
// correctly.
func (w *Wallet) ImportAccountDryRun(name string,
	accountPubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32,
	addrType *waddrmgr.AddressType, numAddrs uint32) (
	*waddrmgr.AccountProperties, []waddrmgr.ManagedAddress,
	[]waddrmgr.ManagedAddress, error) {

	// The address manager uses OnCommit on the walletdb tx to update the
	// in-memory state of the account state. But because the commit happens
	// _after_ the account manager internal lock has been released, there
	// is a chance for the address index to be accessed concurrently, even
	// though the closure in OnCommit re-acquires the lock. To avoid this
	// issue, we surround the whole address creation process with a lock.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var (
		accountProps  *waddrmgr.AccountProperties
		externalAddrs []waddrmgr.ManagedAddress
		internalAddrs []waddrmgr.ManagedAddress
	)

	// Start a database transaction that we'll never commit and always
	// rollback because we'll return a specific error in the end.
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// Import the account as usual.
		var err error
		accountProps, err = w.importAccount(
			ns, name, accountPubKey, masterKeyFingerprint, addrType,
		)
		if err != nil {
			return err
		}

		// Derive the external and internal addresses. Note that we
		// could do this based on the provided accountPubKey alone, but
		// we go through the ScopedKeyManager instead to ensure
		// addresses will be derived as expected from the wallet's
		// point-of-view.
		manager, err := w.addrStore.FetchScopedKeyManager(
			accountProps.KeyScope,
		)
		if err != nil {
			return err
		}

		// The importAccount method above will cache the imported
		// account within the scoped manager. Since this is a dry-run
		// attempt, we'll want to invalidate the cache for it.
		defer manager.InvalidateAccountCache(accountProps.AccountNumber)

		externalAddrs, err = manager.NextExternalAddresses(
			ns, accountProps.AccountNumber, numAddrs,
		)
		if err != nil {
			return err
		}
		internalAddrs, err = manager.NextInternalAddresses(
			ns, accountProps.AccountNumber, numAddrs,
		)
		if err != nil {
			return err
		}

		// Refresh the account's properties after generating the
		// addresses.
		accountProps, err = manager.AccountProperties(
			ns, accountProps.AccountNumber,
		)
		if err != nil {
			return err
		}

		// Make sure we always roll back the dry-run transaction by
		// returning an error here.
		return walletdb.ErrDryRunRollBack
	})
	if err != nil && err != walletdb.ErrDryRunRollBack {
		return nil, nil, nil, err
	}

	return accountProps, externalAddrs, internalAddrs, nil
}

// ImportPublicKey imports a single derived public key into the address manager.
// The address type can usually be inferred from the key's version, but in the
// case of legacy versions (xpub, tpub), an address type must be specified as we
// intend to not support importing BIP-44 keys into the wallet using the legacy
// pay-to-pubkey-hash (P2PKH) scheme.
func (w *Wallet) ImportPublicKeyDeprecated(pubKey *btcec.PublicKey,
	addrType waddrmgr.AddressType) error {

	// Determine what key scope the public key should belong to and import
	// it into the key scope's default imported account.
	var keyScope waddrmgr.KeyScope
	switch addrType {
	case waddrmgr.NestedWitnessPubKey:
		keyScope = waddrmgr.KeyScopeBIP0049Plus

	case waddrmgr.WitnessPubKey:
		keyScope = waddrmgr.KeyScopeBIP0084

	case waddrmgr.TaprootPubKey:
		keyScope = waddrmgr.KeyScopeBIP0086

	default:
		return fmt.Errorf("address type %v is not supported", addrType)
	}

	scopedKeyManager, err := w.addrStore.FetchScopedKeyManager(keyScope)
	if err != nil {
		return err
	}

	// TODO: Perform rescan if requested.
	var addr waddrmgr.ManagedAddress
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		addr, err = scopedKeyManager.ImportPublicKey(ns, pubKey, nil)
		return err
	})
	if err != nil {
		return err
	}

	log.Infof("Imported address %v", addr.Address())

	err = w.chainClient.NotifyReceived([]btcutil.Address{addr.Address()})
	if err != nil {
		return fmt.Errorf("unable to subscribe for address "+
			"notifications: %w", err)
	}

	return nil
}

// ImportTaprootScriptDeprecated imports a user-provided taproot script into the
// address manager. The imported script will act as a pay-to-taproot address.
//
// Deprecated: Use AddressManager.ImportTaprootScript instead.
func (w *Wallet) ImportTaprootScriptDeprecated(scope waddrmgr.KeyScope,
	tapscript *waddrmgr.Tapscript, bs *waddrmgr.BlockStamp,
	witnessVersion byte, isSecretScript bool) (waddrmgr.ManagedAddress,
	error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return nil, err
	}

	// The starting block for the key is the genesis block unless otherwise
	// specified.
	if bs == nil {
		bs = &waddrmgr.BlockStamp{
			Hash:      *w.chainParams.GenesisHash,
			Height:    0,
			Timestamp: w.chainParams.GenesisBlock.Header.Timestamp,
		}
	} else if bs.Timestamp.IsZero() {
		// Only update the new birthday time from default value if we
		// actually have timestamp info in the header.
		header, err := w.chainClient.GetBlockHeader(&bs.Hash)
		if err == nil {
			bs.Timestamp = header.Timestamp
		}
	}

	// TODO: Perform rescan if requested.
	var addr waddrmgr.ManagedAddress
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		addr, err = manager.ImportTaprootScript(
			ns, tapscript, bs, witnessVersion, isSecretScript,
		)
		return err
	})
	if err != nil {
		return nil, err
	}

	log.Infof("Imported address %v", addr.Address())

	err = w.chainClient.NotifyReceived([]btcutil.Address{addr.Address()})
	if err != nil {
		return nil, fmt.Errorf("unable to subscribe for address "+
			"notifications: %w", err)
	}

	return addr, nil
}

// ImportPrivateKey imports a private key to the wallet and writes the new
// wallet to disk.
//
// NOTE: If a block stamp is not provided, then the wallet's birthday will be
// set to the genesis block of the corresponding chain.
func (w *Wallet) ImportPrivateKey(scope waddrmgr.KeyScope, wif *btcutil.WIF,
	bs *waddrmgr.BlockStamp, rescan bool) (string, error) {

	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return "", err
	}

	// The starting block for the key is the genesis block unless otherwise
	// specified.
	if bs == nil {
		bs = &waddrmgr.BlockStamp{
			Hash:      *w.chainParams.GenesisHash,
			Height:    0,
			Timestamp: w.chainParams.GenesisBlock.Header.Timestamp,
		}
	} else if bs.Timestamp.IsZero() {
		// Only update the new birthday time from default value if we
		// actually have timestamp info in the header.
		header, err := w.chainClient.GetBlockHeader(&bs.Hash)
		if err == nil {
			bs.Timestamp = header.Timestamp
		}
	}

	// Attempt to import private key into wallet.
	var addr btcutil.Address
	var props *waddrmgr.AccountProperties
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		maddr, err := manager.ImportPrivateKey(addrmgrNs, wif, bs)
		if err != nil {
			return err
		}
		addr = maddr.Address()
		props, err = manager.AccountProperties(
			addrmgrNs, waddrmgr.ImportedAddrAccount,
		)
		if err != nil {
			return err
		}

		// We'll only update our birthday with the new one if it is
		// before our current one. Otherwise, if we do, we can
		// potentially miss detecting relevant chain events that
		// occurred between them while rescanning.
		birthdayBlock, _, err := w.addrStore.BirthdayBlock(addrmgrNs)
		if err != nil {
			return err
		}
		if bs.Height >= birthdayBlock.Height {
			return nil
		}

		err = w.addrStore.SetBirthday(addrmgrNs, bs.Timestamp)
		if err != nil {
			return err
		}

		// To ensure this birthday block is correct, we'll mark it as
		// unverified to prompt a sanity check at the next restart to
		// ensure it is correct as it was provided by the caller.
		return w.addrStore.SetBirthdayBlock(addrmgrNs, *bs, false)
	})
	if err != nil {
		return "", err
	}

	// Rescan blockchain for transactions with txout scripts paying to the
	// imported address.
	if rescan {
		job := &RescanJob{
			Addrs:      []btcutil.Address{addr},
			OutPoints:  nil,
			BlockStamp: *bs,
		}

		// Submit rescan job and log when the import has completed.
		// Do not block on finishing the rescan.  The rescan success
		// or failure is logged elsewhere, and the channel is not
		// required to be read, so discard the return value.
		_ = w.SubmitRescan(job)
	} else {
		err := w.chainClient.NotifyReceived([]btcutil.Address{addr})
		if err != nil {
			return "", fmt.Errorf("failed to subscribe for address ntfns for "+
				"address %s: %w", addr.EncodeAddress(), err)
		}
	}

	addrStr := addr.EncodeAddress()
	log.Infof("Imported payment address %s", addrStr)

	w.NtfnServer.notifyAccountProperties(props)

	// Return the payment address string of the imported private key.
	return addrStr, nil
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
