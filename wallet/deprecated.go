//nolint:lll
package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
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
