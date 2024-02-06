// Copyright (c) 2016 The Decred developers
// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

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

func (p *OutputSelectionPolicy) meetsRequiredConfs(txHeight, curHeight int32) bool {
	return confirmed(p.RequiredConfirmations, txHeight, curHeight)
}

// UnspentOutputs fetches all unspent outputs from the wallet that match rules
// described in the passed policy.
func (w *Wallet) UnspentOutputs(policy OutputSelectionPolicy) ([]*TransactionOutput, error) {
	var outputResults []*TransactionOutput
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		syncBlock := w.Manager.SyncedTo()

		// TODO: actually stream outputs from the db instead of fetching
		// all of them at once.
		outputs, err := w.TxStore.UnspentOutputs(txmgrNs)
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
			_, outputAcct, err := w.Manager.AddrAccount(addrmgrNs, addrs[0])
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
// full transaction, the target txout and the number of confirmations are
// returned. Otherwise, a non-nil error value of ErrNotMine is returned instead.
func (w *Wallet) FetchInputInfo(prevOut *wire.OutPoint) (*wire.MsgTx,
	*wire.TxOut, *psbt.Bip32Derivation, int64, error) {

	// We manually look up the output within the tx store.
	txid := &prevOut.Hash
	txDetail, err := UnstableAPI(w).TxDetails(txid)
	if err != nil {
		return nil, nil, nil, 0, err
	} else if txDetail == nil {
		return nil, nil, nil, 0, ErrNotMine
	}

	// With the output retrieved, we'll make an additional check to ensure
	// we actually have control of this output. We do this because the check
	// above only guarantees that the transaction is somehow relevant to us,
	// like in the event of us being the sender of the transaction.
	numOutputs := uint32(len(txDetail.TxRecord.MsgTx.TxOut))
	if prevOut.Index >= numOutputs {
		return nil, nil, nil, 0, fmt.Errorf("invalid output index %v for "+
			"transaction with %v outputs", prevOut.Index,
			numOutputs)
	}
	pkScript := txDetail.TxRecord.MsgTx.TxOut[prevOut.Index].PkScript
	addr, err := w.fetchOutputAddr(pkScript)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	pubKeyAddr, ok := addr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, nil, nil, 0, ErrNotMine
	}
	keyScope, derivationPath, _ := pubKeyAddr.DerivationInfo()

	// Determine the number of confirmations the output currently has.
	_, currentHeight, err := w.chainClient.GetBestBlock()
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("unable to retrieve current "+
			"height: %v", err)
	}
	confs := int64(0)
	if txDetail.Block.Height != -1 {
		confs = int64(currentHeight - txDetail.Block.Height)
	}

	return &txDetail.TxRecord.MsgTx, &wire.TxOut{
			Value:    txDetail.TxRecord.MsgTx.TxOut[prevOut.Index].Value,
			PkScript: pkScript,
		}, &psbt.Bip32Derivation{
			PubKey:               pubKeyAddr.PubKey().SerializeCompressed(),
			MasterKeyFingerprint: derivationPath.MasterKeyFingerprint,
			Bip32Path: []uint32{
				keyScope.Purpose + hdkeychain.HardenedKeyStart,
				keyScope.Coin + hdkeychain.HardenedKeyStart,
				derivationPath.Account,
				derivationPath.Branch,
				derivationPath.Index,
			},
		}, confs, nil
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
		addr, err := w.AddressInfo(addr)
		if err == nil {
			return addr, nil
		}
	}

	return nil, ErrNotMine
}
