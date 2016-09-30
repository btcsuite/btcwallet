// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"

	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/walletdb"
	"github.com/decred/dcrwallet/wtxmgr"
)

// MakeSecp256k1MultiSigScript creates a multi-signature script that can be
// redeemed with nRequired signatures of the passed keys and addresses.  If the
// address is a P2PKH address, the associated pubkey is looked up by the wallet
// if possible, otherwise an error is returned for a missing pubkey.
//
// This function only works with secp256k1 pubkeys and P2PKH addresses derived
// from them.
func (w *Wallet) MakeSecp256k1MultiSigScript(secp256k1Addrs []dcrutil.Address, nRequired int) ([]byte, error) {
	secp256k1PubKeys := make([]*dcrutil.AddressSecpPubKey, len(secp256k1Addrs))

	var dbtx walletdb.ReadTx
	var addrmgrNs walletdb.ReadBucket
	defer func() {
		if dbtx != nil {
			dbtx.Rollback()
		}
	}()

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, addr := range secp256k1Addrs {
		switch addr := addr.(type) {
		default:
			return nil, errors.New("cannot make multisig script for " +
				"a non-secp256k1 public key or P2PKH address")

		case *dcrutil.AddressSecpPubKey:
			secp256k1PubKeys[i] = addr

		case *dcrutil.AddressPubKeyHash:
			if addr.DSA(w.chainParams) != chainec.ECTypeSecp256k1 {
				return nil, errors.New("cannot make multisig " +
					"script for a non-secp256k1 P2PKH address")
			}

			if dbtx == nil {
				var err error
				dbtx, err = w.db.BeginReadTx()
				if err != nil {
					return nil, err
				}
				addrmgrNs = dbtx.ReadBucket(waddrmgrNamespaceKey)
			}
			addrInfo, err := w.Manager.Address(addrmgrNs, addr)
			if err != nil {
				return nil, err
			}
			serializedPubKey := addrInfo.(waddrmgr.ManagedPubKeyAddress).
				PubKey().Serialize()

			pubKeyAddr, err := dcrutil.NewAddressSecpPubKey(
				serializedPubKey, w.chainParams)
			if err != nil {
				return nil, err
			}
			secp256k1PubKeys[i] = pubKeyAddr
		}
	}

	return txscript.MultiSigScript(secp256k1PubKeys, nRequired)
}

// ImportP2SHRedeemScript adds a P2SH redeem script to the wallet.
func (w *Wallet) ImportP2SHRedeemScript(script []byte) (*dcrutil.AddressScriptHash, error) {
	var p2shAddr *dcrutil.AddressScriptHash
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		err := w.TxStore.InsertTxScript(txmgrNs, script)
		if err != nil {
			return err
		}

		// TODO(oga) blockstamp current block?
		bs := &waddrmgr.BlockStamp{
			Hash:   *w.ChainParams().GenesisHash,
			Height: 0,
		}

		addrInfo, err := w.Manager.ImportScript(addrmgrNs, script, bs)
		if err != nil {
			// Don't care if it's already there, but still have to
			// set the p2shAddr since the address manager didn't
			// return anything useful.
			if waddrmgr.IsError(err, waddrmgr.ErrDuplicateAddress) {
				// This function will never error as it always
				// hashes the script to the correct length.
				p2shAddr, _ = dcrutil.NewAddressScriptHash(script,
					w.chainParams)
				return nil
			}
			return err
		}

		p2shAddr = addrInfo.Address().(*dcrutil.AddressScriptHash)
		return nil
	})
	return p2shAddr, err
}

// FetchP2SHMultiSigOutput fetches information regarding a wallet's P2SH
// multi-signature output.
func (w *Wallet) FetchP2SHMultiSigOutput(outPoint *wire.OutPoint) (*P2SHMultiSigOutput, error) {
	var (
		mso          *wtxmgr.MultisigOut
		redeemScript []byte
	)
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		var err error

		mso, err = w.TxStore.GetMultisigOutput(txmgrNs, outPoint)
		if err != nil {
			return err
		}

		redeemScript, err = w.TxStore.GetTxScript(txmgrNs, mso.ScriptHash[:])
		if err != nil {
			return err
		}
		// returns nil, nil when it successfully found no script.  That error is
		// only used to return early when the database is closed.
		if redeemScript == nil {
			return errors.New("script not found")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	p2shAddr, err := dcrutil.NewAddressScriptHashFromHash(
		mso.ScriptHash[:], w.chainParams)
	if err != nil {
		return nil, err
	}

	multiSigOutput := P2SHMultiSigOutput{
		OutPoint:     *mso.OutPoint,
		OutputAmount: mso.Amount,
		ContainingBlock: BlockIdentity{
			Hash:   mso.BlockHash,
			Height: int32(mso.BlockHeight),
		},
		P2SHAddress:  p2shAddr,
		RedeemScript: redeemScript,
		M:            mso.M,
		N:            mso.N,
		Redeemer:     nil,
	}

	if mso.Spent {
		multiSigOutput.Redeemer = &OutputRedeemer{
			TxHash:     mso.SpentBy,
			InputIndex: mso.SpentByIndex,
		}
	}

	return &multiSigOutput, nil
}

// FetchAllRedeemScripts returns all P2SH redeem scripts saved by the wallet.
func (w *Wallet) FetchAllRedeemScripts() ([][]byte, error) {
	var redeemScripts [][]byte
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)
		var err error
		redeemScripts, err = w.TxStore.StoredTxScripts(txmgrNs)
		return err
	})
	return redeemScripts, err
}
