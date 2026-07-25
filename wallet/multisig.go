// Copyright (c) 2017 The btcsuite developers
// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// MakeMultiSigScript creates a multi-signature script that can be redeemed with
// nRequired signatures of the passed keys and addresses.  If the address is a
// P2PKH address, the associated pubkey is looked up by the wallet if possible,
// otherwise an error is returned for a missing pubkey.
//
// This function only works with pubkeys and P2PKH addresses derived from them.
func (w *Wallet) MakeMultiSigScript(addrs []address.Address,
	nRequired int) ([]byte, error) {

	pubKeys := make([]*address.AddressPubKey, len(addrs))

	var dbtx walletdb.ReadTx
	var addrmgrNs walletdb.ReadBucket
	defer func() {
		if dbtx != nil {
			_ = dbtx.Rollback()
		}
	}()

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, addr := range addrs {
		switch addr := addr.(type) {
		default:
			return nil, errors.New("cannot make multisig script for " +
				"a non-secp256k1 public key or P2PKH address")

		case *address.AddressPubKey:
			pubKeys[i] = addr

		case *address.AddressPubKeyHash:
			if dbtx == nil && w.db != nil {
				var err error
				dbtx, err = w.db.BeginReadTx()
				if err != nil {
					return nil, err
				}
				addrmgrNs = dbtx.ReadBucket(waddrmgrNamespaceKey)
			}
			var addrInfo waddrmgr.ManagedAddress
			var err error
			if w.db != nil {
				addrInfo, err = w.Manager.Address(addrmgrNs, addr)
			} else {
				addrInfo, err = w.AddressInfo(addr)
			}
			if err != nil {
				return nil, err
			}
			serializedPubKey := addrInfo.(waddrmgr.ManagedPubKeyAddress).
				PubKey().SerializeCompressed()

			pubKeyAddr, err := address.NewAddressPubKey(
				serializedPubKey, w.chainParams)
			if err != nil {
				return nil, err
			}
			pubKeys[i] = pubKeyAddr
		}
	}

	return txscript.MultiSigScript(pubKeys, nRequired)
}

// ImportP2SHRedeemScript adds a P2SH redeem script to the wallet.
func (w *Wallet) ImportP2SHRedeemScript(
	script []byte) (*address.AddressScriptHash, error) {

	var p2shAddr *address.AddressScriptHash
	importScript := func(
		importer func(*waddrmgr.ScopedKeyManager) (
			waddrmgr.ManagedScriptAddress, error)) error {

		bip44Mgr, err := w.Manager.FetchScopedKeyManager(
			waddrmgr.KeyScopeBIP0084,
		)
		if err != nil {
			return err
		}

		addrInfo, err := importer(bip44Mgr)
		if err != nil {
			if waddrmgr.IsError(err, waddrmgr.ErrDuplicateAddress) {
				p2shAddr, _ = address.NewAddressScriptHash(
					script, w.chainParams,
				)
				return nil
			}
			return err
		}

		castAddr, ok := addrInfo.Address().(*address.AddressScriptHash)
		if !ok {
			return fmt.Errorf(
				"unexpected address type: %T", addrInfo.Address(),
			)
		}
		p2shAddr = castAddr

		return nil
	}

	var err error
	if w.db != nil {
		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			// TODO(oga) blockstamp current block?
			bs := &waddrmgr.BlockStamp{
				Hash:   *w.ChainParams().GenesisHash,
				Height: 0,
			}

			return importScript(func(manager *waddrmgr.ScopedKeyManager) (
				waddrmgr.ManagedScriptAddress, error) {

				return manager.ImportScript(addrmgrNs, script, bs)
			})
		})
	} else {
		err = w.store.UpdateOnce(
			context.Background(),
			func(tx walletstore.ReadWriteTx) error {
				bs := &waddrmgr.BlockStamp{
					Hash:      *w.ChainParams().GenesisHash,
					Height:    0,
					Timestamp: w.ChainParams().GenesisBlock.Header.Timestamp,
				}

				return importScript(
					func(manager *waddrmgr.ScopedKeyManager) (
						waddrmgr.ManagedScriptAddress, error) {

						return manager.ImportScriptFromStore(
							tx.Addr(), script, bs,
						)
					},
				)
			}, func() {
				p2shAddr = nil
			},
		)
	}
	w.refreshStartBlockAfterAmbiguous(err)
	return p2shAddr, err
}
