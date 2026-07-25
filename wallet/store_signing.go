// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// storeAccountKey identifies one detached account row.
type storeAccountKey struct {
	scope   waddrmgr.KeyScope
	account uint32
}

// storeAddressMaterial couples one address row with the account row needed to
// reconstruct chain-derived key material after a Store callback returns.
type storeAddressMaterial struct {
	account waddrmgr.AccountState
	address waddrmgr.AddressState
}

// storeAddressSnapshot owns all durable address material read in one Store
// transaction attempt.
type storeAddressSnapshot struct {
	accounts  map[storeAccountKey]waddrmgr.AccountState
	addresses map[[sha256.Size]byte][]waddrmgr.AddressState
}

// copyStoreAccountState detaches account byte slices and optional schema state
// from a backend-owned row.
func copyStoreAccountState(
	state waddrmgr.AccountState) waddrmgr.AccountState {

	state.EncryptedPubKey = append([]byte(nil), state.EncryptedPubKey...)
	state.EncryptedPrivKey = append([]byte(nil), state.EncryptedPrivKey...)
	if state.AddrSchema != nil {
		schema := *state.AddrSchema
		state.AddrSchema = &schema
	}

	return state
}

// copyStoreAddressState detaches address byte slices and optional metadata from
// a backend-owned row.
func copyStoreAddressState(
	state waddrmgr.AddressState) waddrmgr.AddressState {

	state.Hash = append([]byte(nil), state.Hash...)
	state.EncryptedPubKey = append([]byte(nil), state.EncryptedPubKey...)
	state.EncryptedPrivKey = append([]byte(nil), state.EncryptedPrivKey...)
	state.EncryptedHash = append([]byte(nil), state.EncryptedHash...)
	state.EncryptedScript = append([]byte(nil), state.EncryptedScript...)
	if state.Branch != nil {
		branch := *state.Branch
		state.Branch = &branch
	}
	if state.Index != nil {
		index := *state.Index
		state.Index = &index
	}
	if state.WitnessVersion != nil {
		version := *state.WitnessVersion
		state.WitnessVersion = &version
	}
	if state.IsSecretScript != nil {
		secret := *state.IsSecretScript
		state.IsSecretScript = &secret
	}

	return state
}

// readStoreAddressSnapshot copies durable account and address rows without
// decrypting, deriving, validating, or publishing any manager state.
func readStoreAddressSnapshot(
	store walletstore.AddrReadStore) (storeAddressSnapshot, error) {

	snapshot := storeAddressSnapshot{
		accounts: make(map[storeAccountKey]waddrmgr.AccountState),
		addresses: make(
			map[[sha256.Size]byte][]waddrmgr.AddressState,
		),
	}
	scopes, err := store.KeyScopes()
	if err != nil {
		return storeAddressSnapshot{}, err
	}
	for _, scope := range scopes {
		accounts, err := store.Accounts(scope.Scope)
		if err != nil {
			return storeAddressSnapshot{}, err
		}
		for _, account := range accounts {
			account = copyStoreAccountState(account)
			key := storeAccountKey{
				scope:   account.Scope,
				account: account.Account,
			}
			snapshot.accounts[key] = account
		}

		addresses, err := store.ActiveAddresses(scope.Scope)
		if err != nil {
			return storeAddressSnapshot{}, err
		}
		for _, state := range addresses {
			state = copyStoreAddressState(state)
			if len(state.Hash) != sha256.Size {
				return storeAddressSnapshot{}, fmt.Errorf(
					"stored address hash has length %d", len(state.Hash),
				)
			}

			var hash [sha256.Size]byte
			copy(hash[:], state.Hash)
			snapshot.addresses[hash] = append(
				snapshot.addresses[hash], state,
			)
		}
	}

	return snapshot, nil
}

// normalizedStoreAddress converts a public-key address to the public-key-hash
// identity used by durable manager rows.
func normalizedStoreAddress(addr address.Address) address.Address {
	if pubKeyAddr, ok := addr.(*address.AddressPubKey); ok {
		return pubKeyAddr.AddressPubKeyHash()
	}

	return addr
}

// material returns detached durable material for an address, optionally
// restricted to an exact key scope and account.
func (s storeAddressSnapshot) material(addr address.Address,
	scope *waddrmgr.KeyScope, account *uint32) (storeAddressMaterial, bool) {

	addr = normalizedStoreAddress(addr)
	hash := sha256.Sum256(addr.ScriptAddress())
	for _, state := range s.addresses[hash] {
		if scope != nil && state.Scope != *scope {
			continue
		}
		if account != nil && state.Account != *account {
			continue
		}

		accountState, ok := s.accounts[storeAccountKey{
			scope:   state.Scope,
			account: state.Account,
		}]
		if !ok {
			continue
		}

		return storeAddressMaterial{
			account: accountState,
			address: state,
		}, true
	}

	return storeAddressMaterial{}, false
}

// resolve reconstructs one managed address from detached durable state.
func (s storeAddressSnapshot) resolve(w *Wallet,
	addr address.Address) (waddrmgr.ManagedAddress, error) {

	material, ok := s.material(addr, nil, nil)
	if !ok {
		return nil, fmt.Errorf("unable to find key for addr %v", addr)
	}

	observeStoreTxStage(storeTxStageCrypto)
	return w.Manager.AddressFromStoreStates(
		material.account, material.address,
	)
}

// detachedStoreSecretSource resolves already-snapshotted wallet secrets while
// no Store transaction is active.
type detachedStoreSecretSource struct {
	wallet   *Wallet
	snapshot storeAddressSnapshot
	managed  map[[sha256.Size]byte]waddrmgr.ManagedAddress
}

// ChainParams returns the network used to decode signing addresses.
func (s *detachedStoreSecretSource) ChainParams() *chaincfg.Params {
	return s.wallet.ChainParams()
}

// managedAddress resolves and caches one detached managed address.
func (s *detachedStoreSecretSource) managedAddress(
	addr address.Address) (waddrmgr.ManagedAddress, error) {

	addr = normalizedStoreAddress(addr)
	hash := sha256.Sum256(addr.ScriptAddress())
	if managed := s.managed[hash]; managed != nil {
		return managed, nil
	}

	managed, err := s.snapshot.resolve(s.wallet, addr)
	if err != nil {
		return nil, err
	}
	s.managed[hash] = managed

	return managed, nil
}

// GetKey returns a private key reconstructed from detached durable state.
func (s *detachedStoreSecretSource) GetKey(
	addr address.Address) (*btcec.PrivateKey, bool, error) {

	managed, err := s.managedAddress(addr)
	if err != nil {
		return nil, false, err
	}
	pubKeyAddr, ok := managed.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, false, fmt.Errorf("address %v is not a pubkey address",
			managed.Address().EncodeAddress())
	}

	observeStoreTxStage(storeTxStageCrypto)
	key, err := pubKeyAddr.PrivKey()
	if err != nil {
		return nil, false, err
	}

	return key, pubKeyAddr.Compressed(), nil
}

// GetScript returns a script decrypted from detached durable state.
func (s *detachedStoreSecretSource) GetScript(
	addr address.Address) ([]byte, error) {

	managed, err := s.managedAddress(addr)
	if err != nil {
		return nil, err
	}
	scriptAddr, ok := managed.(waddrmgr.ManagedScriptAddress)
	if !ok {
		return nil, errors.New("address is not a script address")
	}

	observeStoreTxStage(storeTxStageCrypto)
	return scriptAddr.Script()
}

// scriptForStoreOutput returns signing metadata for a managed pubkey address
// reconstructed from detached durable state.
func scriptForStoreOutput(output *wire.TxOut,
	managed waddrmgr.ManagedAddress,
	params *chaincfg.Params) (waddrmgr.ManagedPubKeyAddress, []byte, []byte,
	error) {

	pubKeyAddr, ok := managed.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return nil, nil, nil, fmt.Errorf("address %s is not a pubkey "+
			"address", managed.Address())
	}

	var (
		witnessProgram []byte
		sigScript      []byte
	)
	if managed.AddrType() == waddrmgr.NestedWitnessPubKey {
		pubKeyHash := address.Hash160(
			pubKeyAddr.PubKey().SerializeCompressed(),
		)
		witnessAddr, err := address.NewAddressWitnessPubKeyHash(
			pubKeyHash, params,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		witnessProgram, err = txscript.PayToAddrScript(witnessAddr)
		if err != nil {
			return nil, nil, nil, err
		}
		sigScript, err = txscript.NewScriptBuilder().AddData(
			witnessProgram,
		).Script()
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		witnessProgram = append([]byte(nil), output.PkScript...)
	}

	return pubKeyAddr, witnessProgram, sigScript, nil
}

// signTransactionFromStore snapshots previous scripts and address rows, signs
// and validates a transaction copy outside the Store view, then publishes only
// completed input scripts to the caller transaction.
func (w *Wallet) signTransactionFromStore(tx *wire.MsgTx,
	hashType txscript.SigHashType,
	additionalPrevScripts map[wire.OutPoint][]byte,
	additionalKeysByAddress map[string]*btcutil.WIF,
	p2shRedeemScriptsByAddress map[string][]byte) ([]SignatureError, error) {

	workingTx := tx.Copy()
	var (
		prevScripts [][]byte
		addresses   storeAddressSnapshot
	)
	err := w.store.View(
		context.Background(), func(dbtx walletstore.ReadTx) error {
			prevScripts = make([][]byte, len(workingTx.TxIn))
			for i, txIn := range workingTx.TxIn {
				prevOutScript, ok := additionalPrevScripts[txIn.PreviousOutPoint]
				if !ok {
					prevHash := &txIn.PreviousOutPoint.Hash
					details, err := dbtx.Tx().TxDetails(prevHash)
					if err != nil {
						return fmt.Errorf("cannot query previous "+
							"transaction details for %v: %w",
							txIn.PreviousOutPoint, err)
					}
					if details == nil {
						return fmt.Errorf("%v not found",
							txIn.PreviousOutPoint)
					}
					prevIndex := txIn.PreviousOutPoint.Index
					if prevIndex >= uint32(len(details.MsgTx.TxOut)) {
						return fmt.Errorf("previous output %v is out of range",
							txIn.PreviousOutPoint)
					}
					prevOutScript = details.MsgTx.TxOut[prevIndex].PkScript
				}

				prevScripts[i] = append([]byte(nil), prevOutScript...)
			}

			var err error
			addresses, err = readStoreAddressSnapshot(dbtx.Addr())

			return err
		}, func() {
			prevScripts = nil
			addresses = storeAddressSnapshot{}
		},
	)
	if err != nil {
		return nil, err
	}

	secrets := &detachedStoreSecretSource{
		wallet:   w,
		snapshot: addresses,
		managed: make(
			map[[sha256.Size]byte]waddrmgr.ManagedAddress,
		),
	}
	inputFetcher := txscript.NewMultiPrevOutFetcher(nil)
	for i, txIn := range workingTx.TxIn {
		inputFetcher.AddPrevOut(txIn.PreviousOutPoint, &wire.TxOut{
			PkScript: prevScripts[i],
		})
	}

	var signErrors []SignatureError
	for i, txIn := range workingTx.TxIn {
		getKey := txscript.KeyClosure(func(
			addr address.Address) (*btcec.PrivateKey, bool, error) {

			if len(additionalKeysByAddress) != 0 {
				wif, ok := additionalKeysByAddress[addr.EncodeAddress()]
				if !ok {
					return nil, false, errors.New("no key for address")
				}

				return wif.PrivKey, wif.CompressPubKey, nil
			}

			return secrets.GetKey(addr)
		})
		getScript := txscript.ScriptClosure(func(
			addr address.Address) ([]byte, error) {

			if len(additionalKeysByAddress) != 0 {
				script, ok := p2shRedeemScriptsByAddress[addr.EncodeAddress()]
				if !ok {
					return nil, errors.New("no script for address")
				}

				return script, nil
			}

			return secrets.GetScript(addr)
		})

		if (hashType&txscript.SigHashSingle) != txscript.SigHashSingle ||
			i < len(workingTx.TxOut) {

			observeStoreTxStage(storeTxStageSigning)
			script, err := txscript.SignTxOutput(
				w.ChainParams(), workingTx, i, prevScripts[i], hashType,
				getKey, getScript, txIn.SignatureScript,
			)
			if err != nil {
				signErrors = append(signErrors, SignatureError{
					InputIndex: uint32(i),
					Error:      err,
				})
				continue
			}
			txIn.SignatureScript = script
		}

		observeStoreTxStage(storeTxStageVM)
		vm, err := txscript.NewEngine(
			prevScripts[i], workingTx, i, txscript.StandardVerifyFlags,
			nil, nil, 0, inputFetcher,
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

	for i := range tx.TxIn {
		tx.TxIn[i].SignatureScript = append(
			tx.TxIn[i].SignatureScript[:0],
			workingTx.TxIn[i].SignatureScript...,
		)
		tx.TxIn[i].Witness = append(
			wire.TxWitness(nil), workingTx.TxIn[i].Witness...,
		)
	}

	return signErrors, nil
}
