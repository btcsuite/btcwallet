// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
)

// deriveAddressFromPubKey computes the address for a derived or imported public
// key of the given address type. It is the single address-computation switch
// shared by the in-memory managed-address construction
// (newManagedAddressWithoutPrivKey) and the runtime derivation preparation
// (DeriveChainedAddresses), so both produce byte-identical legacy address
// identities. An unsupported address type yields a nil address, which the
// managed-address caller preserves and the runtime preparation rejects.
//
//nolint:cyclop,exhaustive // Mirrors the manager's per-type address switch.
func deriveAddressFromPubKey(pubKey *btcec.PublicKey, compressed bool,
	addrType AddressType, params *chaincfg.Params) (address.Address, error) {

	// Create a pay-to-pubkey-hash address from the public key.
	var pubKeyHash []byte
	if compressed {
		pubKeyHash = address.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = address.Hash160(pubKey.SerializeUncompressed())
	}

	var (
		newAddress address.Address
		err        error
	)

	switch addrType {
	case NestedWitnessPubKey:
		// For this address type we'll generate an address which is
		// backwards compatible to Bitcoin nodes running 0.6.0 onwards,
		// but allows us to take advantage of segwit's scripting
		// improvements, and malleability fixes.

		// First, we'll generate a normal p2wkh address from the pubkey
		// hash.
		witAddr, err := address.NewAddressWitnessPubKeyHash(
			pubKeyHash, params,
		)
		if err != nil {
			return nil, err
		}

		// Next we'll generate the witness program which can be used as a
		// pkScript to pay to this generated address.
		witnessProgram, err := txscript.PayToAddrScript(witAddr)
		if err != nil {
			return nil, err
		}

		// Finally, we'll use the witness program itself as the pre-image
		// to a p2sh address. In order to spend, we first use the
		// witnessProgram as the sigScript, then present the proper
		// <sig, pubkey> pair as the witness.
		newAddress, err = address.NewAddressScriptHash(
			witnessProgram, params,
		)
		if err != nil {
			return nil, err
		}

	case PubKeyHash:
		newAddress, err = address.NewAddressPubKeyHash(pubKeyHash, params)
		if err != nil {
			return nil, err
		}

	case WitnessPubKey:
		newAddress, err = address.NewAddressWitnessPubKeyHash(
			pubKeyHash, params,
		)
		if err != nil {
			return nil, err
		}

	case TaprootPubKey:
		tapKey := txscript.ComputeTaprootKeyNoScript(pubKey)

		newAddress, err = address.NewAddressTaproot(
			schnorr.SerializePubKey(tapKey), params,
		)
		if err != nil {
			return nil, err
		}
	}

	return newAddress, nil
}

// DerivedAddress is a prepared chained address: its legacy script-address
// identity and the derivation path it was produced at. It carries no key
// material because a derived chained address persists none; its keys are
// re-derived on demand from the account key, so the durable row is keyless.
type DerivedAddress struct {
	// AddressID is the legacy address identifier, the address's
	// ScriptAddress bytes. It is the durable identity the SQL backend hashes
	// and the KV backend stores directly.
	AddressID []byte

	// Address is the derived address itself, retained so a recovery scan can
	// build the chain watch-set (which matches by encoded address) without
	// recomputing the per-type address from the identity bytes. It shares the
	// exact address-computation source as AddressID, so the two never diverge.
	Address address.Address

	// Branch is the derivation branch the address belongs to.
	Branch uint32

	// Index is the child index the address was derived at. Indexes are not
	// necessarily contiguous, because an invalid child is skipped.
	Index uint32
}

// childDeriver derives the child extended key at index within a branch. It is
// the seam that lets tests inject hdkeychain.ErrInvalidChild at a chosen index
// while the production caller derives with the real branch key.
type childDeriver func(index uint32) (*hdkeychain.ExtendedKey, error)

// DeriveChainedAddresses derives count valid chained addresses on branch,
// starting at startIndex, from the account's extended key. It mirrors the
// address manager's own derivation: it skips an index whose child key is
// invalid (hdkeychain.ErrInvalidChild), so the consumed index range can exceed
// count. It returns the derived addresses and the next index past the consumed
// range, which the caller advances the branch to with a compare-and-swap.
//
// Only the public key of each child is used, so it works for a watch-only or
// locked account. This is the derivation-preparation half of address
// allocation, run outside any write transaction; the atomic insert and index
// advance are a separate runtime commit.
func DeriveChainedAddresses(acctKey *hdkeychain.ExtendedKey, branch uint32,
	addrType AddressType, params *chaincfg.Params, startIndex,
	count uint32) ([]DerivedAddress, uint32, error) {

	branchKey, err := acctKey.DeriveNonStandard(branch) //nolint:staticcheck
	if err != nil {
		return nil, 0, managerError(ErrKeyChain, fmt.Sprintf(
			"failed to derive extended key branch %d", branch), err)
	}
	defer branchKey.Zero()

	return deriveChainedAddresses(
		func(index uint32) (*hdkeychain.ExtendedKey, error) {
			//nolint:staticcheck
			return branchKey.DeriveNonStandard(index)
		}, branch, addrType, params, startIndex, count,
	)
}

// deriveChainedAddresses is the derivation loop shared by DeriveChainedAddresses
// and its tests. deriveChild is the child-key seam; tests substitute it to
// inject an invalid child deterministically. It faithfully reproduces the
// address manager's nextAddresses accounting: every invalid child advances the
// consumed range without producing an address, so the returned next index is
// exactly one past the last consumed child.
func deriveChainedAddresses(deriveChild childDeriver, branch uint32,
	addrType AddressType, params *chaincfg.Params, startIndex,
	count uint32) ([]DerivedAddress, uint32, error) {

	// Guard the consumed range against the per-account maximum, matching the
	// address manager's own bound.
	if count > MaxAddressesPerAccount ||
		startIndex+count > MaxAddressesPerAccount {

		return nil, 0, managerError(ErrTooManyAddresses, fmt.Sprintf(
			"%d new addresses would exceed the maximum allowed "+
				"number of addresses per account of %d", count,
			MaxAddressesPerAccount), nil)
	}

	addrs := make([]DerivedAddress, 0, count)

	nextIndex := startIndex
	for derived := uint32(0); derived < count; derived++ {
		// There is an extremely small chance that a particular child is
		// invalid, so loop to derive the next valid child, skipping the
		// invalid index exactly as the address manager does.
		var childKey *hdkeychain.ExtendedKey
		for {
			key, err := deriveChild(nextIndex)
			if errors.Is(err, hdkeychain.ErrInvalidChild) {
				nextIndex++

				continue
			}

			if err != nil {
				return nil, 0, managerError(ErrKeyChain,
					fmt.Sprintf("failed to generate child %d",
						nextIndex), err)
			}

			key.SetNet(params)
			childKey = key

			break
		}

		pubKey, err := childKey.ECPubKey()
		childKey.Zero()

		if err != nil {
			return nil, 0, managerError(ErrKeyChain,
				"failed to derive child public key", err)
		}

		addr, err := deriveAddressFromPubKey(pubKey, true, addrType, params)
		if err != nil {
			return nil, 0, err
		}

		if addr == nil {
			return nil, 0, managerError(ErrKeyChain, fmt.Sprintf(
				"unsupported derived address type %d", addrType),
				nil)
		}

		addrs = append(addrs, DerivedAddress{
			AddressID: addr.ScriptAddress(),
			Address:   addr,
			Branch:    branch,
			Index:     nextIndex,
		})
		nextIndex++
	}

	return addrs, nextIndex, nil
}
