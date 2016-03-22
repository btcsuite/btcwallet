// Copyright (c) 2014 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package votingpool

import (
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil/hdkeychain"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/walletdb"
)

var TstLastErr = lastErr

const TstEligibleInputMinConfirmations = eligibleInputMinConfirmations

// TstPutSeries transparently wraps the voting pool putSeries method.
func (vp *Pool) TstPutSeries(version, seriesID, reqSigs uint32, inRawPubKeys []string) error {
	return vp.putSeries(version, seriesID, reqSigs, inRawPubKeys)
}

var TstBranchOrder = branchOrder

// TstExistsSeries checks whether a series is stored in the database.
func (vp *Pool) TstExistsSeries(seriesID uint32) (bool, error) {
	var exists bool
	err := vp.namespace.View(
		func(tx walletdb.Tx) error {
			poolBucket := tx.RootBucket().Bucket(vp.ID)
			if poolBucket == nil {
				return nil
			}
			bucket := poolBucket.Bucket(seriesBucketName)
			if bucket == nil {
				return nil
			}
			exists = bucket.Get(uint32ToBytes(seriesID)) != nil
			return nil
		})
	if err != nil {
		return false, err
	}
	return exists, nil
}

// TstNamespace exposes the Pool's namespace as it's needed in some tests.
func (vp *Pool) TstNamespace() walletdb.Namespace {
	return vp.namespace
}

// TstGetRawPublicKeys gets a series public keys in string format.
func (s *SeriesData) TstGetRawPublicKeys() []string {
	rawKeys := make([]string, len(s.publicKeys))
	for i, key := range s.publicKeys {
		keyString, err := key.String()
		if err != nil {
			return nil
		}
		rawKeys[i] = keyString
	}
	return rawKeys
}

// TstGetRawPrivateKeys gets a series private keys in string format.
func (s *SeriesData) TstGetRawPrivateKeys() []string {
	rawKeys := make([]string, len(s.privateKeys))
	for i, key := range s.privateKeys {
		if key != nil {
			keyString, err := key.String()
			if err != nil {
				return nil
			}
			rawKeys[i] = keyString
		}
	}
	return rawKeys
}

// TstGetReqSigs expose the series reqSigs attribute.
func (s *SeriesData) TstGetReqSigs() uint32 {
	return s.reqSigs
}

// TstEmptySeriesLookup empties the voting pool seriesLookup attribute.
func (vp *Pool) TstEmptySeriesLookup() {
	vp.seriesLookup = make(map[uint32]*SeriesData)
}

// TstDecryptExtendedKey expose the decryptExtendedKey method.
func (vp *Pool) TstDecryptExtendedKey(keyType waddrmgr.CryptoKeyType, encrypted []byte) (*hdkeychain.ExtendedKey, error) {
	return vp.decryptExtendedKey(keyType, encrypted)
}

// TstGetMsgTx returns a copy of the withdrawal transaction with the given
// ntxid.
func (s *WithdrawalStatus) TstGetMsgTx(ntxid Ntxid) *wire.MsgTx {
	return s.transactions[ntxid].MsgTx.Copy()
}
