// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package votingpool

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

var TstLastErr = lastErr

const TstEligibleInputMinConfirmations = eligibleInputMinConfirmations

// TstPutSeries transparently wraps the voting pool putSeries method.
func (vp *Pool) TstPutSeries(ns walletdb.ReadWriteBucket, version, seriesID, reqSigs uint32, inRawPubKeys []string) error {
	return vp.putSeries(ns, version, seriesID, reqSigs, inRawPubKeys)
}

var TstBranchOrder = branchOrder

// TstExistsSeries checks whether a series is stored in the database.
func (vp *Pool) TstExistsSeries(dbtx walletdb.ReadTx, seriesID uint32) (bool, error) {
	ns, _ := TstRNamespaces(dbtx)
	poolBucket := ns.NestedReadBucket(vp.ID)
	if poolBucket == nil {
		return false, nil
	}
	bucket := poolBucket.NestedReadBucket(seriesBucketName)
	if bucket == nil {
		return false, nil
	}
	return bucket.Get(uint32ToBytes(seriesID)) != nil, nil
}

// TstGetRawPublicKeys gets a series public keys in string format.
func (s *SeriesData) TstGetRawPublicKeys() []string {
	rawKeys := make([]string, len(s.publicKeys))
	for i, key := range s.publicKeys {
		rawKeys[i] = key.String()
	}
	return rawKeys
}

// TstGetRawPrivateKeys gets a series private keys in string format.
func (s *SeriesData) TstGetRawPrivateKeys() []string {
	rawKeys := make([]string, len(s.privateKeys))
	for i, key := range s.privateKeys {
		if key != nil {
			rawKeys[i] = key.String()
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
