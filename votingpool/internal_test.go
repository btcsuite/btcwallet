/*
 * Copyright (c) 2014 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package votingpool

import (
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/conformal/btcwallet/waddrmgr"
	"github.com/conformal/btcwallet/walletdb"
)

// TstPutSeries transparently wraps the voting pool putSeries method.
func (vp *Pool) TstPutSeries(version, seriesID, reqSigs uint32, inRawPubKeys []string) error {
	return vp.putSeries(version, seriesID, reqSigs, inRawPubKeys)
}

var TstBranchOrder = branchOrder

// TstExistsSeries checks whether a series is stored in the database.
func (vp *Pool) TstExistsSeries(seriesID uint32) (bool, error) {
	return vp.existsSeries(seriesID)
}

// TstNamespace exposes the Pool's namespace as it's needed in some tests.
func (vp *Pool) TstNamespace() walletdb.Namespace {
	return vp.namespace
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

// SeriesRow mimics dbSeriesRow defined in db.go .
type SeriesRow struct {
	Version           uint32
	Active            bool
	ReqSigs           uint32
	PubKeysEncrypted  [][]byte
	PrivKeysEncrypted [][]byte
}

// SerializeSeries wraps serializeSeriesRow by passing it a freshly-built
// dbSeriesRow.
func SerializeSeries(version uint32, active bool, reqSigs uint32, pubKeys, privKeys [][]byte) ([]byte, error) {
	row := &dbSeriesRow{
		version:           version,
		active:            active,
		reqSigs:           reqSigs,
		pubKeysEncrypted:  pubKeys,
		privKeysEncrypted: privKeys,
	}
	return serializeSeriesRow(row)
}

// DeserializeSeries wraps deserializeSeriesRow and returns a freshly-built
// SeriesRow.
func DeserializeSeries(serializedSeries []byte) (*SeriesRow, error) {
	row, err := deserializeSeriesRow(serializedSeries)

	if err != nil {
		return nil, err
	}

	return &SeriesRow{
		Version:           row.version,
		Active:            row.active,
		ReqSigs:           row.reqSigs,
		PubKeysEncrypted:  row.pubKeysEncrypted,
		PrivKeysEncrypted: row.privKeysEncrypted,
	}, nil
}

var TstValidateAndDecryptKeys = validateAndDecryptKeys
