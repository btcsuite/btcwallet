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
	"fmt"
	"sort"

	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcwallet/waddrmgr"
	"github.com/conformal/btcwallet/walletdb"
)

const (
	minSeriesPubKeys = 3
)

// SeriesData represents a Series for a given Pool.
type SeriesData struct {
	version uint32
	// Whether or not a series is active. This is serialized/deserialized but
	// for now there's no way to deactivate a series.
	active bool
	// A.k.a. "m" in "m of n signatures needed".
	reqSigs     uint32
	publicKeys  []*hdkeychain.ExtendedKey
	privateKeys []*hdkeychain.ExtendedKey
}

// Pool represents an arrangement of notary servers to securely
// store and account for customer cryptocurrency deposits and to redeem
// valid withdrawals. For details about how the arrangement works, see
// http://opentransactions.org/wiki/index.php?title=Category:Voting_Pools
type Pool struct {
	ID           []byte
	seriesLookup map[uint32]*SeriesData
	manager      *waddrmgr.Manager
	namespace    walletdb.Namespace
}

// Create creates a new entry in the database with the given ID
// and returns the Pool representing it.
func Create(namespace walletdb.Namespace, m *waddrmgr.Manager, poolID []byte) (*Pool, error) {
	err := namespace.Update(
		func(tx walletdb.Tx) error {
			return putPool(tx, poolID)
		})
	if err != nil {
		str := fmt.Sprintf("unable to add voting pool %v to db", poolID)
		return nil, managerError(waddrmgr.ErrVotingPoolAlreadyExists, str, err)
	}
	return newPool(namespace, m, poolID), nil
}

// Load fetches the entry in the database with the given ID and returns the Pool
// representing it.
func Load(namespace walletdb.Namespace, m *waddrmgr.Manager, poolID []byte) (*Pool, error) {
	err := namespace.View(
		func(tx walletdb.Tx) error {
			if exists := existsPool(tx, poolID); !exists {
				str := fmt.Sprintf("unable to find voting pool %v in db", poolID)
				return managerError(waddrmgr.ErrVotingPoolNotExists, str, nil)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	vp := newPool(namespace, m, poolID)
	if err = vp.LoadAllSeries(); err != nil {
		return nil, err
	}
	return vp, nil
}

// newPool creates a new Pool instance.
func newPool(namespace walletdb.Namespace, m *waddrmgr.Manager, poolID []byte) *Pool {
	return &Pool{
		ID:           poolID,
		seriesLookup: make(map[uint32]*SeriesData),
		manager:      m,
		namespace:    namespace,
	}
}

// LoadAndGetDepositScript generates and returns a deposit script for the given seriesID,
// branch and index of the Pool identified by poolID.
func LoadAndGetDepositScript(namespace walletdb.Namespace, m *waddrmgr.Manager, poolID string, seriesID, branch, index uint32) ([]byte, error) {
	pid := []byte(poolID)
	vp, err := Load(namespace, m, pid)
	if err != nil {
		return nil, err
	}
	script, err := vp.DepositScript(seriesID, branch, index)
	if err != nil {
		return nil, err
	}
	return script, nil
}

// LoadAndCreateSeries loads the Pool with the given ID, creating a new one if it doesn't
// yet exist, and then creates and returns a Series with the given seriesID, rawPubKeys
// and reqSigs. See CreateSeries for the constraints enforced on rawPubKeys and reqSigs.
func LoadAndCreateSeries(namespace walletdb.Namespace, m *waddrmgr.Manager, version uint32,
	poolID string, seriesID, reqSigs uint32, rawPubKeys []string) error {
	pid := []byte(poolID)
	vp, err := Load(namespace, m, pid)
	if err != nil {
		managerErr := err.(waddrmgr.ManagerError)
		if managerErr.ErrorCode == waddrmgr.ErrVotingPoolNotExists {
			vp, err = Create(namespace, m, pid)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return vp.CreateSeries(version, seriesID, reqSigs, rawPubKeys)
}

// LoadAndReplaceSeries loads the voting pool with the given ID and calls ReplaceSeries,
// passing the given series ID, public keys and reqSigs to it.
func LoadAndReplaceSeries(namespace walletdb.Namespace, m *waddrmgr.Manager, version uint32,
	poolID string, seriesID, reqSigs uint32, rawPubKeys []string) error {
	pid := []byte(poolID)
	vp, err := Load(namespace, m, pid)
	if err != nil {
		return err
	}
	return vp.ReplaceSeries(version, seriesID, reqSigs, rawPubKeys)
}

// LoadAndEmpowerSeries loads the voting pool with the given ID and calls EmpowerSeries,
// passing the given series ID and private key to it.
func LoadAndEmpowerSeries(namespace walletdb.Namespace, m *waddrmgr.Manager,
	poolID string, seriesID uint32, rawPrivKey string) error {
	pid := []byte(poolID)
	pool, err := Load(namespace, m, pid)
	if err != nil {
		return err
	}
	return pool.EmpowerSeries(seriesID, rawPrivKey)
}

// GetSeries returns the series with the given ID, or nil if it doesn't
// exist.
func (vp *Pool) GetSeries(seriesID uint32) *SeriesData {
	series, exists := vp.seriesLookup[seriesID]
	if !exists {
		return nil
	}
	return series
}

// saveSeriesToDisk stores the given series ID and data in the database,
// first encrypting the public/private extended keys.
func (vp *Pool) saveSeriesToDisk(seriesID uint32, data *SeriesData) error {
	var err error
	encryptedPubKeys := make([][]byte, len(data.publicKeys))
	for i, pubKey := range data.publicKeys {
		encryptedPubKeys[i], err = vp.manager.Encrypt(
			waddrmgr.CKTPublic, []byte(pubKey.String()))
		if err != nil {
			str := fmt.Sprintf("key %v failed encryption", pubKey)
			return managerError(waddrmgr.ErrCrypto, str, err)
		}
	}
	encryptedPrivKeys := make([][]byte, len(data.privateKeys))
	for i, privKey := range data.privateKeys {
		if privKey == nil {
			encryptedPrivKeys[i] = nil
		} else {
			encryptedPrivKeys[i], err = vp.manager.Encrypt(
				waddrmgr.CKTPrivate, []byte(privKey.String()))
		}
		if err != nil {
			str := fmt.Sprintf("key %v failed encryption", privKey)
			return managerError(waddrmgr.ErrCrypto, str, err)
		}
	}

	err = vp.namespace.Update(func(tx walletdb.Tx) error {
		return putSeries(tx, vp.ID, data.version, seriesID, data.active,
			data.reqSigs, encryptedPubKeys, encryptedPrivKeys)
	})
	if err != nil {
		str := fmt.Sprintf("cannot put series #%d into db", seriesID)
		return managerError(waddrmgr.ErrSeriesStorage, str, err)
	}
	return nil
}

// CanonicalKeyOrder will return a copy of the input canonically
// ordered which is defined to be lexicographical.
func CanonicalKeyOrder(keys []string) []string {
	orderedKeys := make([]string, len(keys))
	copy(orderedKeys, keys)
	sort.Sort(sort.StringSlice(orderedKeys))
	return orderedKeys
}

// Convert the given slice of strings into a slice of ExtendedKeys,
// checking that all of them are valid public (and not private) keys,
// and that there are no duplicates.
func convertAndValidatePubKeys(rawPubKeys []string) ([]*hdkeychain.ExtendedKey, error) {
	seenKeys := make(map[string]bool)
	keys := make([]*hdkeychain.ExtendedKey, len(rawPubKeys))
	for i, rawPubKey := range rawPubKeys {
		if _, seen := seenKeys[rawPubKey]; seen {
			str := fmt.Sprintf("duplicated public key: %v", rawPubKey)
			return nil, managerError(waddrmgr.ErrKeyDuplicate, str, nil)
		}
		seenKeys[rawPubKey] = true

		key, err := hdkeychain.NewKeyFromString(rawPubKey)
		if err != nil {
			str := fmt.Sprintf("invalid extended public key %v", rawPubKey)
			return nil, managerError(waddrmgr.ErrKeyChain, str, err)
		}

		if key.IsPrivate() {
			str := fmt.Sprintf("private keys not accepted: %v", rawPubKey)
			return nil, managerError(waddrmgr.ErrKeyIsPrivate, str, nil)
		}
		keys[i] = key
	}
	return keys, nil
}

// putSeries creates a new seriesData with the given arguments, ordering the
// given public keys (using CanonicalKeyOrder), validating and converting them
// to hdkeychain.ExtendedKeys, saves that to disk and adds it to this voting
// pool's seriesLookup map. It also ensures inRawPubKeys has at least
// minSeriesPubKeys items and reqSigs is not greater than the number of items in
// inRawPubKeys.
func (vp *Pool) putSeries(version, seriesID, reqSigs uint32, inRawPubKeys []string) error {
	if len(inRawPubKeys) < minSeriesPubKeys {
		str := fmt.Sprintf("need at least %d public keys to create a series", minSeriesPubKeys)
		return managerError(waddrmgr.ErrTooFewPublicKeys, str, nil)
	}

	if reqSigs > uint32(len(inRawPubKeys)) {
		str := fmt.Sprintf(
			"the number of required signatures cannot be more than the number of keys")
		return managerError(waddrmgr.ErrTooManyReqSignatures, str, nil)
	}

	rawPubKeys := CanonicalKeyOrder(inRawPubKeys)

	keys, err := convertAndValidatePubKeys(rawPubKeys)
	if err != nil {
		return err
	}

	data := &SeriesData{
		version:     version,
		active:      false,
		reqSigs:     reqSigs,
		publicKeys:  keys,
		privateKeys: make([]*hdkeychain.ExtendedKey, len(keys)),
	}

	err = vp.saveSeriesToDisk(seriesID, data)
	if err != nil {
		return err
	}
	vp.seriesLookup[seriesID] = data
	return nil
}

// CreateSeries will create and return a new non-existing series.
//
// - rawPubKeys has to contain three or more public keys;
// - reqSigs has to be less or equal than the number of public keys in rawPubKeys.
func (vp *Pool) CreateSeries(version, seriesID, reqSigs uint32, rawPubKeys []string) error {
	if series := vp.GetSeries(seriesID); series != nil {
		str := fmt.Sprintf("series #%d already exists", seriesID)
		return managerError(waddrmgr.ErrSeriesAlreadyExists, str, nil)
	}

	return vp.putSeries(version, seriesID, reqSigs, rawPubKeys)
}

// ReplaceSeries will replace an already existing series.
//
// - rawPubKeys has to contain three or more public keys
// - reqSigs has to be less or equal than the number of public keys in rawPubKeys.
func (vp *Pool) ReplaceSeries(version, seriesID, reqSigs uint32, rawPubKeys []string) error {
	series := vp.GetSeries(seriesID)
	if series == nil {
		str := fmt.Sprintf("series #%d does not exist, cannot replace it", seriesID)
		return managerError(waddrmgr.ErrSeriesNotExists, str, nil)
	}

	if series.IsEmpowered() {
		str := fmt.Sprintf("series #%d has private keys and cannot be replaced", seriesID)
		return managerError(waddrmgr.ErrSeriesAlreadyEmpowered, str, nil)
	}

	return vp.putSeries(version, seriesID, reqSigs, rawPubKeys)
}

// decryptExtendedKey uses Manager.Decrypt() to decrypt the encrypted byte slice and return
// an extended (public or private) key representing it.
func (vp *Pool) decryptExtendedKey(keyType waddrmgr.CryptoKeyType, encrypted []byte) (*hdkeychain.ExtendedKey, error) {
	decrypted, err := vp.manager.Decrypt(keyType, encrypted)
	if err != nil {
		str := fmt.Sprintf("cannot decrypt key %v", encrypted)
		return nil, managerError(waddrmgr.ErrCrypto, str, err)
	}
	result, err := hdkeychain.NewKeyFromString(string(decrypted))
	zero(decrypted)
	if err != nil {
		str := fmt.Sprintf("cannot get key from string %v", decrypted)
		return nil, managerError(waddrmgr.ErrKeyChain, str, err)
	}
	return result, nil
}

// validateAndDecryptSeriesKeys checks that the length of the public and private key
// slices is the same, decrypts them, ensures the non-nil private keys have a matching
// public key and returns them.
func validateAndDecryptKeys(rawPubKeys, rawPrivKeys [][]byte, vp *Pool) (pubKeys, privKeys []*hdkeychain.ExtendedKey, err error) {
	pubKeys = make([]*hdkeychain.ExtendedKey, len(rawPubKeys))
	privKeys = make([]*hdkeychain.ExtendedKey, len(rawPrivKeys))
	if len(pubKeys) != len(privKeys) {
		return nil, nil, managerError(waddrmgr.ErrKeysPrivatePublicMismatch,
			"the pub key and priv key arrays should have the same number of elements",
			nil)
	}

	for i, encryptedPub := range rawPubKeys {
		pubKey, err := vp.decryptExtendedKey(waddrmgr.CKTPublic, encryptedPub)
		if err != nil {
			return nil, nil, err
		}
		pubKeys[i] = pubKey

		encryptedPriv := rawPrivKeys[i]
		var privKey *hdkeychain.ExtendedKey
		if encryptedPriv == nil {
			privKey = nil
		} else {
			privKey, err = vp.decryptExtendedKey(waddrmgr.CKTPrivate, encryptedPriv)
			if err != nil {
				return nil, nil, err
			}
		}
		privKeys[i] = privKey

		if privKey != nil {
			checkPubKey, err := privKey.Neuter()
			if err != nil {
				str := fmt.Sprintf("cannot neuter key %v", privKey)
				return nil, nil, managerError(waddrmgr.ErrKeyNeuter, str, err)
			}
			if pubKey.String() != checkPubKey.String() {
				str := fmt.Sprintf("public key %v different than expected %v",
					pubKey, checkPubKey)
				return nil, nil, managerError(waddrmgr.ErrKeyMismatch, str, nil)
			}
		}
	}
	return pubKeys, privKeys, nil
}

// LoadAllSeries fetches all series (decrypting their public and private
// extended keys) for this Pool from the database and populates the
// seriesLookup map with them. If there are any private extended keys for
// a series, it will also ensure they have a matching extended public key
// in that series.
func (vp *Pool) LoadAllSeries() error {
	var series map[uint32]*dbSeriesRow
	err := vp.namespace.View(func(tx walletdb.Tx) error {
		var err error
		series, err = loadAllSeries(tx, vp.ID)
		return err
	})
	if err != nil {
		return err
	}
	for id, series := range series {
		pubKeys, privKeys, err := validateAndDecryptKeys(
			series.pubKeysEncrypted, series.privKeysEncrypted, vp)
		if err != nil {
			return err
		}
		vp.seriesLookup[id] = &SeriesData{
			publicKeys:  pubKeys,
			privateKeys: privKeys,
			reqSigs:     series.reqSigs,
		}
	}
	return nil
}

// existsSeries checks whether a series is stored in the database.
// Used solely by the series creation test.
func (vp *Pool) existsSeries(seriesID uint32) (bool, error) {
	var exists bool
	err := vp.namespace.View(
		func(tx walletdb.Tx) error {
			bucket := tx.RootBucket().Bucket(vp.ID)
			if bucket == nil {
				exists = false
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

// Change the order of the pubkeys based on branch number.
// Given the three pubkeys ABC, this would mean:
// - branch 0: CBA (reversed)
// - branch 1: ABC (first key priority)
// - branch 2: BAC (second key priority)
// - branch 3: CAB (third key priority)
func branchOrder(pks []*hdkeychain.ExtendedKey, branch uint32) ([]*hdkeychain.ExtendedKey, error) {
	if pks == nil {
		// This really shouldn't happen, but we want to be good citizens, so we
		// return an error instead of crashing.
		return nil, managerError(waddrmgr.ErrInvalidValue, "pks cannot be nil", nil)
	}

	if branch > uint32(len(pks)) {
		return nil, managerError(waddrmgr.ErrInvalidBranch, "branch number is bigger than number of public keys", nil)
	}

	if branch == 0 {
		numKeys := len(pks)
		res := make([]*hdkeychain.ExtendedKey, numKeys)
		copy(res, pks)
		// reverse pk
		for i, j := 0, numKeys-1; i < j; i, j = i+1, j-1 {
			res[i], res[j] = res[j], res[i]
		}
		return res, nil
	}

	tmp := make([]*hdkeychain.ExtendedKey, len(pks))
	tmp[0] = pks[branch-1]
	j := 1
	for i := 0; i < len(pks); i++ {
		if i != int(branch-1) {
			tmp[j] = pks[i]
			j++
		}
	}
	return tmp, nil
}

// DepositScriptAddress constructs a multi-signature redemption script using DepositScript
// and returns the pay-to-script-hash-address for that script.
func (vp *Pool) DepositScriptAddress(seriesID, branch, index uint32) (btcutil.Address, error) {
	script, err := vp.DepositScript(seriesID, branch, index)
	if err != nil {
		return nil, err
	}
	scriptHash := btcutil.Hash160(script)

	return btcutil.NewAddressScriptHashFromHash(scriptHash, vp.manager.Net())
}

// DepositScript constructs and returns a multi-signature redemption script where
// a certain number (Series.reqSigs) of the public keys belonging to the series
// with the given ID are required to sign the transaction for it to be successful.
func (vp *Pool) DepositScript(seriesID, branch, index uint32) ([]byte, error) {
	series := vp.GetSeries(seriesID)
	if series == nil {
		str := fmt.Sprintf("series #%d does not exist", seriesID)
		return nil, managerError(waddrmgr.ErrSeriesNotExists, str, nil)
	}

	pubKeys, err := branchOrder(series.publicKeys, branch)
	if err != nil {
		return nil, err
	}

	pks := make([]*btcutil.AddressPubKey, len(pubKeys))
	for i, key := range pubKeys {
		child, err := key.Child(index)
		// TODO: implement getting the next index until we find a valid one,
		// in case there is a hdkeychain.ErrInvalidChild.
		if err != nil {
			str := fmt.Sprintf("child #%d for this pubkey %d does not exist", index, i)
			return nil, managerError(waddrmgr.ErrKeyChain, str, err)
		}
		pubkey, err := child.ECPubKey()
		if err != nil {
			str := fmt.Sprintf("child #%d for this pubkey %d does not exist", index, i)
			return nil, managerError(waddrmgr.ErrKeyChain, str, err)
		}
		pks[i], err = btcutil.NewAddressPubKey(pubkey.SerializeCompressed(), vp.manager.Net())
		if err != nil {
			str := fmt.Sprintf(
				"child #%d for this pubkey %d could not be converted to an address",
				index, i)
			return nil, managerError(waddrmgr.ErrKeyChain, str, err)
		}
	}

	script, err := btcscript.MultiSigScript(pks, int(series.reqSigs))
	if err != nil {
		str := fmt.Sprintf("error while making multisig script hash, %d", len(pks))
		return nil, managerError(waddrmgr.ErrScriptCreation, str, err)
	}

	return script, nil
}

// EmpowerSeries adds the given extended private key (in raw format) to the
// series with the given ID, thus allowing it to sign deposit/withdrawal
// scripts. The series with the given ID must exist, the key must be a valid
// private extended key and must match one of the series' extended public keys.
func (vp *Pool) EmpowerSeries(seriesID uint32, rawPrivKey string) error {
	// make sure this series exists
	series := vp.GetSeries(seriesID)
	if series == nil {
		str := fmt.Sprintf("series %d does not exist for this voting pool",
			seriesID)
		return managerError(waddrmgr.ErrSeriesNotExists, str, nil)
	}

	// Check that the private key is valid.
	privKey, err := hdkeychain.NewKeyFromString(rawPrivKey)
	if err != nil {
		str := fmt.Sprintf("invalid extended private key %v", rawPrivKey)
		return managerError(waddrmgr.ErrKeyChain, str, err)
	}
	if !privKey.IsPrivate() {
		str := fmt.Sprintf(
			"to empower a series you need the extended private key, not an extended public key %v",
			privKey)
		return managerError(waddrmgr.ErrKeyIsPublic, str, err)
	}

	pubKey, err := privKey.Neuter()
	if err != nil {
		str := fmt.Sprintf("invalid extended private key %v, can't convert to public key",
			rawPrivKey)
		return managerError(waddrmgr.ErrKeyNeuter, str, err)
	}

	lookingFor := pubKey.String()
	found := false

	// Make sure the private key has the corresponding public key in the series,
	// to be able to empower it.
	for i, publicKey := range series.publicKeys {
		if publicKey.String() == lookingFor {
			found = true
			series.privateKeys[i] = privKey
		}
	}

	if !found {
		str := fmt.Sprintf(
			"private Key does not have a corresponding public key in this series")
		return managerError(waddrmgr.ErrKeysPrivatePublicMismatch, str, nil)
	}

	err = vp.saveSeriesToDisk(seriesID, series)

	if err != nil {
		return err
	}

	return nil
}

// IsEmpowered returns true if this series is empowered (i.e. if it has
// at least one private key loaded).
func (s *SeriesData) IsEmpowered() bool {
	for _, key := range s.privateKeys {
		if key != nil {
			return true
		}
	}
	return false
}

// managerError creates a waddrmgr.ManagerError given a set of arguments.
// XXX(lars): We should probably make our own votingpoolError function.
func managerError(c waddrmgr.ErrorCode, desc string, err error) waddrmgr.ManagerError {
	return waddrmgr.ManagerError{ErrorCode: c, Description: desc, Err: err}
}

// zero sets all bytes in the passed slice to zero.  This is used to
// explicitly clear private key material from memory.
//
// XXX(lars) there exists currently around 4-5 other zero functions
// with at least 3 different implementations. We should try to
// consolidate these.
func zero(b []byte) {
	for i := range b {
		b[i] ^= b[i]
	}
}
