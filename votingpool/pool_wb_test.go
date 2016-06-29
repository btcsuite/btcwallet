// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package votingpool

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

func TestPoolEnsureUsedAddr(t *testing.T) {
	tearDown, mgr, pool := TstCreatePool(t)
	defer tearDown()

	var err error
	var script []byte
	var addr waddrmgr.ManagedScriptAddress
	TstCreateSeries(t, pool, []TstSeriesDef{{ReqSigs: 2, PubKeys: TstPubKeys[0:3], SeriesID: 1}})

	idx := Index(0)
	TstRunWithManagerUnlocked(t, mgr, func() {
		err = pool.EnsureUsedAddr(1, 0, idx)
	})
	if err != nil {
		t.Fatalf("Failed to ensure used addresses: %v", err)
	}
	addr, err = pool.getUsedAddr(1, 0, 0)
	if err != nil {
		t.Fatalf("Failed to get addr from used addresses set: %v", err)
	}
	TstRunWithManagerUnlocked(t, mgr, func() {
		script, err = addr.Script()
	})
	if err != nil {
		t.Fatalf("Failed to get script: %v", err)
	}
	wantScript, _ := pool.DepositScript(1, 0, 0)
	if !bytes.Equal(script, wantScript) {
		t.Fatalf("Script from looked up addr is not what we expect")
	}

	idx = Index(3)
	TstRunWithManagerUnlocked(t, mgr, func() {
		err = pool.EnsureUsedAddr(1, 0, idx)
	})
	if err != nil {
		t.Fatalf("Failed to ensure used addresses: %v", err)
	}
	for _, i := range []int{0, 1, 2, 3} {
		addr, err = pool.getUsedAddr(1, 0, Index(i))
		if err != nil {
			t.Fatalf("Failed to get addr from used addresses set: %v", err)
		}
		TstRunWithManagerUnlocked(t, mgr, func() {
			script, err = addr.Script()
		})
		if err != nil {
			t.Fatalf("Failed to get script: %v", err)
		}
		wantScript, _ := pool.DepositScript(1, 0, Index(i))
		if !bytes.Equal(script, wantScript) {
			t.Fatalf("Script from looked up addr is not what we expect")
		}
	}
}

func TestPoolGetUsedAddr(t *testing.T) {
	tearDown, mgr, pool := TstCreatePool(t)
	defer tearDown()

	TstCreateSeries(t, pool, []TstSeriesDef{{ReqSigs: 2, PubKeys: TstPubKeys[0:3], SeriesID: 1}})

	// Addr with series=1, branch=0, index=10 has never been used, so it should
	// return nil.
	addr, err := pool.getUsedAddr(1, 0, 10)
	if err != nil {
		t.Fatalf("Error when looking up used addr: %v", err)
	}
	if addr != nil {
		t.Fatalf("Unused address found in used addresses DB: %v", addr)
	}

	// Now we add that addr to the used addresses DB and check that the value
	// returned by getUsedAddr() is what we expect.
	TstRunWithManagerUnlocked(t, mgr, func() {
		err = pool.addUsedAddr(1, 0, 10)
	})
	if err != nil {
		t.Fatalf("Error when storing addr in used addresses DB: %v", err)
	}
	var script []byte
	addr, err = pool.getUsedAddr(1, 0, 10)
	if err != nil {
		t.Fatalf("Error when looking up used addr: %v", err)
	}
	TstRunWithManagerUnlocked(t, mgr, func() {
		script, err = addr.Script()
	})
	if err != nil {
		t.Fatalf("Failed to get script: %v", err)
	}
	wantScript, _ := pool.DepositScript(1, 0, 10)
	if !bytes.Equal(script, wantScript) {
		t.Fatalf("Script from looked up addr is not what we expect")
	}
}

func TestPoolUsedAddrs(t *testing.T) {
	tearDown, mgr, pool := TstCreatePool(t)
	defer tearDown()

	seriesID := uint32(1)
	pubKeys := 3
	TstCreateSeries(t, pool, []TstSeriesDef{
		{ReqSigs: 2, PubKeys: TstPubKeys[0:pubKeys], SeriesID: seriesID}})

	var addrs []*WithdrawalAddress
	var err error
	TstRunWithManagerUnlocked(t, mgr, func() {
		addrs, err = pool.usedAddrs(seriesID)
	})
	if err != nil {
		t.Fatal(err)
	}

	// Initially there should obviously be no used addresses for a series.
	if len(addrs) != 0 {
		t.Fatalf("Unexpected number of used addresses; got %d, want 0", len(addrs))
	}

	// This will add 3 entries (Index==[0..2]) to each of our 4 (pubKeys+1)
	// series/branch usedAddr bucket.
	idx := Index(2)
	TstRunWithManagerUnlocked(t, mgr, func() {
		for branch := 0; branch <= pubKeys; branch++ {
			err = pool.EnsureUsedAddr(seriesID, Branch(branch), idx)
			if err != nil {
				t.Fatal(err)
			}
		}
	})

	TstRunWithManagerUnlocked(t, mgr, func() {
		addrs, err = pool.usedAddrs(seriesID)
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedCount := (int(idx) + 1) * (pubKeys + 1)
	if len(addrs) != expectedCount {
		t.Fatalf("Unexpected number of used addresses; got %d, want %d", len(addrs), expectedCount)
	}
}

func TestPoolSeriesBalance(t *testing.T) {
	tearDown, pool, store := TstCreatePoolAndTxStore(t)
	defer tearDown()

	creditAmt := int64(2)
	pubKeys := TstPubKeys[0:3]
	seriesID := uint32(1)
	TstCreateSeries(t, pool, []TstSeriesDef{{ReqSigs: 2, PubKeys: pubKeys, SeriesID: seriesID}})
	expectedBalance := btcutil.Amount(0)
	// Start from branch==1 because otherwise we'd need to add extra logic to
	// skip the input on branch==0/index==0 as that's the charter contract.
	for branch := 1; branch <= 3; branch++ {
		for index := 0; index < 2; index++ {
			pkScript := TstCreatePkScript(t, pool, seriesID, Branch(branch), Index(index))
			for _, c := range TstCreateCreditsOnStore(t, store, pkScript, []int64{creditAmt}) {
				expectedBalance += c.Amount
			}
		}
	}
	// Require 0 confirmations so that all credits created above are included.
	minConf := 0
	dustThreshold := btcutil.Amount(0)

	var balance btcutil.Amount
	var err error
	TstRunWithManagerUnlocked(t, pool.manager, func() {
		balance, err = pool.seriesBalance(seriesID, dustThreshold, minConf, store)
	})
	if err != nil {
		t.Fatal(err)
	}

	if balance != expectedBalance {
		t.Fatalf("Unexpected series balance; got %v, want %v", balance, expectedBalance)
	}

	// If we require any confirmations the balance will be 0 because none of
	// the credits above will have the minimum required confirmations.
	minConf = 1
	TstRunWithManagerUnlocked(t, pool.manager, func() {
		balance, err = pool.seriesBalance(seriesID, dustThreshold, minConf, store)
	})
	if err != nil {
		t.Fatal(err)
	}

	if balance != btcutil.Amount(0) {
		t.Fatalf("Unexpected series balance; got %v, want %v", balance, btcutil.Amount(0))
	}

	// Similary, if the dustThreshold is higher than the amount in our credits,
	// the balance will be 0.
	minConf = 0
	dustThreshold = btcutil.Amount(creditAmt + 1)
	TstRunWithManagerUnlocked(t, pool.manager, func() {
		balance, err = pool.seriesBalance(seriesID, dustThreshold, minConf, store)
	})
	if err != nil {
		t.Fatal(err)
	}

	if balance != btcutil.Amount(0) {
		t.Fatalf("Unexpected series balance; got %v, want %v", balance, btcutil.Amount(0))
	}
}

func TestSerializationErrors(t *testing.T) {
	tearDown, mgr, _ := TstCreatePool(t)
	defer tearDown()

	tests := []struct {
		version  uint32
		pubKeys  []string
		privKeys []string
		reqSigs  uint32
		err      ErrorCode
	}{
		{
			version: 2,
			pubKeys: TstPubKeys[0:3],
			err:     ErrSeriesVersion,
		},
		{
			pubKeys: []string{"NONSENSE"},
			// Not a valid length public key.
			err: ErrSeriesSerialization,
		},
		{
			pubKeys:  TstPubKeys[0:3],
			privKeys: TstPrivKeys[0:1],
			// The number of public and private keys should be the same.
			err: ErrSeriesSerialization,
		},
		{
			pubKeys:  TstPubKeys[0:1],
			privKeys: []string{"NONSENSE"},
			// Not a valid length private key.
			err: ErrSeriesSerialization,
		},
	}

	active := true
	for testNum, test := range tests {
		encryptedPubs, err := encryptKeys(test.pubKeys, mgr, waddrmgr.CKTPublic)
		if err != nil {
			t.Fatalf("Test #%d - Error encrypting pubkeys: %v", testNum, err)
		}
		var encryptedPrivs [][]byte
		TstRunWithManagerUnlocked(t, mgr, func() {
			encryptedPrivs, err = encryptKeys(test.privKeys, mgr, waddrmgr.CKTPrivate)
		})
		if err != nil {
			t.Fatalf("Test #%d - Error encrypting privkeys: %v", testNum, err)
		}

		row := &dbSeriesRow{
			version:           test.version,
			active:            active,
			reqSigs:           test.reqSigs,
			pubKeysEncrypted:  encryptedPubs,
			privKeysEncrypted: encryptedPrivs}
		_, err = serializeSeriesRow(row)

		TstCheckError(t, fmt.Sprintf("Test #%d", testNum), err, test.err)
	}
}

func TestSerialization(t *testing.T) {
	tearDown, mgr, _ := TstCreatePool(t)
	defer tearDown()

	tests := []struct {
		version  uint32
		active   bool
		pubKeys  []string
		privKeys []string
		reqSigs  uint32
	}{
		{
			version: 1,
			active:  true,
			pubKeys: TstPubKeys[0:1],
			reqSigs: 1,
		},
		{
			version:  0,
			active:   false,
			pubKeys:  TstPubKeys[0:1],
			privKeys: TstPrivKeys[0:1],
			reqSigs:  1,
		},
		{
			pubKeys:  TstPubKeys[0:3],
			privKeys: []string{TstPrivKeys[0], "", ""},
			reqSigs:  2,
		},
		{
			pubKeys: TstPubKeys[0:5],
			reqSigs: 3,
		},
		{
			pubKeys:  TstPubKeys[0:7],
			privKeys: []string{"", TstPrivKeys[1], "", TstPrivKeys[3], "", "", ""},
			reqSigs:  4,
		},
	}

	var encryptedPrivs [][]byte
	for testNum, test := range tests {
		encryptedPubs, err := encryptKeys(test.pubKeys, mgr, waddrmgr.CKTPublic)
		if err != nil {
			t.Fatalf("Test #%d - Error encrypting pubkeys: %v", testNum, err)
		}
		TstRunWithManagerUnlocked(t, mgr, func() {
			encryptedPrivs, err = encryptKeys(test.privKeys, mgr, waddrmgr.CKTPrivate)
		})
		if err != nil {
			t.Fatalf("Test #%d - Error encrypting privkeys: %v", testNum, err)
		}

		row := &dbSeriesRow{
			version:           test.version,
			active:            test.active,
			reqSigs:           test.reqSigs,
			pubKeysEncrypted:  encryptedPubs,
			privKeysEncrypted: encryptedPrivs,
		}
		serialized, err := serializeSeriesRow(row)
		if err != nil {
			t.Fatalf("Test #%d - Error in serialization %v", testNum, err)
		}

		row, err = deserializeSeriesRow(serialized)
		if err != nil {
			t.Fatalf("Test #%d - Failed to deserialize %v %v", testNum, serialized, err)
		}

		if row.version != test.version {
			t.Errorf("Serialization #%d - version mismatch: got %d want %d",
				testNum, row.version, test.version)
		}

		if row.active != test.active {
			t.Errorf("Serialization #%d - active mismatch: got %v want %v",
				testNum, row.active, test.active)
		}

		if row.reqSigs != test.reqSigs {
			t.Errorf("Serialization #%d - row reqSigs off. Got %d, want %d",
				testNum, row.reqSigs, test.reqSigs)
		}

		if len(row.pubKeysEncrypted) != len(test.pubKeys) {
			t.Errorf("Serialization #%d - Wrong no. of pubkeys. Got %d, want %d",
				testNum, len(row.pubKeysEncrypted), len(test.pubKeys))
		}

		for i, encryptedPub := range encryptedPubs {
			got := string(row.pubKeysEncrypted[i])

			if got != string(encryptedPub) {
				t.Errorf("Serialization #%d - Pubkey deserialization. Got %v, want %v",
					testNum, got, string(encryptedPub))
			}
		}

		if len(row.privKeysEncrypted) != len(row.pubKeysEncrypted) {
			t.Errorf("Serialization #%d - no. privkeys (%d) != no. pubkeys (%d)",
				testNum, len(row.privKeysEncrypted), len(row.pubKeysEncrypted))
		}

		for i, encryptedPriv := range encryptedPrivs {
			got := string(row.privKeysEncrypted[i])

			if got != string(encryptedPriv) {
				t.Errorf("Serialization #%d - Privkey deserialization. Got %v, want %v",
					testNum, got, string(encryptedPriv))
			}
		}
	}
}

func TestDeserializationErrors(t *testing.T) {
	tearDown, _, _ := TstCreatePool(t)
	defer tearDown()

	tests := []struct {
		serialized []byte
		err        ErrorCode
	}{
		{
			serialized: make([]byte, seriesMaxSerial+1),
			// Too many bytes (over seriesMaxSerial).
			err: ErrSeriesSerialization,
		},
		{
			serialized: make([]byte, seriesMinSerial-1),
			// Not enough bytes (under seriesMinSerial).
			err: ErrSeriesSerialization,
		},
		{
			serialized: []byte{
				1, 0, 0, 0, // 4 bytes (version)
				0,          // 1 byte (active)
				2, 0, 0, 0, // 4 bytes (reqSigs)
				3, 0, 0, 0, // 4 bytes (nKeys)
			},
			// Here we have the constant data but are missing any public/private keys.
			err: ErrSeriesSerialization,
		},
		{
			serialized: []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			// Unsupported version.
			err: ErrSeriesVersion,
		},
	}

	for testNum, test := range tests {
		_, err := deserializeSeriesRow(test.serialized)

		TstCheckError(t, fmt.Sprintf("Test #%d", testNum), err, test.err)
	}
}

func TestValidateAndDecryptKeys(t *testing.T) {
	tearDown, manager, pool := TstCreatePool(t)
	defer tearDown()

	rawPubKeys, err := encryptKeys(TstPubKeys[0:2], manager, waddrmgr.CKTPublic)
	if err != nil {
		t.Fatalf("Failed to encrypt public keys: %v", err)
	}

	var rawPrivKeys [][]byte
	TstRunWithManagerUnlocked(t, manager, func() {
		rawPrivKeys, err = encryptKeys([]string{TstPrivKeys[0], ""}, manager, waddrmgr.CKTPrivate)
	})
	if err != nil {
		t.Fatalf("Failed to encrypt private keys: %v", err)
	}

	var pubKeys, privKeys []*hdkeychain.ExtendedKey
	TstRunWithManagerUnlocked(t, manager, func() {
		pubKeys, privKeys, err = validateAndDecryptKeys(rawPubKeys, rawPrivKeys, pool)
	})
	if err != nil {
		t.Fatalf("Error when validating/decrypting keys: %v", err)
	}

	if len(pubKeys) != 2 {
		t.Fatalf("Unexpected number of decrypted public keys: got %d, want 2", len(pubKeys))
	}
	if len(privKeys) != 2 {
		t.Fatalf("Unexpected number of decrypted private keys: got %d, want 2", len(privKeys))
	}

	if pubKeys[0].String() != TstPubKeys[0] || pubKeys[1].String() != TstPubKeys[1] {
		t.Fatalf("Public keys don't match: %v!=%v ", TstPubKeys[0:2], pubKeys)
	}

	if privKeys[0].String() != TstPrivKeys[0] || privKeys[1] != nil {
		t.Fatalf("Private keys don't match: %v, %v", []string{TstPrivKeys[0], ""}, privKeys)
	}

	neuteredKey, err := privKeys[0].Neuter()
	if err != nil {
		t.Fatalf("Unable to neuter private key: %v", err)
	}
	if pubKeys[0].String() != neuteredKey.String() {
		t.Errorf("Public key (%v) does not match neutered private key (%v)",
			pubKeys[0].String(), neuteredKey.String())
	}
}

func TestValidateAndDecryptKeysErrors(t *testing.T) {
	tearDown, manager, pool := TstCreatePool(t)
	defer tearDown()

	encryptedPubKeys, err := encryptKeys(TstPubKeys[0:1], manager, waddrmgr.CKTPublic)
	if err != nil {
		t.Fatalf("Failed to encrypt public key: %v", err)
	}

	var encryptedPrivKeys [][]byte
	TstRunWithManagerUnlocked(t, manager, func() {
		encryptedPrivKeys, err = encryptKeys(TstPrivKeys[1:2], manager, waddrmgr.CKTPrivate)
	})
	if err != nil {
		t.Fatalf("Failed to encrypt private key: %v", err)
	}

	tests := []struct {
		rawPubKeys  [][]byte
		rawPrivKeys [][]byte
		err         ErrorCode
	}{
		{
			// Number of public keys does not match number of private keys.
			rawPubKeys:  [][]byte{[]byte(TstPubKeys[0])},
			rawPrivKeys: [][]byte{},
			err:         ErrKeysPrivatePublicMismatch,
		},
		{
			// Failure to decrypt public key.
			rawPubKeys:  [][]byte{[]byte(TstPubKeys[0])},
			rawPrivKeys: [][]byte{[]byte(TstPrivKeys[0])},
			err:         ErrCrypto,
		},
		{
			// Failure to decrypt private key.
			rawPubKeys:  encryptedPubKeys,
			rawPrivKeys: [][]byte{[]byte(TstPrivKeys[0])},
			err:         ErrCrypto,
		},
		{
			// One public and one private key, but they don't match.
			rawPubKeys:  encryptedPubKeys,
			rawPrivKeys: encryptedPrivKeys,
			err:         ErrKeyMismatch,
		},
	}

	for i, test := range tests {
		TstRunWithManagerUnlocked(t, manager, func() {
			_, _, err = validateAndDecryptKeys(test.rawPubKeys, test.rawPrivKeys, pool)
		})
		TstCheckError(t, fmt.Sprintf("Test #%d", i), err, test.err)
	}
}

func encryptKeys(keys []string, mgr *waddrmgr.Manager, keyType waddrmgr.CryptoKeyType) ([][]byte, error) {
	encryptedKeys := make([][]byte, len(keys))
	var err error
	for i, key := range keys {
		if key == "" {
			encryptedKeys[i] = nil
		} else {
			encryptedKeys[i], err = mgr.Encrypt(keyType, []byte(key))
		}
		if err != nil {
			return nil, err
		}
	}
	return encryptedKeys, nil
}
