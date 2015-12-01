// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package snacl

import (
	"bytes"
	"testing"
)

var (
	password = []byte("sikrit")
	message  = []byte("this is a secret message of sorts")
	key      *SecretKey
	params   []byte
	blob     []byte
)

func TestNewSecretKey(t *testing.T) {
	var err error
	key, err = NewSecretKey(&password, DefaultN, DefaultR, DefaultP)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestMarshalSecretKey(t *testing.T) {
	params = key.Marshal()
}

func TestUnmarshalSecretKey(t *testing.T) {
	var sk SecretKey
	if err := sk.Unmarshal(params); err != nil {
		t.Errorf("unexpected unmarshal error: %v", err)
		return
	}

	if err := sk.DeriveKey(&password); err != nil {
		t.Errorf("unexpected DeriveKey error: %v", err)
		return
	}

	if !bytes.Equal(sk.Key[:], key.Key[:]) {
		t.Errorf("keys not equal")
	}
}

func TestUnmarshalSecretKeyInvalid(t *testing.T) {
	var sk SecretKey
	if err := sk.Unmarshal(params); err != nil {
		t.Errorf("unexpected unmarshal error: %v", err)
		return
	}

	p := []byte("wrong password")
	if err := sk.DeriveKey(&p); err != ErrInvalidPassword {
		t.Errorf("wrong password didn't fail")
		return
	}
}

func TestEncrypt(t *testing.T) {
	var err error

	blob, err = key.Encrypt(message)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestDecrypt(t *testing.T) {
	decryptedMessage, err := key.Decrypt(blob)
	if err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(decryptedMessage, message) {
		t.Errorf("decryption failed")
		return
	}
}

func TestDecryptCorrupt(t *testing.T) {
	blob[len(blob)-15] = blob[len(blob)-15] + 1
	_, err := key.Decrypt(blob)
	if err == nil {
		t.Errorf("corrupt message decrypted")
		return
	}
}

func TestZero(t *testing.T) {
	var zeroKey [32]byte

	key.Zero()
	if !bytes.Equal(key.Key[:], zeroKey[:]) {
		t.Errorf("zero key failed")
	}
}

func TestDeriveKey(t *testing.T) {
	if err := key.DeriveKey(&password); err != nil {
		t.Errorf("unexpected DeriveKey key failure: %v", err)
	}
}

func TestDeriveKeyInvalid(t *testing.T) {
	bogusPass := []byte("bogus")
	if err := key.DeriveKey(&bogusPass); err != ErrInvalidPassword {
		t.Errorf("unexpected DeriveKey key failure: %v", err)
	}
}
