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

/*
This test file is part of the waddrmgr package rather than than the
waddrmgr_test package so it can bridge access to the internals to properly test
cases which are either not possible or can't reliably be tested via the public
interface. The functions are only exported while the tests are being run.
*/

package waddrmgr

import (
	"errors"

	"github.com/conformal/btcwallet/snacl"
)

// TstMaxRecentHashes makes the unexported maxRecentHashes constant available
// when tests are run.
var TstMaxRecentHashes = maxRecentHashes

// Replace the Manager.newSecretKey function with the given one and calls
// the callback function. Afterwards the original newSecretKey
// function will be restored.
func TstRunWithReplacedNewSecretKey(callback func()) {
	orig := newSecretKey
	defer func() {
		newSecretKey = orig
	}()
	newSecretKey = func(passphrase *[]byte, config *Options) (*snacl.SecretKey, error) {
		return nil, snacl.ErrDecryptFailed
	}
	callback()
}

// TstCheckPublicPassphrase return true if the provided public passphrase is
// correct for the manager.
func (m *Manager) TstCheckPublicPassphrase(pubPassphrase []byte) bool {
	secretKey := snacl.SecretKey{Key: &snacl.CryptoKey{}}
	secretKey.Parameters = m.masterKeyPub.Parameters
	err := secretKey.DeriveKey(&pubPassphrase)
	return err == nil
}

// failingCryptoKey is an implementation of the EncryptorDecryptor interface
// with intentionally fails when attempting to encrypt or decrypt with it.
type failingCryptoKey struct {
	cryptoKey
}

// Encrypt intenionally returns a failure when invoked to test error paths.
//
// This is part of the EncryptorDecryptor interface implementation.
func (c *failingCryptoKey) Encrypt(in []byte) ([]byte, error) {
	return nil, errors.New("failed to encrypt")
}

// Decrypt intenionally returns a failure when invoked to test error paths.
//
// This is part of the EncryptorDecryptor interface implementation.
func (c *failingCryptoKey) Decrypt(in []byte) ([]byte, error) {
	return nil, errors.New("failed to decrypt")
}

// TstRunWithFailingCryptoKeyPriv runs the provided callback with the
// private crypto key replaced with a version that fails to help test error
// paths.
func TstRunWithFailingCryptoKeyPriv(m *Manager, callback func()) {
	orig := m.cryptoKeyPriv
	defer func() {
		m.cryptoKeyPriv = orig
	}()
	m.cryptoKeyPriv = &failingCryptoKey{}
	callback()
}
