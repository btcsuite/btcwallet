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
	"github.com/conformal/btcwallet/snacl"
)

// TstMaxRecentHashes makes the unexported maxRecentHashes constant available
// when tests are run.
var TstMaxRecentHashes = maxRecentHashes

// TstSetScryptParams allows the scrypt parameters to be set to much lower
// values while the tests are running so they are faster.
func TstSetScryptParams(n, r, p int) {
	scryptN = n
	scryptR = r
	scryptP = p
}

// TstReplaceNewSecretKeyFunc replaces the new secret key generation function
// with a version that intentionally fails.
func TstReplaceNewSecretKeyFunc() {
	newSecretKey = func(passphrase *[]byte) (*snacl.SecretKey, error) {
		return nil, snacl.ErrDecryptFailed
	}
}

// TstResetNewSecretKeyFunc resets the new secret key generation function to the
// original version.
func TstResetNewSecretKeyFunc() {
	newSecretKey = defaultNewSecretKey
}

// TstCheckPublicPassphrase return true if the provided public passphrase is
// correct for the manager.
func (m *Manager) TstCheckPublicPassphrase(pubPassphrase []byte) bool {
	secretKey := snacl.SecretKey{Key: &snacl.CryptoKey{}}
	secretKey.Parameters = m.masterKeyPub.Parameters
	err := secretKey.DeriveKey(&pubPassphrase)
	return err == nil
}
