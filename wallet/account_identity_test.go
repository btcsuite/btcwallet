// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

const accountIdentityTestName = "imported-xpub"

// TestAccountIdentitySelectorConstructors verifies that the public
// constructors preserve the supplied semantic identity.
func TestAccountIdentitySelectorConstructors(t *testing.T) {
	t.Parallel()

	keyScope := waddrmgr.KeyScopeBIP0084
	accountName := accountIdentityTestName
	accountNumber := AccountNumber(0)

	byName := NewAccountSelectorByName(keyScope, accountName)

	require.Equal(t, keyScope, byName.keyScope)
	require.NotNil(t, byName.accountName)
	require.Equal(t, accountName, *byName.accountName)
	require.Nil(t, byName.accountNumber)

	byNumber := NewAccountSelectorByNumber(keyScope, accountNumber)

	require.Equal(t, keyScope, byNumber.keyScope)
	require.Nil(t, byNumber.accountName)
	require.NotNil(t, byNumber.accountNumber)
	require.Equal(t, accountNumber, *byNumber.accountNumber)
}

// TestAccountIdentitySelectorValidate verifies that semantic account selectors
// accept exactly one portable identity and reject ambiguous or empty shapes.
func TestAccountIdentitySelectorValidate(t *testing.T) {
	t.Parallel()

	accountName := accountIdentityTestName
	accountNumber := AccountNumber(0)

	tests := []struct {
		name      string
		selector  AccountSelector
		wantError bool
	}{
		{
			name: "accepts name constructor",
			selector: NewAccountSelectorByName(
				waddrmgr.KeyScopeBIP0084, accountName,
			),
		},
		{
			name: "accepts present zero number constructor",
			selector: NewAccountSelectorByNumber(
				waddrmgr.KeyScopeBIP0084, accountNumber,
			),
		},
		{
			name: "rejects neither",
			selector: AccountSelector{
				keyScope: waddrmgr.KeyScopeBIP0084,
			},
			wantError: true,
		},
		{
			name: "rejects both",
			selector: AccountSelector{
				keyScope:      waddrmgr.KeyScopeBIP0084,
				accountName:   &accountName,
				accountNumber: &accountNumber,
			},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.selector.validate()

			if test.wantError {
				require.ErrorIs(t, err, errInvalidAccountSelector)
				return
			}

			require.NoError(t, err)
		})
	}
}

// TestAccountIdentityOptionalValues verifies that callers can distinguish
// absent identity values from present-zero values using pointers.
func TestAccountIdentityOptionalValues(t *testing.T) {
	t.Parallel()

	var absentAccountNumber *AccountNumber

	accountNumber := AccountNumber(0)
	presentAccountNumber := &accountNumber

	var absentFingerprint *MasterFingerprint

	fingerprint := MasterFingerprint(0)
	presentFingerprint := &fingerprint

	require.Nil(t, absentAccountNumber)
	require.NotNil(t, presentAccountNumber)
	require.Equal(t, AccountNumber(0), *presentAccountNumber)
	require.Nil(t, absentFingerprint)
	require.NotNil(t, presentFingerprint)
	require.Equal(t, MasterFingerprint(0), *presentFingerprint)
}
