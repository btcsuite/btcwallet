//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// importedAccountKeys holds deterministic public and private account material
// used to exercise imported-account contracts without sharing wallet state.
// accountPrivateKey is present only so a case can assert private keys are
// refused.
type importedAccountKeys struct {
	scope                waddrmgr.KeyScope
	addrType             waddrmgr.AddressType
	accountKey           *hdkeychain.ExtendedKey
	otherAccountKey      *hdkeychain.ExtendedKey
	accountPrivateKey    *hdkeychain.ExtendedKey
	masterKeyFingerprint uint32
}

// canonicalAccountKey returns a derived account key under the network default
// public version so backend-specific serialized versions compare consistently.
func canonicalAccountKey(h *bwtest.HarnessTest, key []byte) []byte {
	h.Helper()

	parsed, err := hdkeychain.NewKeyFromString(string(key))
	require.NoError(h, err, "failed to decode account public key")
	normalized, err := parsed.CloneWithVersion(
		h.NetParams().HDPublicKeyID[:],
	)
	require.NoError(
		h, err, "failed to normalize account public key version",
	)

	return []byte(normalized.String())
}

// deterministicImportedAccountKeys derives distinct BIP84 account XPubs from a
// fixed root so imported-account cases are reproducible.
func deterministicImportedAccountKeys(
	h *bwtest.HarnessTest) importedAccountKeys {

	h.Helper()

	scope := waddrmgr.KeyScopeBIP0084
	root, err := hdkeychain.NewMaster(
		[]byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		},
		h.NetParams(),
	)
	require.NoError(h, err, "failed to derive deterministic root key")

	defer root.Zero()

	purpose, err := root.Derive(hdkeychain.HardenedKeyStart + scope.Purpose)
	require.NoError(h, err, "failed to derive BIP84 purpose key")

	defer purpose.Zero()

	coinType, err := purpose.Derive(
		hdkeychain.HardenedKeyStart + h.NetParams().HDCoinType,
	)
	require.NoError(h, err, "failed to derive BIP84 coin type key")

	defer coinType.Zero()

	// Neuter hands the public key the same chain code and parent
	// fingerprint slices the private key holds, so the two account private
	// keys below must outlive this call. Zeroing either one rewrites the
	// XPub being returned.
	accountPrivateKey, err := coinType.Derive(hdkeychain.HardenedKeyStart)
	require.NoError(h, err, "failed to derive imported account private key")
	accountKey, err := accountPrivateKey.Neuter()
	require.NoError(h, err, "failed to derive imported account public key")

	otherPrivateKey, err := coinType.Derive(hdkeychain.HardenedKeyStart + 1)
	require.NoError(h, err, "failed to derive second imported private key")
	otherAccountKey, err := otherPrivateKey.Neuter()
	require.NoError(h, err, "failed to derive second imported public key")

	return importedAccountKeys{
		scope:                scope,
		addrType:             waddrmgr.WitnessPubKey,
		accountKey:           accountKey,
		otherAccountKey:      otherAccountKey,
		accountPrivateKey:    accountPrivateKey,
		masterKeyFingerprint: purpose.ParentFingerprint(),
	}
}

// testAccountManagerCreateAccount verifies that a new derived account's
// returned view matches an immediate read and survives a wallet reload.
func testAccountManagerCreateAccount(h *bwtest.HarnessTest) {
	const accountName = "account manager created"

	scope := waddrmgr.KeyScopeBIP0084
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})

	created, err := w.NewAccount(ctx, scope, accountName)

	require.NoError(h, err, "failed to create derived account")
	require.Equal(h, accountName, created.AccountName)
	require.NotNil(
		h, created.AccountNumber, "derived account has no number",
	)
	require.Zero(h, created.ExternalKeyCount)
	require.Zero(h, created.InternalKeyCount)
	require.Zero(h, created.ImportedKeyCount)
	require.Zero(h, created.ConfirmedBalance)
	require.Zero(h, created.UnconfirmedBalance)
	require.False(h, created.IsImported, "derived account is imported")
	require.False(h, created.IsWatchOnly, "derived account is watch-only")
	require.NotZero(
		h, created.CreatedAt, "derived account has no creation time",
	)
	require.Equal(h, scope, created.KeyScope)
	require.Equal(
		h, waddrmgr.WitnessPubKey, created.AddrSchema.ExternalAddrType,
	)
	require.Equal(
		h, waddrmgr.WitnessPubKey, created.AddrSchema.InternalAddrType,
	)
	normalizedPublicKey := canonicalAccountKey(h, created.PublicKey)
	require.NotEmpty(
		h, normalizedPublicKey, "derived account has no public key",
	)
	require.NotNil(
		h, created.MasterKeyFingerprint,
		"derived account has no master key fingerprint",
	)
	require.NotZero(
		h, *created.MasterKeyFingerprint,
		"derived account has no master key fingerprint",
	)
	want := *created
	want.PublicKey = normalizedPublicKey
	got, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "failed to read created account")

	gotInfo := *got
	gotInfo.PublicKey = canonicalAccountKey(h, gotInfo.PublicKey)
	require.Equal(h, want, gotInfo)

	w = h.ReloadWallet(w)
	durable, err := w.GetAccount(ctx, scope, accountName)
	require.NoError(h, err, "failed to read account after reload")

	durableInfo := *durable
	durableInfo.PublicKey = canonicalAccountKey(h, durableInfo.PublicKey)
	require.Equal(h, want, durableInfo)
}

// testAccountManagerCreateAccountSequence verifies that derived account numbers
// are allocated contiguously within a key scope, that each scope allocates from
// its own counter, and that the counter survives a wallet reload.
func testAccountManagerCreateAccountSequence(h *bwtest.HarnessTest) {
	const (
		otherScopeName = "account manager sequence other"
		resumedName    = "account manager sequence next"
	)

	names := []string{
		"account manager sequence one",
		"account manager sequence two",
		"account manager sequence three",
	}

	ctx := h.Context()
	scope := waddrmgr.KeyScopeBIP0084
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})

	numbers := make([]wallet.AccountNumber, 0, len(names))
	for _, name := range names {
		created, err := w.NewAccount(ctx, scope, name)
		require.NoError(h, err, "failed to create %q", name)
		require.NotNil(h, created.AccountNumber, "%q has no number", name)

		numbers = append(numbers, *created.AccountNumber)
	}

	for i := 1; i < len(numbers); i++ {
		require.Equal(
			h, numbers[i-1]+1, numbers[i],
			"%q did not take the next account number", names[i],
		)
	}

	// A second scope allocates from its own counter, so its first
	// user-created account repeats the first scope's starting number.
	other, err := w.NewAccount(ctx, waddrmgr.KeyScopeBIP0044, otherScopeName)
	require.NoError(h, err, "failed to create other scope account")
	require.NotNil(h, other.AccountNumber, "other scope has no number")

	require.Equal(
		h, numbers[0], *other.AccountNumber,
		"second scope did not allocate from its own counter",
	)

	// The counter is persistent, so the next account continues the sequence
	// rather than reusing a number.
	w = h.ReloadWallet(w)
	h.UnlockWallet(w)

	resumed, err := w.NewAccount(ctx, scope, resumedName)
	require.NoError(h, err, "failed to create account after reload")
	require.NotNil(
		h, resumed.AccountNumber, "resumed account has no number",
	)
	require.Equal(
		h, numbers[len(numbers)-1]+1, *resumed.AccountNumber,
		"account number did not resume the sequence after reload",
	)
}

// testAccountManagerRejectAccountCreation verifies rejected names cannot alter
// an existing account or its scope's account count.
func testAccountManagerRejectAccountCreation(h *bwtest.HarnessTest) {
	const (
		sourceName         = "account manager rejection source"
		afterRejectionName = "account manager after rejection"
	)

	scope := waddrmgr.KeyScopeBIP0084
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})

	_, err := w.NewAccount(ctx, scope, sourceName)
	require.NoError(h, err, "failed to create rejection source")

	existing, err := w.GetAccount(ctx, scope, sourceName)
	require.NoError(h, err, "failed to read rejection source")

	wantExisting := *existing
	wantExisting.PublicKey = canonicalAccountKey(h, wantExisting.PublicKey)
	accounts, err := w.ListAccountsByScope(ctx, scope)
	require.NoError(h, err, "failed to list source scope accounts")

	wantCount := len(accounts)

	// These rejections have no stable public error identity yet, so the
	// rows assert rejection and unchanged state only.
	testCases := []struct {
		name        string
		accountName string
	}{
		{
			name:        "duplicate source name",
			accountName: sourceName,
		},
		{
			name:        "empty name",
			accountName: "",
		},
	}

	for _, tc := range testCases {
		_, err := w.NewAccount(ctx, scope, tc.accountName)

		require.Error(h, err, "%s was accepted", tc.name)

		current, err := w.GetAccount(ctx, scope, sourceName)
		require.NoError(
			h, err, "failed to read source account after rejection",
		)

		currentInfo := *current
		currentInfo.PublicKey = canonicalAccountKey(
			h, currentInfo.PublicKey,
		)
		require.Equal(h, wantExisting, currentInfo)

		accounts, err = w.ListAccountsByScope(ctx, scope)
		require.NoError(
			h, err, "failed to list accounts after rejection",
		)
		require.Len(
			h, accounts, wantCount, "rejection changed account count",
		)
	}

	// The account number is allocated before the insert, so only the
	// rolled-back transaction keeps a rejected call from consuming one.
	next, err := w.NewAccount(ctx, scope, afterRejectionName)
	require.NoError(h, err, "failed to create account after rejections")
	require.NotNil(
		h, next.AccountNumber, "account after rejections has no number",
	)
	require.Equal(
		h, *wantExisting.AccountNumber+1, *next.AccountNumber,
		"rejected creation consumed an account number",
	)
}

// testAccountManagerEnforceAccountCreationLifecycle verifies NewAccount admits
// neither locked nor stopped wallets.
func testAccountManagerEnforceAccountCreationLifecycle(h *bwtest.HarnessTest) {
	const (
		lockedName  = "account manager locked"
		stoppedName = "account manager stopped"
	)

	scope := waddrmgr.KeyScopeBIP0084
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})

	accounts, err := w.ListAccounts(ctx)
	require.NoError(h, err, "failed to list accounts before rejections")

	wantCount := len(accounts)

	require.NoError(h, w.Lock(ctx), "failed to lock wallet")

	_, err = w.NewAccount(ctx, scope, lockedName)

	require.Error(h, err, "locked wallet created an account")
	require.NoError(h, w.Stop(ctx), "failed to stop wallet")

	_, err = w.NewAccount(ctx, scope, stoppedName)

	require.ErrorIs(h, err, wallet.ErrStateForbidden)

	// An admission rejected before or after the wallet stops must leave no
	// partial account, so neither name resolves across a reopen and the
	// account set is unchanged.
	w = h.ReloadWallet(w)
	_, err = w.GetAccount(ctx, scope, lockedName)
	require.Error(h, err, "locked rejection created an account")
	_, err = w.GetAccount(ctx, scope, stoppedName)
	require.Error(h, err, "stopped rejection created an account")

	accounts, err = w.ListAccounts(ctx)
	require.NoError(h, err, "failed to list accounts after rejections")
	require.Len(h, accounts, wantCount, "rejection changed account count")
}

// testAccountManagerRejectWatchOnlyAccountCreation verifies a rootless wallet
// cannot derive account key material.
func testAccountManagerRejectWatchOnlyAccountCreation(h *bwtest.HarnessTest) {
	const accountName = "watch-only"

	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})
	require.True(h, w.IsWatchOnly(), "watch-only fixture is not watch-only")

	_, err := w.NewAccount(ctx, waddrmgr.KeyScopeBIP0084, accountName)

	require.Error(h, err, "watch-only wallet created an account")
	_, err = w.GetAccount(ctx, waddrmgr.KeyScopeBIP0084, accountName)
	require.Error(h, err, "rejected watch-only account name resolves")
}
