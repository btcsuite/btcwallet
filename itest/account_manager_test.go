//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// accountManagerFundingType is the address type whose key scope the
// default-account case operates in. Funding it materializes that scope on
// every backend.
const accountManagerFundingType = waddrmgr.WitnessPubKey

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

// testAccountManagerRenameDerivedAccount verifies that renaming a derived
// account changes only its name and survives a wallet reload.
func testAccountManagerRenameDerivedAccount(h *bwtest.HarnessTest) {
	const (
		sourceName  = "account manager derived source"
		renamedName = "account manager derived renamed"
	)

	scope := waddrmgr.KeyScopeBIP0084
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	_, err := w.NewAccount(ctx, scope, sourceName)
	require.NoError(h, err, "failed to create derived rename source")

	source, err := w.GetAccount(ctx, scope, sourceName)
	require.NoError(h, err, "failed to read derived rename source")

	wantRenamed := *source
	wantRenamed.AccountName = renamedName
	wantRenamed.PublicKey = canonicalAccountKey(h, wantRenamed.PublicKey)

	err = w.RenameAccount(ctx, scope, sourceName, renamedName)

	require.NoError(h, err, "failed to rename derived account")
	_, err = w.GetAccount(ctx, scope, sourceName)
	require.Error(h, err, "old derived account name still resolves")
	renamed, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "failed to read renamed derived account")

	renamedInfo := *renamed
	renamedInfo.PublicKey = canonicalAccountKey(h, renamedInfo.PublicKey)
	require.Equal(h, wantRenamed, renamedInfo)

	w = h.ReloadWallet(w)
	_, err = w.GetAccount(ctx, scope, sourceName)
	require.Error(h, err, "old derived account name resolves after reload")
	durable, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "failed to read renamed account after reload")

	durableInfo := *durable
	durableInfo.PublicKey = canonicalAccountKey(h, durableInfo.PublicKey)
	require.Equal(h, wantRenamed, durableInfo)
}

// testAccountManagerRenameDefaultAccount verifies the default account keeps a
// present-zero account number across a rename and a wallet reload, rather than
// collapsing the zero value to an absent identity.
//
// The scope is derived from the funding address type because that is the only
// scope every backend is guaranteed to hold a default account in: kvdb seeds
// one per scope at genesis, while SQL creates it lazily on first use.
func testAccountManagerRenameDefaultAccount(h *bwtest.HarnessTest) {
	const renamedName = "account manager renamed default"

	scope, err := accountManagerFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	ctx := h.Context()
	w, _ := h.NewWallet(
		bwtest.WalletFixture{
			AddrType: accountManagerFundingType,
			Amounts:  []btcutil.Amount{oneBTC},
			Unlocked: true,
		},
	)

	source, err := w.GetAccount(ctx, scope, waddrmgr.DefaultAccountName)
	require.NoError(h, err, "failed to read default account")
	require.NotNil(h, source.AccountNumber, "default account has no number")
	require.Zero(
		h, *source.AccountNumber, "default account number is not zero",
	)

	wantRenamed := *source
	wantRenamed.AccountName = renamedName
	wantRenamed.PublicKey = canonicalAccountKey(h, wantRenamed.PublicKey)

	err = w.RenameAccount(
		ctx, scope, waddrmgr.DefaultAccountName, renamedName,
	)

	require.NoError(h, err, "failed to rename default account")
	renamed, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(h, err, "failed to read renamed default account")
	require.NotNil(
		h, renamed.AccountNumber, "renamed default account has no number",
	)
	require.Zero(
		h, *renamed.AccountNumber,
		"renamed default account number is not zero",
	)

	renamedInfo := *renamed
	renamedInfo.PublicKey = canonicalAccountKey(h, renamedInfo.PublicKey)
	require.Equal(h, wantRenamed, renamedInfo)

	w = h.ReloadWallet(w)
	durable, err := w.GetAccount(ctx, scope, renamedName)
	require.NoError(
		h, err, "failed to read renamed default account after reload",
	)
	require.NotNil(
		h, durable.AccountNumber,
		"default account number is absent after reload",
	)
	require.Zero(
		h, *durable.AccountNumber,
		"default account number is not zero after reload",
	)

	durableInfo := *durable
	durableInfo.PublicKey = canonicalAccountKey(h, durableInfo.PublicKey)
	require.Equal(h, wantRenamed, durableInfo)
}

// testAccountManagerRenameImportedAccount verifies an InitialAccounts XPub
// keeps its caller-supplied serialization when renamed and reloaded.
func testAccountManagerRenameImportedAccount(h *bwtest.HarnessTest) {
	const (
		sourceName  = "account manager imported source"
		renamedName = "account manager imported renamed"
	)

	keys := deterministicImportedAccountKeys(h)
	ctx := h.Context()
	w, _ := h.NewWallet(
		bwtest.WalletFixture{
			InitialAccounts: []wallet.WatchOnlyAccount{{
				Scope:                keys.scope,
				XPub:                 keys.accountKey,
				MasterKeyFingerprint: keys.masterKeyFingerprint,
				Name:                 sourceName,
				AddrType:             keys.addrType,
			}},
		},
	)
	source, err := w.GetAccount(ctx, keys.scope, sourceName)
	require.NoError(h, err, "failed to read imported account")

	wantRenamed := *source
	wantRenamed.AccountName = renamedName
	wantRenamed.PublicKey = []byte(keys.accountKey.String())

	err = w.RenameAccount(ctx, keys.scope, sourceName, renamedName)

	require.NoError(h, err, "failed to rename imported account")
	_, err = w.GetAccount(ctx, keys.scope, sourceName)
	require.Error(h, err, "old imported account name still resolves")
	renamed, err := w.GetAccount(ctx, keys.scope, renamedName)
	require.NoError(h, err, "failed to read renamed imported account")
	require.Equal(h, wantRenamed, *renamed)

	w = h.ReloadWallet(w)
	_, err = w.GetAccount(ctx, keys.scope, sourceName)
	require.Error(h, err, "old imported account name resolves after reload")
	durable, err := w.GetAccount(ctx, keys.scope, renamedName)
	require.NoError(h, err, "failed to read renamed import after reload")
	require.Equal(h, wantRenamed, *durable)
}

// testAccountManagerRejectAccountRename verifies rejected rename requests leave
// the established source and duplicate target unchanged.
func testAccountManagerRejectAccountRename(h *bwtest.HarnessTest) {
	const (
		sourceName      = "account manager rename source"
		duplicateTarget = "account manager occupied target"
	)

	scope := waddrmgr.KeyScopeBIP0084
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})

	_, err := w.NewAccount(ctx, scope, sourceName)
	require.NoError(h, err, "failed to create rename source")
	_, err = w.NewAccount(ctx, scope, duplicateTarget)
	require.NoError(h, err, "failed to create duplicate rename target")

	wantAccounts, err := w.ListAccounts(ctx)
	require.NoError(h, err, "failed to list accounts before rejection")

	// These rejections have no stable public error identity yet, so the
	// rows assert rejection and unchanged state only.
	testCases := []struct {
		name    string
		oldName string
		newName string
	}{
		{
			name:    "duplicate target",
			oldName: sourceName,
			newName: duplicateTarget,
		},
		{
			name:    "empty target",
			oldName: sourceName,
			newName: "",
		},
		{
			name:    "reserved target",
			oldName: sourceName,
			newName: waddrmgr.ImportedAddrAccountName,
		},
		{
			name:    "unknown source",
			oldName: "account manager unknown source",
			newName: "account manager unknown target",
		},
		{
			name:    "reserved source",
			oldName: waddrmgr.ImportedAddrAccountName,
			newName: "account manager reserved source target",
		},
	}

	for _, tc := range testCases {
		err := w.RenameAccount(
			ctx, scope, tc.oldName, tc.newName,
		)

		require.Error(h, err, "%s was accepted", tc.name)

		gotAccounts, err := w.ListAccounts(ctx)
		require.NoError(h, err, "failed to list accounts after rejection")
		require.ElementsMatch(
			h, wantAccounts, gotAccounts, "%s changed the account set", tc.name,
		)
	}
}

// testAccountManagerEnforceAccountRenameLifecycle verifies metadata rename is
// admitted while locked but rejected after the wallet stops.
func testAccountManagerEnforceAccountRenameLifecycle(h *bwtest.HarnessTest) {
	const (
		sourceName  = "account manager lifecycle source"
		lockedName  = "account manager locked rename"
		stoppedName = "account manager stopped rename"
	)

	scope := waddrmgr.KeyScopeBIP0084
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	_, err := w.NewAccount(ctx, scope, sourceName)
	require.NoError(h, err, "failed to create lifecycle source")

	// Reload to reach the started but locked state this rename must be
	// admitted in, not to re-check that the source persisted.
	w = h.ReloadWallet(w)
	source, err := w.GetAccount(ctx, scope, sourceName)
	require.NoError(h, err, "failed to read lifecycle source")

	wantLockedRename := *source
	wantLockedRename.AccountName = lockedName
	wantLockedRename.PublicKey = canonicalAccountKey(
		h, wantLockedRename.PublicKey,
	)

	err = w.RenameAccount(ctx, scope, sourceName, lockedName)

	require.NoError(h, err, "locked wallet rejected metadata rename")
	_, err = w.GetAccount(ctx, scope, sourceName)
	require.Error(h, err, "old locked rename name still resolves")
	locked, err := w.GetAccount(ctx, scope, lockedName)
	require.NoError(h, err, "failed to read locked rename")

	lockedInfo := *locked
	lockedInfo.PublicKey = canonicalAccountKey(h, lockedInfo.PublicKey)
	require.Equal(h, wantLockedRename, lockedInfo)

	w = h.ReloadWallet(w)
	_, err = w.GetAccount(ctx, scope, sourceName)
	require.Error(h, err, "old locked rename name resolves after reload")
	durable, err := w.GetAccount(ctx, scope, lockedName)
	require.NoError(h, err, "failed to read locked rename after reload")

	durableInfo := *durable
	durableInfo.PublicKey = canonicalAccountKey(h, durableInfo.PublicKey)
	require.Equal(h, wantLockedRename, durableInfo)
	require.NoError(h, w.Stop(ctx), "failed to stop wallet")

	err = w.RenameAccount(ctx, scope, lockedName, stoppedName)

	require.ErrorIs(h, err, wallet.ErrStateForbidden)

	// The rejected rename must not move the account, so the source keeps
	// its complete result and the target stays absent across a reopen.
	w = h.ReloadWallet(w)
	_, err = w.GetAccount(ctx, scope, stoppedName)
	require.Error(h, err, "stopped rename created a target account")
	unchanged, err := w.GetAccount(ctx, scope, lockedName)
	require.NoError(h, err, "failed to read source after stopped rename")

	unchangedInfo := *unchanged
	unchangedInfo.PublicKey = canonicalAccountKey(
		h, unchangedInfo.PublicKey,
	)
	require.Equal(h, wantLockedRename, unchangedInfo)
}

// testAccountManagerImportAccount verifies that one XPub import's returned
// view matches an immediate read and survives a wallet reload.
func testAccountManagerImportAccount(h *bwtest.HarnessTest) {
	const (
		existingName = "account manager import existing"
		accountName  = "account manager imported"
	)

	keys := deterministicImportedAccountKeys(h)
	ctx := h.Context()
	w, _ := h.NewWallet(
		bwtest.WalletFixture{
			InitialAccounts: []wallet.WatchOnlyAccount{{
				Scope:                keys.scope,
				XPub:                 keys.otherAccountKey,
				MasterKeyFingerprint: keys.masterKeyFingerprint,
				Name:                 existingName,
				AddrType:             keys.addrType,
			}},
		},
	)

	imported, err := w.ImportAccount(
		ctx, accountName, keys.accountKey, keys.masterKeyFingerprint,
		keys.addrType, false,
	)

	require.NoError(h, err, "failed to import account")
	require.Nil(h, imported.AccountNumber, "imported account has a number")
	require.Equal(h, accountName, imported.AccountName)
	require.True(h, imported.IsImported, "account is not imported")
	require.True(
		h, imported.IsWatchOnly, "imported account is not watch-only",
	)
	require.Zero(h, imported.ExternalKeyCount)
	require.Zero(h, imported.InternalKeyCount)
	require.Zero(h, imported.ImportedKeyCount)
	require.Zero(h, imported.ConfirmedBalance)
	require.Zero(h, imported.UnconfirmedBalance)
	require.NotZero(
		h, imported.CreatedAt, "imported account has no creation time",
	)
	require.Equal(h, keys.scope, imported.KeyScope)
	require.Equal(h, keys.addrType, imported.AddrSchema.ExternalAddrType)
	require.Equal(h, keys.addrType, imported.AddrSchema.InternalAddrType)
	require.Equal(h, []byte(keys.accountKey.String()), imported.PublicKey)
	require.NotNil(
		h, imported.MasterKeyFingerprint,
		"imported account has no master key fingerprint",
	)
	require.Equal(
		h, wallet.MasterFingerprint(keys.masterKeyFingerprint),
		*imported.MasterKeyFingerprint,
	)
	want := *imported
	got, err := w.GetAccount(ctx, keys.scope, accountName)
	require.NoError(h, err, "failed to read imported account")
	require.Equal(h, want, *got)

	w = h.ReloadWallet(w)
	durable, err := w.GetAccount(ctx, keys.scope, accountName)
	require.NoError(h, err, "failed to read imported account after reload")
	require.Equal(h, want, *durable)
}

// testAccountManagerImportAccountZeroFingerprint verifies an import declaring
// a zero master key fingerprint keeps a present-zero identity across the
// mutation result, its lookup, and a wallet reload, rather than collapsing the
// zero value to an absent identity.
func testAccountManagerImportAccountZeroFingerprint(h *bwtest.HarnessTest) {
	const (
		existingName = "account manager zero fingerprint existing"
		accountName  = "account manager zero fingerprint"
	)

	keys := deterministicImportedAccountKeys(h)
	ctx := h.Context()
	w, _ := h.NewWallet(
		bwtest.WalletFixture{
			InitialAccounts: []wallet.WatchOnlyAccount{{
				Scope:                keys.scope,
				XPub:                 keys.otherAccountKey,
				MasterKeyFingerprint: keys.masterKeyFingerprint,
				Name:                 existingName,
				AddrType:             keys.addrType,
			}},
		},
	)

	imported, err := w.ImportAccount(
		ctx, accountName, keys.accountKey, 0, keys.addrType, false,
	)

	require.NoError(h, err, "failed to import zero fingerprint account")
	require.NotNil(
		h, imported.MasterKeyFingerprint,
		"zero fingerprint collapsed to absent on import",
	)
	require.Zero(
		h, *imported.MasterKeyFingerprint,
		"imported fingerprint is not zero",
	)

	want := *imported
	got, err := w.GetAccount(ctx, keys.scope, accountName)
	require.NoError(h, err, "failed to read zero fingerprint account")
	require.NotNil(
		h, got.MasterKeyFingerprint,
		"zero fingerprint collapsed to absent on lookup",
	)
	require.Zero(
		h, *got.MasterKeyFingerprint, "read fingerprint is not zero",
	)
	require.Equal(h, want, *got)

	// The seeded account keeps its non-zero fingerprint, so a present-zero
	// identity is distinguishable from a present-nonzero one in the same
	// wallet rather than from a backend-wide default.
	existing, err := w.GetAccount(ctx, keys.scope, existingName)
	require.NoError(h, err, "failed to read seeded imported account")
	require.NotNil(
		h, existing.MasterKeyFingerprint,
		"seeded account has no master key fingerprint",
	)
	require.Equal(
		h, wallet.MasterFingerprint(keys.masterKeyFingerprint),
		*existing.MasterKeyFingerprint,
	)

	w = h.ReloadWallet(w)
	durable, err := w.GetAccount(ctx, keys.scope, accountName)
	require.NoError(
		h, err, "failed to read zero fingerprint account after reload",
	)
	require.NotNil(
		h, durable.MasterKeyFingerprint,
		"zero fingerprint collapsed to absent after reload",
	)
	require.Zero(
		h, *durable.MasterKeyFingerprint,
		"fingerprint is not zero after reload",
	)
	require.Equal(h, want, *durable)
}

// testAccountManagerPreviewAccountImport verifies a dry run returns portable
// identity fields without materializing an account.
func testAccountManagerPreviewAccountImport(h *bwtest.HarnessTest) {
	const (
		existingName = "account manager preview existing"
		accountName  = "account manager import preview"
	)

	keys := deterministicImportedAccountKeys(h)
	ctx := h.Context()
	w, _ := h.NewWallet(
		bwtest.WalletFixture{
			InitialAccounts: []wallet.WatchOnlyAccount{{
				Scope:                keys.scope,
				XPub:                 keys.otherAccountKey,
				MasterKeyFingerprint: keys.masterKeyFingerprint,
				Name:                 existingName,
				AddrType:             keys.addrType,
			}},
		},
	)

	preview, err := w.ImportAccount(
		ctx, accountName, keys.accountKey, keys.masterKeyFingerprint,
		keys.addrType, true,
	)

	require.NoError(h, err, "failed to preview account import")
	require.Equal(h, accountName, preview.AccountName)
	require.True(h, preview.IsImported, "preview is not imported")
	require.True(h, preview.IsWatchOnly, "preview is not watch-only")
	require.Nil(h, preview.AccountNumber, "preview has an account number")
	require.Equal(h, keys.scope, preview.KeyScope)
	require.Equal(h, []byte(keys.accountKey.String()), preview.PublicKey)
	require.NotNil(
		h, preview.MasterKeyFingerprint,
		"preview account has no master key fingerprint",
	)
	require.Equal(
		h, wallet.MasterFingerprint(keys.masterKeyFingerprint),
		*preview.MasterKeyFingerprint,
	)
	_, err = w.GetAccount(ctx, keys.scope, accountName)
	require.Error(h, err, "preview materialized an account")
}

// testAccountManagerRejectAccountImport verifies rejected imports preserve the
// existing imported account and its scope's account count.
func testAccountManagerRejectAccountImport(h *bwtest.HarnessTest) {
	const existingName = "account manager existing import"

	keys := deterministicImportedAccountKeys(h)
	ctx := h.Context()
	w, _ := h.NewWallet(
		bwtest.WalletFixture{
			InitialAccounts: []wallet.WatchOnlyAccount{{
				Scope:                keys.scope,
				XPub:                 keys.accountKey,
				MasterKeyFingerprint: keys.masterKeyFingerprint,
				Name:                 existingName,
				AddrType:             keys.addrType,
			}},
		},
	)

	wantAccounts, err := w.ListAccounts(ctx)
	require.NoError(h, err, "failed to list accounts before rejection")

	testCases := []struct {
		name        string
		accountName string
		accountKey  *hdkeychain.ExtendedKey
	}{
		// Both rows collide on name only. Rejecting a colliding XPub
		// under a fresh name is a separate contract the wallet does
		// not implement yet.
		{
			name:        "duplicate name, same key",
			accountName: existingName,
			accountKey:  keys.accountKey,
		},
		{
			name:        "duplicate name, other key",
			accountName: existingName,
			accountKey:  keys.otherAccountKey,
		},
		{
			name:        "empty name",
			accountName: "",
			accountKey:  keys.otherAccountKey,
		},
	}

	for _, tc := range testCases {
		_, err := w.ImportAccount(
			ctx, tc.accountName, tc.accountKey, keys.masterKeyFingerprint,
			keys.addrType, false,
		)

		require.Error(h, err, "%s was accepted", tc.name)

		gotAccounts, err := w.ListAccounts(ctx)
		require.NoError(h, err, "failed to list accounts after rejection")
		require.ElementsMatch(
			h, wantAccounts, gotAccounts, "%s changed the account set", tc.name,
		)
	}
}

// testAccountManagerRejectInvalidImportKey verifies invalid import keys are
// rejected without changing the account set.
func testAccountManagerRejectInvalidImportKey(h *bwtest.HarnessTest) {
	const existingName = "account manager existing import"

	keys := deterministicImportedAccountKeys(h)
	ctx := h.Context()
	w, _ := h.NewWallet(
		bwtest.WalletFixture{
			InitialAccounts: []wallet.WatchOnlyAccount{{
				Scope:                keys.scope,
				XPub:                 keys.accountKey,
				MasterKeyFingerprint: keys.masterKeyFingerprint,
				Name:                 existingName,
				AddrType:             keys.addrType,
			}},
		},
	)

	wantAccounts, err := w.ListAccounts(ctx)
	require.NoError(h, err, "failed to list accounts before rejection")

	testCases := []struct {
		name        string
		accountName string
		accountKey  *hdkeychain.ExtendedKey
	}{
		{
			name:        "nil key",
			accountName: "account manager nil key",
			accountKey:  nil,
		},
		{
			name:        "private key",
			accountName: "account manager private key",
			accountKey:  keys.accountPrivateKey,
		},
	}

	for _, tc := range testCases {
		_, err := w.ImportAccount(
			ctx, tc.accountName, tc.accountKey, keys.masterKeyFingerprint,
			keys.addrType, false,
		)

		require.ErrorIs(h, err, wallet.ErrInvalidAccountKey)

		gotAccounts, err := w.ListAccounts(ctx)
		require.NoError(
			h, err, "failed to list accounts after rejection",
		)
		require.ElementsMatch(
			h, wantAccounts, gotAccounts, "%s changed the account set", tc.name,
		)
	}
}

// testAccountManagerEnforceAccountImportLifecycle verifies that a stopped
// watch-only wallet rejects an otherwise valid account import.
func testAccountManagerEnforceAccountImportLifecycle(h *bwtest.HarnessTest) {
	const accountName = "account manager stopped import"

	keys := deterministicImportedAccountKeys(h)
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})

	accounts, err := w.ListAccounts(ctx)
	require.NoError(h, err, "failed to list accounts before rejection")

	wantCount := len(accounts)

	require.NoError(h, w.Stop(ctx), "failed to stop wallet")

	_, err = w.ImportAccount(
		ctx, accountName, keys.accountKey, keys.masterKeyFingerprint,
		keys.addrType, false,
	)

	require.ErrorIs(h, err, wallet.ErrStateForbidden)

	// A rejected import must leave no partial account, so the target stays
	// absent across a reopen and the account set is unchanged.
	w = h.ReloadWallet(w)
	_, err = w.GetAccount(ctx, keys.scope, accountName)
	require.Error(h, err, "stopped import created an account")

	accounts, err = w.ListAccounts(ctx)
	require.NoError(h, err, "failed to list accounts after rejection")
	require.Len(h, accounts, wantCount, "rejection changed account count")
}
