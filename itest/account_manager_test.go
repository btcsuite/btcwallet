//go:build itest

package itest

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// accountManagerExpectation records the published identity of a derived
// account, which is what every read surface is then required to report for it.
//
// Names are only unique within a key scope, so a row is identified by the name
// and scope together rather than by the name alone.
type accountManagerExpectation struct {
	name      string
	scope     waddrmgr.KeyScope
	publicKey []byte
}

// String identifies an expectation in assertion messages so that a failure
// raised inside a loop over several accounts names the one it came from.
func (e accountManagerExpectation) String() string {
	return fmt.Sprintf("account %q in scope %s", e.name, e.scope)
}

// defaultKeyScopes are the key scopes a wallet initializes on creation. Every
// derived-account case runs against all four so a scope-specific regression,
// such as the taproot schema BIP0086 resolves through its own scope mapping,
// cannot hide behind the two scopes that happen to be exercised elsewhere.
var defaultKeyScopes = []waddrmgr.KeyScope{
	waddrmgr.KeyScopeBIP0044,
	waddrmgr.KeyScopeBIP0049Plus,
	waddrmgr.KeyScopeBIP0084,
	waddrmgr.KeyScopeBIP0086,
}

// testAccountManagerLifecycle verifies derived account creation across every
// default key scope, scope-local names, rename isolation, read results that do
// not depend on lock state, and durable state after a fresh wallet reload.
func testAccountManagerLifecycle(h *bwtest.HarnessTest) {
	const (
		sharedName  = "account manager shared"
		renamedName = "account manager renamed"
	)

	// The rename is applied to one scope only; the others must keep the shared
	// name, which is what proves names are scope-local.
	renameScope := waddrmgr.KeyScopeBIP0084

	cfg, manager, w := newAccountManagerWallet(h)
	ctx := h.Context()

	// One account per default scope, all under the same name. This
	// characterizes the existing scope-local name behavior: a single name can
	// resolve to one public row per scope that uses it.
	created := make([]accountManagerExpectation, 0, len(defaultKeyScopes))
	for _, scope := range defaultKeyScopes {
		expected := accountManagerExpectation{
			name:  sharedName,
			scope: scope,
		}

		account, err := w.NewAccount(ctx, expected.scope, expected.name)
		require.NoErrorf(h, err, "failed to create %s", expected)
		require.NotNilf(h, account, "%s is missing", expected)
		require.Equalf(
			h, expected.name, account.AccountName, "unexpected name for %s",
			expected,
		)
		require.Equalf(
			h, expected.scope, waddrmgr.KeyScope(account.KeyScope),
			"unexpected scope for %s", expected,
		)
		require.NotNilf(
			h, account.AccountNumber, "%s has no account number", expected,
		)
		require.Falsef(
			h, account.IsImported, "%s is reported as imported", expected,
		)
		require.NotEmptyf(
			h, account.PublicKey, "%s has no public key", expected,
		)

		expected.publicKey = bytes.Clone(account.PublicKey)
		created = append(created, expected)
	}

	requireAccountManagerState(h, w, created...)

	// Reads must not depend on whether the private keys are available, so the
	// same queries have to answer identically once the wallet is locked.
	requireAccountManagerLockInvariance(h, w, created...)

	err := w.RenameAccount(ctx, renameScope, sharedName, renamedName)
	require.NoErrorf(
		h, err, "failed to rename the account in scope %s", renameScope,
	)

	renamed := make([]accountManagerExpectation, 0, len(created))
	for _, expected := range created {
		if expected.scope == renameScope {
			expected.name = renamedName
		}

		renamed = append(renamed, expected)
	}

	requireRenamedAccountIsolation(h, w, renameScope, sharedName, created)
	requireAccountManagerState(h, w, renamed...)

	// Both the rename and the untouched scopes have to survive a reload from
	// durable state.
	reloaded := reloadAccountManagerWallet(h, cfg, manager, w)

	requireRenamedAccountIsolation(
		h, reloaded, renameScope, sharedName, created,
	)
	requireAccountManagerState(h, reloaded, renamed...)

	// The freed name must be reusable in the scope it was renamed out of,
	// which is what proves the rename released the name instead of leaving it
	// bound to the account. The reloaded wallet needs its private keys back to
	// derive the replacement.
	require.NoError(h, reloaded.Unlock(ctx, wallet.UnlockRequest{
		Passphrase: []byte(bwtest.TestWalletPrivatePassphrase),
		Timeout:    -1,
	}), "failed to unlock the reloaded wallet")

	reused, err := reloaded.NewAccount(ctx, renameScope, sharedName)
	require.NoErrorf(
		h, err, "the name freed by the rename was not reusable in scope %s",
		renameScope,
	)
	require.NotNil(h, reused, "recreated account is missing")
	require.NotEmpty(h, reused.PublicKey, "recreated account has no public key")

	reusedExpectation := accountManagerExpectation{
		name:      sharedName,
		scope:     renameScope,
		publicKey: bytes.Clone(reused.PublicKey),
	}
	require.NotEqual(
		h, reusedExpectation.publicKey,
		expectationForScope(h, created, renameScope).publicKey,
		"the recreated account reused the renamed account's key",
	)

	final := make([]accountManagerExpectation, 0, len(renamed)+1)
	final = append(final, renamed...)
	final = append(final, reusedExpectation)

	requireAccountManagerState(h, reloaded, final...)

	// The renamed account and its recreated namesake now share a scope, so
	// renaming one onto the other must be rejected: names are unique within a
	// scope even though they are not unique wallet-wide.
	err = reloaded.RenameAccount(ctx, renameScope, renamedName, sharedName)
	require.Error(
		h, err,
		"a rename onto a name already used in the same scope was accepted",
	)

	requireAccountManagerState(h, reloaded, final...)
}

// expectationForScope returns the expectation recorded for a scope.
func expectationForScope(h *bwtest.HarnessTest,
	expectations []accountManagerExpectation,
	scope waddrmgr.KeyScope) accountManagerExpectation {

	h.Helper()

	for _, expected := range expectations {
		if expected.scope == scope {
			return expected
		}
	}

	h.Fatalf("no expectation recorded for scope %s", scope)

	return accountManagerExpectation{}
}

// newAccountManagerWallet creates, registers, starts, and unlocks a wallet for
// AccountManager operations, returning the same manager and config used later
// by the reload assertion.
func newAccountManagerWallet(h *bwtest.HarnessTest) (
	wallet.Config, *wallet.Manager, *wallet.Wallet) {

	h.Helper()

	cfg, params := h.TestWalletConfig()
	manager := h.NewWalletManager()
	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")

	// Register before starting so harness cleanup owns the store if Start
	// fails.
	h.RegisterWallet(w)
	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

	err = w.Unlock(h.Context(), wallet.UnlockRequest{
		Passphrase: []byte(bwtest.TestWalletPrivatePassphrase),
		Timeout:    -1,
	})
	require.NoError(h, err, "failed to unlock wallet")

	return cfg, manager, w
}

// reloadAccountManagerWallet rebuilds a wallet from its durable state and
// returns the started replacement.
//
// The Manager caches published wallets and never evicts on Stop, so loading
// through the original Manager would hand back the very instance that was just
// stopped. Reaching durable state requires closing that Manager and opening a
// new one over the same store. Ownership is released only once each shutdown
// step succeeds, so a failure mid-sequence leaves teardown responsible for the
// resources it already knows about. The replacement Manager is registered with
// the harness, which closes it, so callers only need the wallet.
func reloadAccountManagerWallet(h *bwtest.HarnessTest, cfg wallet.Config,
	manager *wallet.Manager, w *wallet.Wallet) *wallet.Wallet {

	h.Helper()

	ctx := h.Context()

	require.NoError(h, w.Stop(ctx), "failed to stop wallet before reload")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")
	require.NoError(h, manager.Close(), "failed to close wallet manager")
	require.True(h, h.ReleaseManager(manager), "failed to release manager")

	reloaded, err := h.NewWalletManager().Load(cfg)
	require.NoError(h, err, "failed to reload wallet")
	h.RegisterWallet(reloaded)
	require.NotSame(h, w, reloaded, "reload returned the stopped wallet")
	require.NoError(h, reloaded.Start(ctx), "failed to start reloaded wallet")

	return reloaded
}

// requireAccountManagerState exercises every AccountManager get/list surface
// for the expected derived rows without relying on result ordering.
//
// Each surface is checked by its own helper that issues its own query. The
// account row type lives in wallet/internal/db, which this package cannot
// import, so no helper can accept a result slice as a parameter.
func requireAccountManagerState(h *bwtest.HarnessTest, w *wallet.Wallet,
	expectations ...accountManagerExpectation) {

	h.Helper()

	requireDerivedAccountsListed(h, w, expectations)
	requireDerivedAccountsByScope(h, w, expectations)
	requireDerivedAccountsByName(h, w, expectations)
	requireDerivedAccountsByGet(h, w, expectations)
}

// requireDerivedAccountsListed verifies ListAccounts reports every expected
// derived row.
func requireDerivedAccountsListed(h *bwtest.HarnessTest, w *wallet.Wallet,
	expectations []accountManagerExpectation) {

	h.Helper()

	accounts, err := w.ListAccounts(h.Context())
	require.NoError(h, err, "failed to list accounts")

	for _, expected := range expectations {
		found := false

		for _, account := range accounts {
			if account.AccountName != expected.name ||
				waddrmgr.KeyScope(account.KeyScope) != expected.scope {

				continue
			}

			require.NotNilf(
				h, account.AccountNumber, "listed %s has no account number",
				expected,
			)
			require.Falsef(
				h, account.IsImported, "listed %s is reported as imported",
				expected,
			)
			requireDerivedAccountKeyEqual(
				h, expected.publicKey, account.PublicKey, expected.String(),
			)

			found = true

			break
		}

		require.Truef(h, found, "%s was not listed", expected)
	}
}

// requireDerivedAccountsByScope verifies ListAccountsByScope returns only rows
// of the requested scope and includes the expected one.
func requireDerivedAccountsByScope(h *bwtest.HarnessTest, w *wallet.Wallet,
	expectations []accountManagerExpectation) {

	h.Helper()

	for _, expected := range expectations {
		accounts, err := w.ListAccountsByScope(h.Context(), expected.scope)
		require.NoErrorf(
			h, err, "failed to list accounts in scope %s", expected.scope,
		)

		found := false

		for _, account := range accounts {
			require.Equalf(
				h, expected.scope.Purpose, account.KeyScope.Purpose,
				"account %q listed under the wrong scope purpose while "+
					"querying scope %s",
				account.AccountName, expected.scope,
			)
			require.Equalf(
				h, expected.scope.Coin, account.KeyScope.Coin,
				"account %q listed under the wrong scope coin while querying "+
					"scope %s",
				account.AccountName, expected.scope,
			)

			if account.AccountName != expected.name {
				continue
			}

			requireDerivedAccountKeyEqual(
				h, expected.publicKey, account.PublicKey, expected.String(),
			)

			found = true
		}

		require.Truef(h, found, "%s was not listed by scope", expected)
	}
}

// requireDerivedAccountsByName verifies ListAccountsByName resolves each
// expected row under its own name.
//
// Account names are scope-local, so one name legitimately resolves to one row
// per scope that uses it. The expected row count therefore follows how many
// expectations share the name rather than being fixed at one.
func requireDerivedAccountsByName(h *bwtest.HarnessTest, w *wallet.Wallet,
	expectations []accountManagerExpectation) {

	h.Helper()

	for _, expected := range expectations {
		want := 0

		for _, other := range expectations {
			if other.name == expected.name {
				want++
			}
		}

		accounts, err := w.ListAccountsByName(h.Context(), expected.name)
		require.NoErrorf(
			h, err, "failed to list accounts named %q", expected.name,
		)
		require.Lenf(
			h, accounts, want, "unexpected number of accounts named %q",
			expected.name,
		)

		found := false

		for _, account := range accounts {
			if account.AccountName != expected.name ||
				waddrmgr.KeyScope(account.KeyScope) != expected.scope {

				continue
			}

			requireDerivedAccountKeyEqual(
				h, expected.publicKey, account.PublicKey, expected.String(),
			)

			found = true

			break
		}

		require.Truef(h, found, "%s was not listed by name", expected)
	}
}

// requireDerivedAccountsByGet verifies GetAccount resolves each expected row by
// its scope and name.
func requireDerivedAccountsByGet(h *bwtest.HarnessTest, w *wallet.Wallet,
	expectations []accountManagerExpectation) {

	h.Helper()

	for _, expected := range expectations {
		account, err := w.GetAccount(
			h.Context(), expected.scope, expected.name,
		)
		require.NoErrorf(h, err, "failed to get %s", expected)
		require.NotNilf(h, account, "get returned no row for %s", expected)
		require.Equalf(
			h, expected.name, account.AccountName,
			"get returned the wrong name for %s", expected,
		)
		require.Equalf(
			h, expected.scope, waddrmgr.KeyScope(account.KeyScope),
			"get returned the wrong scope for %s", expected,
		)
		require.NotNilf(
			h, account.AccountNumber, "get returned no account number for %s",
			expected,
		)
		require.Falsef(
			h, account.IsImported, "get reports %s as imported", expected,
		)
		requireDerivedAccountKeyEqual(
			h, expected.publicKey, account.PublicKey, expected.String(),
		)
	}
}

// requireRenamedAccountIsolation proves oldName no longer resolves in
// renamedScope while every other scope that shared the name keeps its own row.
//
// original holds the expectations as they were recorded before the rename, so
// the surviving rows are matched against the keys they were created with.
func requireRenamedAccountIsolation(h *bwtest.HarnessTest, w *wallet.Wallet,
	renamedScope waddrmgr.KeyScope, oldName string,
	original []accountManagerExpectation) {

	h.Helper()

	_, err := w.GetAccount(h.Context(), renamedScope, oldName)
	require.Errorf(
		h, err, "the old name %q still resolves in scope %s", oldName,
		renamedScope,
	)

	survivors := make(map[waddrmgr.KeyScope]accountManagerExpectation)
	for _, expected := range original {
		if expected.scope == renamedScope || expected.name != oldName {
			continue
		}

		survivors[expected.scope] = expected
	}

	oldNameAccounts, err := w.ListAccountsByName(h.Context(), oldName)
	require.NoError(h, err, "failed to list the old account name")
	require.Lenf(
		h, oldNameAccounts, len(survivors),
		"the old name %q must resolve only to the scopes it was not renamed "+
			"out of",
		oldName,
	)

	for _, account := range oldNameAccounts {
		scope := waddrmgr.KeyScope(account.KeyScope)

		expected, ok := survivors[scope]
		require.Truef(
			h, ok, "the old name %q resolved in unexpected scope %s", oldName,
			scope,
		)
		require.Equalf(
			h, expected.name, account.AccountName,
			"unexpected name kept for %s", expected,
		)
		requireDerivedAccountKeyEqual(
			h, expected.publicKey, account.PublicKey, expected.String(),
		)
	}
}

// requireAccountManagerLockInvariance verifies the read surfaces answer
// identically before and after locking, then restores the unlocked state.
//
// Account reads are public metadata and must not depend on the availability of
// private key material. The kvdb path is the one at risk here: it assembles
// rows from waddrmgr account properties whose contents vary with lock state,
// which is why the wallet injects its own watch-only and fingerprint values.
// The comparison is order-independent because kvdb assembles ListAccounts from
// its scoped managers and does not return them in a stable order between calls.
func requireAccountManagerLockInvariance(h *bwtest.HarnessTest,
	w *wallet.Wallet, expectations ...accountManagerExpectation) {

	h.Helper()

	ctx := h.Context()

	unlocked, err := w.ListAccounts(ctx)
	require.NoError(h, err, "failed to list accounts while unlocked")

	unlockedKeys := make([]string, 0, len(unlocked))
	for _, account := range unlocked {
		unlockedKeys = append(unlockedKeys, accountRowKey(
			account.AccountName, account.KeyScope.Purpose,
			account.KeyScope.Coin, account.AccountNumber,
			account.IsImported, account.IsWatchOnly,
			account.MasterKeyFingerprint, account.PublicKey,
		))
	}

	require.NoError(h, w.Lock(ctx), "failed to lock wallet")

	locked, err := w.ListAccounts(ctx)
	require.NoError(h, err, "failed to list accounts while locked")

	lockedKeys := make([]string, 0, len(locked))
	for _, account := range locked {
		lockedKeys = append(lockedKeys, accountRowKey(
			account.AccountName, account.KeyScope.Purpose,
			account.KeyScope.Coin, account.AccountNumber,
			account.IsImported, account.IsWatchOnly,
			account.MasterKeyFingerprint, account.PublicKey,
		))
	}

	require.ElementsMatch(
		h, unlockedKeys, lockedKeys,
		"the accounts reported by ListAccounts changed once the wallet was "+
			"locked",
	)

	// Every expectation must still verify in full while locked, which covers
	// the scope, name, and get surfaces too.
	requireAccountManagerState(h, w, expectations...)

	require.NoError(h, w.Unlock(ctx, wallet.UnlockRequest{
		Passphrase: []byte(bwtest.TestWalletPrivatePassphrase),
		Timeout:    -1,
	}), "failed to restore the unlocked wallet")
}

// accountRowKey renders the identifying fields of an account row into a
// comparable string.
//
// The row type lives in wallet/internal/db, which this package cannot import,
// so a whole row cannot be passed to a helper. Callers pass the exported fields
// instead, which keeps result sets comparable without naming the type.
func accountRowKey(name string, purpose, coin uint32, number *uint32,
	imported, watchOnly bool, fingerprint uint32, publicKey []byte) string {

	accountNumber := "none"
	if number != nil {
		accountNumber = strconv.FormatUint(uint64(*number), 10)
	}

	return fmt.Sprintf("%q scope=%d/%d number=%s imported=%t watchOnly=%t "+
		"fingerprint=%d key=%s", name, purpose, coin, accountNumber, imported,
		watchOnly, fingerprint, publicKey)
}

// testAccountManagerContractErrors verifies AccountManager state gates and
// that rejected account mutations — duplicate names, empty names, unknown
// scopes, and missing accounts — leave public account state unchanged. Apart
// from the state gates, which assert wallet.ErrStateForbidden, the cases only
// require rejection, not a specific error classification.
func testAccountManagerContractErrors(h *bwtest.HarnessTest) {
	const (
		preStartName       = "account manager pre-start"
		lockedName         = "account manager locked"
		sourceName         = "account manager source"
		targetName         = "account manager target"
		unknownScopeName   = "account manager unknown scope"
		missingAccountName = "account manager missing"
		missingRenameName  = "account manager missing rename"
		missingRenameNew   = "account manager missing rename target"
	)

	ctx := h.Context()
	cfg, params := h.TestWalletConfig()
	manager := h.NewWalletManager()
	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create wallet")
	h.RegisterWallet(w)

	// Every gated surface, so the table can be replayed against each state that
	// must reject it. A nil import key is intentional: ImportAccount has to
	// reject on state before it reaches extended-key validation.
	gated := []struct {
		operation string
		run       func() error
	}{
		{
			operation: "NewAccount",
			run: func() error {
				_, err := w.NewAccount(
					ctx, waddrmgr.KeyScopeBIP0084, preStartName,
				)

				return err
			},
		},
		{
			operation: "ListAccounts",
			run: func() error {
				_, err := w.ListAccounts(ctx)

				return err
			},
		},
		{
			operation: "ListAccountsByScope",
			run: func() error {
				_, err := w.ListAccountsByScope(
					ctx, waddrmgr.KeyScopeBIP0084,
				)

				return err
			},
		},
		{
			operation: "ListAccountsByName",
			run: func() error {
				_, err := w.ListAccountsByName(ctx, preStartName)

				return err
			},
		},
		{
			operation: "GetAccount",
			run: func() error {
				_, err := w.GetAccount(
					ctx, waddrmgr.KeyScopeBIP0084, preStartName,
				)

				return err
			},
		},
		{
			operation: "RenameAccount",
			run: func() error {
				return w.RenameAccount(
					ctx, waddrmgr.KeyScopeBIP0084, preStartName,
					"account manager renamed",
				)
			},
		},
		{
			operation: "ImportAccount",
			run: func() error {
				_, err := w.ImportAccount(
					ctx, preStartName, nil, 0,
					waddrmgr.WitnessPubKey, false,
				)

				return err
			},
		},
	}

	// The started-state gate must run before operation-specific validation.
	for _, tc := range gated {
		require.ErrorIsf(
			h, tc.run(), wallet.ErrStateForbidden,
			"%s ran before the wallet was started", tc.operation,
		)
	}

	require.NoError(h, w.Start(ctx), "failed to start wallet")

	_, err = w.NewAccount(ctx, waddrmgr.KeyScopeBIP0084, lockedName)
	require.Error(h, err, "locked wallet created an account")
	requireAccountManagerNameAbsent(h, w, lockedName, "locked account creation")

	require.NoError(h, w.Unlock(ctx, wallet.UnlockRequest{
		Passphrase: []byte(bwtest.TestWalletPrivatePassphrase),
		Timeout:    -1,
	}), "failed to unlock wallet")

	scope := waddrmgr.KeyScopeBIP0084
	source := accountManagerExpectation{name: sourceName, scope: scope}
	target := accountManagerExpectation{name: targetName, scope: scope}

	sourceAccount, err := w.NewAccount(ctx, source.scope, source.name)
	require.NoError(h, err, "failed to create source account")
	require.NotNil(h, sourceAccount)
	require.NotEmpty(h, sourceAccount.PublicKey)
	source.publicKey = bytes.Clone(sourceAccount.PublicKey)

	targetAccount, err := w.NewAccount(ctx, target.scope, target.name)
	require.NoError(h, err, "failed to create target account")
	require.NotNil(h, targetAccount)
	require.NotEmpty(h, targetAccount.PublicKey)
	target.publicKey = bytes.Clone(targetAccount.PublicKey)

	requireAccountManagerState(h, w, source, target)

	unknownScope := waddrmgr.KeyScope{Purpose: 999, Coin: 999}

	newAccountRejections := []struct {
		operation   string
		scope       waddrmgr.KeyScope
		name        string
		absentNames []string
	}{
		{
			operation:   "duplicate account name",
			scope:       scope,
			name:        sourceName,
			absentNames: []string{},
		},
		{
			operation:   "empty account name",
			scope:       scope,
			name:        "",
			absentNames: []string{""},
		},
		{
			operation:   "unknown account scope",
			scope:       unknownScope,
			name:        unknownScopeName,
			absentNames: []string{unknownScopeName},
		},
	}
	for _, rejection := range newAccountRejections {
		_, err = w.NewAccount(ctx, rejection.scope, rejection.name)
		require.Errorf(
			h, err, "%s was accepted for scope %s and name %q",
			rejection.operation, rejection.scope, rejection.name,
		)

		for _, absentName := range rejection.absentNames {
			requireAccountManagerNameAbsent(
				h, w, absentName, rejection.operation,
			)
		}

		requireAccountManagerState(h, w, source, target)
	}

	_, err = w.GetAccount(ctx, scope, missingAccountName)
	require.Error(h, err, "missing account lookup succeeded")

	renameAccountRejections := []struct {
		operation   string
		scope       waddrmgr.KeyScope
		source      string
		target      string
		absentNames []string
	}{
		{
			operation:   "missing rename source",
			scope:       scope,
			source:      missingRenameName,
			target:      missingRenameNew,
			absentNames: []string{missingRenameName, missingRenameNew},
		},
		{
			operation:   "empty rename target",
			scope:       scope,
			source:      sourceName,
			target:      "",
			absentNames: []string{""},
		},
		{
			operation:   "rename target collision",
			scope:       scope,
			source:      sourceName,
			target:      targetName,
			absentNames: []string{},
		},
	}
	for _, rejection := range renameAccountRejections {
		err = w.RenameAccount(
			ctx, rejection.scope, rejection.source, rejection.target,
		)
		require.Errorf(
			h, err, "%s was accepted for scope %s from %q to %q",
			rejection.operation, rejection.scope, rejection.source,
			rejection.target,
		)

		for _, absentName := range rejection.absentNames {
			requireAccountManagerNameAbsent(
				h, w, absentName, rejection.operation,
			)
		}

		requireAccountManagerState(h, w, source, target)
	}

	// An unregistered scope has to be rejected on the read path too, not only
	// when creating accounts. Both backends agree on the split asserted here:
	// a scoped list reports no rows rather than failing, while a get for a
	// named account in that scope fails.
	unknownScopeAccounts, err := w.ListAccountsByScope(ctx, unknownScope)
	require.NoError(
		h, err,
		"listing an unregistered scope failed instead of reporting no rows",
	)
	require.Empty(
		h, unknownScopeAccounts, "an unregistered scope reported accounts",
	)

	_, err = w.GetAccount(ctx, unknownScope, sourceName)
	require.Error(h, err, "a get in an unregistered scope succeeded")

	requireAccountManagerState(h, w, source, target)

	// The state gates apply to a stopped wallet whether or not it ever ran, so
	// the same table has to reject every surface again after Stop.
	require.NoError(h, w.Stop(ctx), "failed to stop wallet")

	for _, tc := range gated {
		require.ErrorIsf(
			h, tc.run(), wallet.ErrStateForbidden,
			"%s ran after the wallet was stopped", tc.operation,
		)
	}
}

// requireAccountManagerNameAbsent verifies that no public name lookup returns
// a row for a failed account or rename mutation.
func requireAccountManagerNameAbsent(h *bwtest.HarnessTest, w *wallet.Wallet,
	name, operation string) {

	h.Helper()

	accounts, err := w.ListAccountsByName(h.Context(), name)
	require.NoErrorf(
		h, err, "failed to check absent account name %q after %s", name,
		operation,
	)
	require.Emptyf(
		h, accounts, "account name %q resolves to a row after %s", name,
		operation,
	)
}

// requireDerivedAccountKeyEqual compares two serialized derived account keys
// in full: depth, parent fingerprint, child index, chain code, and key data
// all have to match. Only the four HD version bytes are normalized away,
// because that prefix is backend dependent and does not change key identity.
// Comparing the bare EC public key instead would accept keys that share a
// curve point but derive different children through a different chain code.
//
// owner names the account under comparison so a failure inside a loop over
// several accounts identifies which one mismatched.
func requireDerivedAccountKeyEqual(h *bwtest.HarnessTest,
	expected, actual []byte, owner string) {

	h.Helper()

	expectedKey := parseDerivedAccountKey(h, expected, "expected", owner)
	actualKey := parseDerivedAccountKey(h, actual, "actual", owner)

	normalized, err := actualKey.CloneWithVersion(expectedKey.Version())
	require.NoErrorf(
		h, err, "failed to normalize actual derived account key for %s", owner,
	)

	require.Equalf(
		h, expectedKey.String(), normalized.String(),
		"derived account key mismatch for %s", owner,
	)
}

// parseDerivedAccountKey decodes a serialized derived account key and requires
// that it is a public extended key, so a leaked private key can never satisfy
// a derived account comparison.
func parseDerivedAccountKey(h *bwtest.HarnessTest, serialized []byte,
	role, owner string) *hdkeychain.ExtendedKey {

	h.Helper()

	key, err := hdkeychain.NewKeyFromString(string(serialized))
	require.NoErrorf(
		h, err, "failed to parse %s derived account key for %s", role, owner,
	)
	require.Falsef(
		h, key.IsPrivate(), "%s derived account key for %s is not a public key",
		role, owner,
	)

	return key
}
