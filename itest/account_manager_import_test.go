//go:build itest

package itest

import (
	"bytes"
	"encoding/binary"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/netparams"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// importAccountExpectation records the published identity of an imported
// account so the same values can be re-asserted through every read surface and
// across a reload.
type importAccountExpectation struct {
	name        string
	publicKey   []byte
	fingerprint uint32
}

// testAccountManagerImportAccount verifies deterministic BIP84 account import
// validation, dry-run rollback, persisted metadata, and reload durability.
func testAccountManagerImportAccount(h *bwtest.HarnessTest) {
	const (
		initialName   = "account manager initial import"
		candidateName = "account manager imported"
	)

	// The wallet is seeded with one account key and the import runs with
	// another. Requiring the two to differ is what makes a later match on the
	// imported key meaningful: if they were the same, every key assertion
	// below would also pass against the seeded account.
	keys := deterministicImportAccountKeys(h)
	require.NotEqual(h, keys.initial.String(), keys.candidate.String())
	expected := importAccountExpectation{
		name:        candidateName,
		publicKey:   bytes.Clone([]byte(keys.candidate.String())),
		fingerprint: keys.fingerprint,
	}
	ctx := h.Context()
	cfg, params := h.TestWalletConfig()

	// An xpub-only account belongs in a watch-only wallet, so the import runs
	// against a watch-only shell; what a spendable wallet does with the same
	// call is pinned separately by testAccountManagerImportSpendable.
	//
	// Override the harness defaults instead of building params from
	// scratch. Creation must present the same passphrases cfg carries,
	// because that is what a later Load offers; kvdb validates the master
	// public key against them, so a params struct built field by field
	// fails the reload rather than the create.
	params.Mode = wallet.ModeShell
	params.WatchOnly = true
	params.InitialAccounts = []wallet.WatchOnlyAccount{
		{
			Scope:                waddrmgr.KeyScopeBIP0084,
			XPub:                 keys.initial,
			MasterKeyFingerprint: keys.fingerprint,
			Name:                 initialName,
			AddrType:             waddrmgr.WitnessPubKey,
		},
	}

	manager := h.NewWalletManager()
	w, err := manager.Create(cfg, params)
	require.NoError(h, err, "failed to create watch-only shell wallet")
	h.RegisterWallet(w)
	require.NoError(h, w.Start(ctx), "failed to start watch-only shell wallet")

	// A dry run has to answer with the row a real import would publish,
	// otherwise it is useless as a preview. The same fields are therefore
	// asserted here and again after the persisting import below, and the two
	// results have to agree.
	dryRun, err := w.ImportAccount(
		ctx, expected.name, keys.candidate, expected.fingerprint,
		waddrmgr.WitnessPubKey, true,
	)
	require.NoError(h, err, "failed to dry-run account import")
	require.NotNil(h, dryRun, "dry-run import returned no account")
	require.Equal(h, expected.name, dryRun.AccountName)
	require.Equal(
		h, waddrmgr.KeyScopeBIP0084, waddrmgr.KeyScope(dryRun.KeyScope),
	)
	require.True(h, dryRun.IsImported)
	require.True(h, dryRun.IsWatchOnly)
	require.Nil(h, dryRun.AccountNumber)
	require.Equal(h, expected.publicKey, dryRun.PublicKey)
	require.Equal(h, expected.fingerprint, dryRun.MasterKeyFingerprint)

	// The dry run validated through the store, so its transaction has to have
	// been rolled back: neither the scoped get nor a name lookup may resolve
	// the account it previewed.
	_, err = w.GetAccount(ctx, waddrmgr.KeyScopeBIP0084, expected.name)
	require.Error(h, err, "dry-run account remained queryable")
	requireAccountManagerNameAbsent(
		h, w, expected.name, "dry-run account import",
	)

	// The same import without the dry-run flag must now publish the account,
	// which also proves the dry run left the name free to be taken.
	persisted, err := w.ImportAccount(
		ctx, expected.name, keys.candidate, expected.fingerprint,
		waddrmgr.WitnessPubKey, false,
	)
	require.NoError(h, err, "failed to persist account import")
	require.NotNil(h, persisted, "persisted import returned no account")
	require.Equal(h, expected.name, persisted.AccountName)
	require.Equal(
		h, waddrmgr.KeyScopeBIP0084, waddrmgr.KeyScope(persisted.KeyScope),
	)
	require.True(h, persisted.IsImported)
	require.True(h, persisted.IsWatchOnly)
	require.Nil(h, persisted.AccountNumber)
	require.Equal(h, expected.publicKey, persisted.PublicKey)
	require.Equal(h, expected.fingerprint, persisted.MasterKeyFingerprint)
	requireImportedAccountState(h, w, expected)

	// Everything asserted so far could have been served from memory, so the
	// wallet is rebuilt from its durable state and the same read surfaces are
	// required to report the identical row.
	reloaded := reloadAccountManagerWallet(h, cfg, manager, w)

	requireImportedAccountState(h, reloaded, expected)

	// One key per rule the account key validation enforces. Each has to be
	// rejected as ErrInvalidAccountKey rather than by some incidental failure,
	// and must leave no row behind under the name it was offered with.
	invalidKeys := []struct {
		name string
		key  *hdkeychain.ExtendedKey
	}{
		{name: "account manager import nil", key: nil},
		{name: "account manager import private", key: keys.private},
		{name: "account manager import wrong depth", key: keys.wrongDepth},
		{
			name: "account manager import non hardened",
			key:  keys.nonHardenedAccount,
		},
		{
			name: "account manager import wrong network",
			key:  keys.wrongNetwork,
		},
	}
	for _, invalid := range invalidKeys {
		_, err = reloaded.ImportAccount(
			ctx, invalid.name, invalid.key, keys.fingerprint,
			waddrmgr.WitnessPubKey, false,
		)
		require.ErrorIsf(
			h, err, wallet.ErrInvalidAccountKey,
			"import of %q was not rejected as an invalid key", invalid.name,
		)
		requireAccountManagerNameAbsent(h, reloaded, invalid.name, invalid.name)
	}

	// Names stay unique within the derived scope across a reload, so replaying
	// the successful import must now fail. The rejection may not disturb the
	// account already published under that name either.
	_, err = reloaded.ImportAccount(
		ctx, expected.name, keys.candidate, expected.fingerprint,
		waddrmgr.WitnessPubKey, false,
	)
	require.Error(h, err, "duplicate persisted account name was accepted")
	requireImportedAccountState(h, reloaded, expected)
}

// requireImportedAccountState verifies the imported account through every
// public read surface without relying on internal AccountInfo types or
// ordering.
func requireImportedAccountState(h *bwtest.HarnessTest, w *wallet.Wallet,
	expected importAccountExpectation) {

	h.Helper()

	account, err := w.GetAccount(
		h.Context(), waddrmgr.KeyScopeBIP0084, expected.name,
	)
	require.NoError(h, err, "failed to get imported account")
	require.NotNil(h, account, "get returned no imported account row")
	require.Equal(h, expected.name, account.AccountName)
	require.Equal(
		h, waddrmgr.KeyScopeBIP0084, waddrmgr.KeyScope(account.KeyScope),
	)
	require.True(h, account.IsImported)
	require.True(h, account.IsWatchOnly)
	require.Nil(h, account.AccountNumber)
	// Imported xpubs are compared by raw bytes to prove exact serialized
	// round-trip persistence of the caller-supplied key, not EC identity.
	require.Equal(h, expected.publicKey, account.PublicKey)
	require.Equal(h, expected.fingerprint, account.MasterKeyFingerprint)

	named, err := w.ListAccountsByName(h.Context(), expected.name)
	require.NoError(h, err, "failed to list imported account by name")
	require.Len(h, named, 1)
	require.Equal(h, expected.name, named[0].AccountName)
	require.Equal(
		h, waddrmgr.KeyScopeBIP0084, waddrmgr.KeyScope(named[0].KeyScope),
	)
	require.True(h, named[0].IsImported)
	require.True(h, named[0].IsWatchOnly)
	require.Nil(h, named[0].AccountNumber)
	require.Equal(h, expected.publicKey, named[0].PublicKey)
	require.Equal(h, expected.fingerprint, named[0].MasterKeyFingerprint)

	scoped, err := w.ListAccountsByScope(h.Context(), waddrmgr.KeyScopeBIP0084)
	require.NoError(h, err, "failed to list imported account by scope")

	foundScoped := false
	for _, account := range scoped {
		if account.AccountName == expected.name &&
			waddrmgr.KeyScope(account.KeyScope) == waddrmgr.KeyScopeBIP0084 {

			require.True(h, account.IsImported)
			require.True(h, account.IsWatchOnly)
			require.Nil(h, account.AccountNumber)
			require.Equal(h, expected.publicKey, account.PublicKey)
			require.Equal(h, expected.fingerprint, account.MasterKeyFingerprint)

			foundScoped = true

			break
		}
	}

	require.True(
		h, foundScoped, "imported account %q was not listed by scope",
		expected.name,
	)

	accounts, err := w.ListAccounts(h.Context())
	require.NoError(h, err, "failed to list imported account")

	found := false
	for _, account := range accounts {
		if account.AccountName == expected.name &&
			waddrmgr.KeyScope(account.KeyScope) == waddrmgr.KeyScopeBIP0084 {

			require.True(h, account.IsImported)
			require.True(h, account.IsWatchOnly)
			require.Nil(h, account.AccountNumber)
			require.Equal(h, expected.publicKey, account.PublicKey)
			require.Equal(h, expected.fingerprint, account.MasterKeyFingerprint)

			found = true

			break
		}
	}

	require.True(h, found, "imported account %q was not listed", expected.name)
}

// importAccountKeys holds the deterministic account keys the import cases run
// against: two keys a valid import must accept, and one key per rejection the
// account key validation is required to make.
type importAccountKeys struct {
	initial            *hdkeychain.ExtendedKey
	candidate          *hdkeychain.ExtendedKey
	private            *hdkeychain.ExtendedKey
	wrongDepth         *hdkeychain.ExtendedKey
	nonHardenedAccount *hdkeychain.ExtendedKey
	wrongNetwork       *hdkeychain.ExtendedKey
	fingerprint        uint32
}

// deterministicImportAccountKeys derives fixed account keys and clones their
// public forms to the BIP84 version accepted by the harness network.
func deterministicImportAccountKeys(h *bwtest.HarnessTest) importAccountKeys {
	h.Helper()

	seed := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	root, err := hdkeychain.NewMaster(seed, h.NetParams())
	require.NoError(h, err, "failed to derive deterministic root")
	rootPub, err := root.ECPubKey()
	require.NoError(h, err, "failed to get deterministic root public key")

	fingerprint := binary.BigEndian.Uint32(
		address.Hash160(rootPub.SerializeCompressed())[:4],
	)

	purpose, err := root.Derive(hdkeychain.HardenedKeyStart + 84)
	require.NoError(h, err, "failed to derive BIP84 purpose key")
	coinType, err := purpose.Derive(
		hdkeychain.HardenedKeyStart + h.NetParams().HDCoinType,
	)
	require.NoError(h, err, "failed to derive BIP84 coin-type key")
	initial, err := coinType.Derive(hdkeychain.HardenedKeyStart)
	require.NoError(h, err, "failed to derive initial account key")
	candidate, err := coinType.Derive(hdkeychain.HardenedKeyStart + 1)
	require.NoError(h, err, "failed to derive candidate account key")
	nonHardened, err := coinType.Derive(1)
	require.NoError(h, err, "failed to derive non-hardened account key")

	versions := harnessHDVersions(h)
	initialPub := cloneAccountPublicKey(h, initial, versions.bip84)
	candidatePub := cloneAccountPublicKey(h, candidate, versions.bip84)
	wrongDepth := cloneAccountPublicKey(h, coinType, versions.bip84)
	nonHardenedPub := cloneAccountPublicKey(h, nonHardened, versions.bip84)
	wrongNetwork := cloneAccountPublicKey(h, candidate, versions.rejected)

	return importAccountKeys{
		initial:            initialPub,
		candidate:          candidatePub,
		private:            candidate,
		wrongDepth:         wrongDepth,
		nonHardenedAccount: nonHardenedPub,
		wrongNetwork:       wrongNetwork,
		fingerprint:        fingerprint,
	}
}

// cloneAccountPublicKey neuters key and changes its serialized version.
func cloneAccountPublicKey(h *bwtest.HarnessTest, key *hdkeychain.ExtendedKey,
	version [4]byte) *hdkeychain.ExtendedKey {

	h.Helper()

	pub, err := key.Neuter()
	require.NoError(h, err, "failed to neuter deterministic account key")
	pub, err = pub.CloneWithVersion(version[:])
	require.NoError(h, err, "failed to clone deterministic account public key")

	return pub
}

// harnessHDVersionSet holds the serialized account-level HD versions the
// harness network accepts, plus one it deliberately rejects.
type harnessHDVersionSet struct {
	bip44    [4]byte
	bip49    [4]byte
	bip84    [4]byte
	rejected [4]byte
}

// harnessHDVersions returns the SLIP-0132 public versions for the harness
// network.
//
// The values are written out per network rather than derived from the wallet's
// own network check, so that dropping a version from the accepted set in
// production fails these tests instead of changing both sides at once.
func harnessHDVersions(h *bwtest.HarnessTest) harnessHDVersionSet {
	h.Helper()

	var bip44, bip49, bip84, rejected waddrmgr.HDVersion
	switch h.NetParams().Net {
	case wire.MainNet:
		bip44 = waddrmgr.HDVersionMainNetBIP0044
		bip49 = waddrmgr.HDVersionMainNetBIP0049
		bip84 = waddrmgr.HDVersionMainNetBIP0084
		rejected = waddrmgr.HDVersionTestNetBIP0084

	// wire.SigNet covers the default signet magic; SigNetWire additionally
	// resolves a custom signet, whose magic is not a compile-time constant.
	case wire.TestNet, wire.TestNet3, wire.TestNet4, wire.SigNet,
		netparams.SigNetWire(h.NetParams()):
		bip44 = waddrmgr.HDVersionTestNetBIP0044
		bip49 = waddrmgr.HDVersionTestNetBIP0049
		bip84 = waddrmgr.HDVersionTestNetBIP0084
		rejected = waddrmgr.HDVersionMainNetBIP0084

	// simnet has no version set of its own beyond BIP44, so the wallet accepts
	// the mainnet BIP49 and BIP84 versions there.
	case wire.SimNet:
		bip44 = waddrmgr.HDVersionSimNetBIP0044
		bip49 = waddrmgr.HDVersionMainNetBIP0049
		bip84 = waddrmgr.HDVersionMainNetBIP0084
		rejected = waddrmgr.HDVersionTestNetBIP0084

	default:
		h.Fatalf("unsupported harness network %v", h.NetParams().Name)
	}

	var versions harnessHDVersionSet
	binary.BigEndian.PutUint32(versions.bip44[:], uint32(bip44))
	binary.BigEndian.PutUint32(versions.bip49[:], uint32(bip49))
	binary.BigEndian.PutUint32(versions.bip84[:], uint32(bip84))
	binary.BigEndian.PutUint32(versions.rejected[:], uint32(rejected))

	return versions
}
