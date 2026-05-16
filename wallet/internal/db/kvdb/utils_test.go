package kvdb

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

const defaultDBTimeout = 10 * time.Second

var errTestAccountNotFound = errors.New("test account not found")

// newTestDB creates a temporary bdb walletdb for kvdb store tests.
//
// It returns the opened database and a cleanup function that must be called
// after the test completes.
func newTestDB(t *testing.T) (walletdb.DB, func()) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "wallet.db")

	dbConn, err := walletdb.Create(
		"bdb", dbPath, true, defaultDBTimeout, false,
	)
	require.NoError(t, err)

	cleanup := func() {
		_ = dbConn.Close()
	}

	return dbConn, cleanup
}

// newTxStore initializes and opens a wtxmgr store in the test database.
//
// NOTE: The kvdb Store under test expects the walletdb top-level bucket key
// `wtxmgrNamespaceKey` to exist and contain a valid wtxmgr store.
func newTxStore(t *testing.T, dbConn walletdb.DB) *wtxmgr.Store {
	t.Helper()

	var txStore *wtxmgr.Store

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			return err
		}

		err = wtxmgr.Create(ns)
		if err != nil {
			return err
		}

		txStore, err = wtxmgr.Open(ns, &chaincfg.RegressionNetParams)

		return err
	})
	require.NoError(t, err)

	return txStore
}

// newAddrmgrNamespace creates the top-level waddrmgr bucket expected by kvdb
// address-related tests.
func newAddrmgrNamespace(t *testing.T, dbConn walletdb.DB) {
	t.Helper()

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		_, err := tx.CreateTopLevelBucket(waddrmgr.NamespaceKey)
		return err
	})
	require.NoError(t, err)
}

// testLegacyAddrStore is a narrow legacy address-manager test double.
type testLegacyAddrStore struct {
	chainParams   *chaincfg.Params
	currentHeight int32
	accountByAddr map[string]uint32
}

// ActiveScopedKeyManagers returns no scoped managers for this test double.
func (s *testLegacyAddrStore) ActiveScopedKeyManagers() []waddrmgr.AccountStore { //nolint:lll
	return nil
}

// Address fails legacy address lookup for this test double.
func (s *testLegacyAddrStore) Address(_ walletdb.ReadBucket,
	_ btcutil.Address) (waddrmgr.ManagedAddress, error) {

	return nil, errTestAccountNotFound
}

// AddrAccount returns the test account number for the requested address.
func (s *testLegacyAddrStore) AddrAccount(_ walletdb.ReadBucket,
	addr btcutil.Address) (waddrmgr.AccountStore, uint32, error) {

	account, ok := s.accountByAddr[addr.String()]
	if !ok {
		return nil, 0, errTestAccountNotFound
	}

	return nil, account, nil
}

// Birthday returns the zero birthday for this test double.
func (s *testLegacyAddrStore) Birthday() time.Time {
	return time.Time{}
}

// BirthdayBlock returns no verified birthday block for this test double.
func (s *testLegacyAddrStore) BirthdayBlock(
	_ walletdb.ReadBucket) (waddrmgr.BlockStamp, bool, error) {

	return waddrmgr.BlockStamp{}, false, nil
}

// BlockHash fails block-hash lookup for this test double.
func (s *testLegacyAddrStore) BlockHash(_ walletdb.ReadBucket,
	_ int32) (*chainhash.Hash, error) {

	return nil, errTestAccountNotFound
}

// ChangePassphrase accepts passphrase updates for this test double.
func (s *testLegacyAddrStore) ChangePassphrase(_ walletdb.ReadWriteBucket,
	_, _ []byte, _ bool, _ *waddrmgr.ScryptOptions) error {

	return nil
}

// ChainParams returns the chain parameters for this test double.
func (s *testLegacyAddrStore) ChainParams() *chaincfg.Params {
	return s.chainParams
}

// Decrypt returns the input unchanged for tests that do not inspect secrets.
func (s *testLegacyAddrStore) Decrypt(_ waddrmgr.CryptoKeyType,
	in []byte) ([]byte, error) {

	return in, nil
}

// MarkUsed accepts address-used updates for this test double.
func (s *testLegacyAddrStore) MarkUsed(_ walletdb.ReadWriteBucket,
	_ btcutil.Address) error {

	return nil
}

// NewScopedKeyManager fails scoped manager creation for this test double.
func (s *testLegacyAddrStore) NewScopedKeyManager(
	_ walletdb.ReadWriteBucket, _ waddrmgr.KeyScope,
	_ waddrmgr.ScopeAddrSchema) (waddrmgr.AccountStore, error) {

	return nil, errTestAccountNotFound
}

// FetchScopedKeyManager fails scoped manager lookup for this test double.
func (s *testLegacyAddrStore) FetchScopedKeyManager(
	_ waddrmgr.KeyScope) (waddrmgr.AccountStore, error) {

	return nil, errTestAccountNotFound
}

// SetBirthday accepts birthday updates for this test double.
func (s *testLegacyAddrStore) SetBirthday(_ walletdb.ReadWriteBucket,
	_ time.Time) error {

	return nil
}

// SetBirthdayBlock accepts birthday-block updates for this test double.
func (s *testLegacyAddrStore) SetBirthdayBlock(_ walletdb.ReadWriteBucket,
	_ waddrmgr.BlockStamp, _ bool) error {

	return nil
}

// SetSyncedTo records the sync height for this test double.
func (s *testLegacyAddrStore) SetSyncedTo(_ walletdb.ReadWriteBucket,
	bs *waddrmgr.BlockStamp) error {

	if bs != nil {
		s.currentHeight = bs.Height
	}

	return nil
}

// SyncedTo returns the current test sync height.
func (s *testLegacyAddrStore) SyncedTo() waddrmgr.BlockStamp {
	return waddrmgr.BlockStamp{Height: s.currentHeight}
}

// Unlock accepts private-key unlocks for this test double.
func (s *testLegacyAddrStore) Unlock(_ walletdb.ReadBucket,
	_ []byte) error {

	return nil
}

// AddressDetails is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testLegacyAddrStore) AddressDetails(_ walletdb.ReadBucket,
	_ btcutil.Address) (bool, string, waddrmgr.AddressType) {

	return false, "", 0
}

// ConvertToWatchingOnly is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testLegacyAddrStore) ConvertToWatchingOnly(
	_ walletdb.ReadWriteBucket) error {

	return nil
}

// Close is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testLegacyAddrStore) Close() {}

// EncryptedMasterHDPriv is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testLegacyAddrStore) EncryptedMasterHDPriv(
	_ walletdb.ReadBucket) ([]byte, error) {

	return nil, nil
}

// MasterHDPubKey is a no-op stub for the waddrmgr.AddrStore interface.
// Tests that exercise derived-account fingerprint resolution should
// override this on a per-test basis with a valid serialized extended
// public key.
func (s *testLegacyAddrStore) MasterHDPubKey(
	_ walletdb.ReadBucket) ([]byte, error) {

	return nil, nil
}

// ForEachAccountAddress is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testLegacyAddrStore) ForEachAccountAddress(_ walletdb.ReadBucket,
	_ uint32, _ func(waddrmgr.ManagedAddress) error) error {

	return nil
}

// ForEachActiveAddress is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testLegacyAddrStore) ForEachActiveAddress(_ walletdb.ReadBucket,
	_ func(btcutil.Address) error) error {

	return nil
}

// ForEachRelevantActiveAddress is a no-op stub for the waddrmgr.AddrStore
// interface.
func (s *testLegacyAddrStore) ForEachRelevantActiveAddress(
	_ walletdb.ReadBucket, _ func(btcutil.Address) error) error {

	return nil
}

// IsLocked is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testLegacyAddrStore) IsLocked() bool { return false }

// IsWatchOnlyAccount is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testLegacyAddrStore) IsWatchOnlyAccount(_ walletdb.ReadBucket,
	_ waddrmgr.KeyScope, _ uint32) (bool, error) {

	return false, nil
}

// Lock is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testLegacyAddrStore) Lock() error { return nil }

// LookupAccount is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testLegacyAddrStore) LookupAccount(_ walletdb.ReadBucket,
	_ string) (waddrmgr.KeyScope, uint32, error) {

	return waddrmgr.KeyScope{}, 0, nil
}

// WatchOnly is a no-op stub for the waddrmgr.AddrStore interface.
func (s *testLegacyAddrStore) WatchOnly() bool { return false }

// newTestAddressScript returns a test address and its payment script.
func newTestAddressScript(t *testing.T) (btcutil.Address, []byte) {
	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	addr, err := btcutil.NewAddressPubKey(
		privKey.PubKey().SerializeCompressed(), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return addr, pkScript
}
