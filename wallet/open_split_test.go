package wallet

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	storesqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	"github.com/stretchr/testify/require"
)

// openSplitBoundaryStore records whether snapshot capture returned an error
// from inside the delegated Store callback.
type openSplitBoundaryStore struct {
	// Store delegates the underlying transaction execution.
	walletstore.Store

	wrap       func(walletstore.ReadTx) walletstore.ReadTx
	bodyErrors []error
	viewExited bool
}

// View records callback results and marks the transaction exited only after
// the delegated Store returns.
func (s *openSplitBoundaryStore) View(ctx context.Context,
	body func(walletstore.ReadTx) error, reset func()) error {

	err := s.Store.View(ctx, func(tx walletstore.ReadTx) error {
		if s.wrap != nil {
			tx = s.wrap(tx)
		}

		bodyErr := body(tx)
		s.bodyErrors = append(s.bodyErrors, bodyErr)

		return bodyErr
	}, reset)
	s.viewExited = true

	return err
}

// openSplitReadTx replaces the address read surface for one Store attempt.
type openSplitReadTx struct {
	// ReadTx delegates transaction-manager reads.
	walletstore.ReadTx

	addr walletstore.AddrReadStore
}

// Addr returns the test-controlled address-manager read surface.
//
//nolint:ireturn // The test wrapper implements the transaction contract.
func (t *openSplitReadTx) Addr() walletstore.AddrReadStore {
	return t.addr
}

// openSplitAddressStore can corrupt or fail active-address reads for one scope.
type openSplitAddressStore struct {
	// AddrReadStore delegates address reads not overridden by the fixture.
	walletstore.AddrReadStore

	scope       waddrmgr.KeyScope
	failure     error
	malformed   bool
	matchedRead bool
}

// ActiveAddresses delegates one scope read before optionally failing or
// removing required chain-address metadata.
func (s *openSplitAddressStore) ActiveAddresses(
	scope waddrmgr.KeyScope) ([]waddrmgr.AddressState, error) {

	states, err := s.AddrReadStore.ActiveAddresses(scope)
	if err != nil || scope != s.scope {
		return states, err
	}
	s.matchedRead = true

	if s.failure != nil {
		return nil, s.failure
	}
	if !s.malformed {
		return states, nil
	}

	for i := range states {
		if states[i].Type == waddrmgr.AddressChain {
			states[i].Branch = nil
			return states, nil
		}
	}

	return nil, errors.New("chain address fixture not found")
}

// openSplitRetryStore simulates a Store retry after a late snapshot read
// failure and records reset behavior for both attempts.
type openSplitRetryStore struct {
	// Store delegates the underlying transaction execution.
	walletstore.Store

	scope      waddrmgr.KeyScope
	failure    error
	bodyErrors []error
	resets     int
}

// View runs one failing snapshot attempt followed by one successful attempt in
// the same real read transaction.
func (s *openSplitRetryStore) View(ctx context.Context,
	body func(walletstore.ReadTx) error, reset func()) error {

	return s.Store.View(ctx, func(tx walletstore.ReadTx) error {
		resetAttempt := func() {
			s.resets++
			if reset != nil {
				reset()
			}
		}

		resetAttempt()
		failingAddr := &openSplitAddressStore{
			AddrReadStore: tx.Addr(),
			scope:         s.scope,
			failure:       s.failure,
		}
		firstErr := body(&openSplitReadTx{
			ReadTx: tx,
			addr:   failingAddr,
		})
		s.bodyErrors = append(s.bodyErrors, firstErr)
		if !errors.Is(firstErr, s.failure) {
			return firstErr
		}

		resetAttempt()
		secondErr := body(tx)
		s.bodyErrors = append(s.bodyErrors, secondErr)

		return secondErr
	}, nil)
}

// newOpenSplitStore creates a wallet with one active chain address and returns
// its caller-owned SQLite Store after unloading the initial wallet.
//
//nolint:ireturn // The test helper intentionally hides the concrete backend.
func newOpenSplitStore(t *testing.T) walletstore.Store {
	t.Helper()

	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: filepath.Join(t.TempDir(), "wallet.sqlite"),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})
	require.NoError(t, storesqlite.ApplyMigrations(conn))

	store := dbsqlite.NewNamedStore(conn, "open-split")
	loader, err := NewLoaderWithStore(&chaincfg.TestNet3Params, 0, store)
	require.NoError(t, err)

	wallet, err := loader.CreateNewWallet(
		[]byte("public-pass"), []byte("private-pass"), nil,
		time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	wallet.chainClient = &mockChainClient{}
	_, err = wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	require.NoError(t, loader.UnloadWallet())

	return store
}

// TestStoreOpenReconstructsAfterView verifies passphrase checking and malformed
// address validation occur only after the Store callback has returned.
func TestStoreOpenReconstructsAfterView(t *testing.T) {
	store := newOpenSplitStore(t)

	wrongPassStore := &openSplitBoundaryStore{Store: store}
	wallet, err := OpenFromStore(
		wrongPassStore, []byte("wrong-pass"), &chaincfg.TestNet3Params, 0,
		defaultSyncRetryInterval,
	)
	require.Nil(t, wallet)
	require.True(t, wrongPassStore.viewExited)
	require.Equal(t, []error{nil}, wrongPassStore.bodyErrors)
	require.True(t, waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase))

	malformedAddr := &openSplitAddressStore{
		scope:     waddrmgr.KeyScopeBIP0084,
		malformed: true,
	}
	malformedStore := &openSplitBoundaryStore{
		Store: store,
		wrap: func(tx walletstore.ReadTx) walletstore.ReadTx {
			malformedAddr.AddrReadStore = tx.Addr()
			return &openSplitReadTx{
				ReadTx: tx,
				addr:   malformedAddr,
			}
		},
	}
	wallet, err = OpenFromStore(
		malformedStore, []byte("public-pass"),
		&chaincfg.TestNet3Params, 0, defaultSyncRetryInterval,
	)
	require.Nil(t, wallet)
	require.True(t, malformedStore.viewExited)
	require.True(t, malformedAddr.matchedRead)
	require.Equal(t, []error{nil}, malformedStore.bodyErrors)
	require.ErrorContains(t, err, "stored chain address path is missing")
}

// TestStoreOpenSnapshotRetryReset verifies a failed snapshot attempt is cleared
// before a successful retry and no partially reconstructed manager is returned.
func TestStoreOpenSnapshotRetryReset(t *testing.T) {
	store := newOpenSplitStore(t)
	readErr := errors.New("retry snapshot read")
	retryStore := &openSplitRetryStore{
		Store:   store,
		scope:   waddrmgr.KeyScopeBIP0084,
		failure: readErr,
	}

	wallet, err := OpenFromStore(
		retryStore, []byte("public-pass"), &chaincfg.TestNet3Params, 0,
		defaultSyncRetryInterval,
	)
	require.NoError(t, err)
	require.NotNil(t, wallet)
	require.Equal(t, 2, retryStore.resets)
	require.Len(t, retryStore.bodyErrors, 2)
	require.ErrorIs(t, retryStore.bodyErrors[0], readErr)
	require.NoError(t, retryStore.bodyErrors[1])

	scopedManager, err := wallet.Manager.FetchScopedKeyManager(
		waddrmgr.KeyScopeBIP0084,
	)
	require.NoError(t, err)
	lastAddress, err := scopedManager.LastExternalAddress(
		nil, waddrmgr.DefaultAccountNum,
	)
	require.NoError(t, err)
	require.NotNil(t, lastAddress)
	wallet.Manager.Close()
}
