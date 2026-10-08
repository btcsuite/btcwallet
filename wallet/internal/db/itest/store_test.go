//go:build itest

package itest

import (
	"database/sql"
	"errors"
	"io"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// databaseIdentityFixture keeps only operations shared by both SQL dialects.
type databaseIdentityFixture struct {
	// driver and source open a raw handle for test-only malformed state.
	driver, source string

	// open calls the concrete backend constructor for the fixture database.
	open func(db.DatabaseIdentity) (io.Closer, error)

	// malformations maps each shared malformed case to its raw fixture SQL.
	malformations map[string][]string
}

// mutateIdentity applies test-only SQL and always closes its temporary handle.
func (f databaseIdentityFixture) mutateIdentity(t *testing.T,
	statements []string) {

	t.Helper()

	fixtureDB, err := sql.Open(f.driver, f.source)
	require.NoError(t, err)

	defer func() {
		// Close during fail-fast exits so malformed setup cannot retain locks.
		require.NoError(t, fixtureDB.Close())
	}()

	for _, statement := range statements {
		_, err = fixtureDB.ExecContext(t.Context(), statement)
		require.NoError(t, err)
	}
}

// openAndCloseIdentityStore closes each successful Store before returning it
// so tests can observe whether startup produced a resource without leaking it.
func openAndCloseIdentityStore(t *testing.T, fixture databaseIdentityFixture,
	identity db.DatabaseIdentity) (io.Closer, error) {

	t.Helper()

	store, err := fixture.open(identity)
	if store == nil {
		return nil, errors.Join(err, errors.New("nil Store"))
	}

	return store, errors.Join(err, store.Close())
}

func TestNewTestStore(t *testing.T) {
	t.Parallel()

	// This test store exercises the underlying database connector in a test
	// environment, so we can verify that the store is created successfully with
	// a valid database connection and later properly closed. Will test all
	// backends (SQLite, PostgreSQL) based in the build tags.
	store := NewTestStore(t)

	require.NotNil(t, store)
	require.NotNil(t, store.DB())
	require.NotNil(t, store.Queries())
	require.NoError(t, store.Close())
}

// TestDatabaseIdentity applies one startup contract to both SQL backends.
func TestDatabaseIdentity(t *testing.T) {
	// Arrange: Build ordinary, wrong-network, and colliding-magic signet
	// tuples shared by both database backends.
	regtest, regtestErr := db.NewDatabaseIdentity(
		&chaincfg.RegressionNetParams, nil,
	)
	require.NoError(t, regtestErr)

	testnet, testErr := db.NewDatabaseIdentity(&chaincfg.TestNet3Params, nil)
	require.NoError(t, testErr)

	challenge := chaincfg.DefaultSignetChallenge
	digest := chainhash.DoubleHashB(
		append([]byte{byte(len(challenge))}, challenge...),
	)
	otherDigest := append([]byte(nil), digest...)
	otherDigest[len(otherDigest)-1] ^= 1
	signet, signetErr := db.NewDatabaseIdentity(&chaincfg.SigNetParams, digest)
	require.NoError(t, signetErr)

	otherSignet, otherErr := db.NewDatabaseIdentity(
		&chaincfg.SigNetParams, otherDigest,
	)
	require.NoError(t, otherErr)

	t.Run("initializes and reopens", func(t *testing.T) {
		// Arrange: Select one empty backend fixture for both startup attempts.
		fixture := newDatabaseIdentityFixture(t)

		// Act: Open the fixture twice with the same regression-test tuple.
		_, firstErr := openAndCloseIdentityStore(t, fixture, regtest)
		_, secondErr := openAndCloseIdentityStore(t, fixture, regtest)

		// Assert: Initial creation and matching reopen both return a Store.
		require.NoError(t, firstErr)
		require.NoError(t, secondErr)
	})

	mismatches := map[string]struct {
		stored    db.DatabaseIdentity
		requested db.DatabaseIdentity
	}{
		"wrong network": {
			stored:    regtest,
			requested: testnet,
		},
		"different signet": {
			stored:    signet,
			requested: otherSignet,
		},
	}

	for name, tc := range mismatches {
		t.Run("rejects "+name, func(t *testing.T) {
			// Arrange: Persist the canonical tuple in one isolated fixture.
			fixture := newDatabaseIdentityFixture(t)
			_, err := openAndCloseIdentityStore(t, fixture, tc.stored)
			require.NoError(t, err)

			// Act: Try the mismatch, then retry the stored tuple.
			rejected, rejectErr := openAndCloseIdentityStore(
				t, fixture, tc.requested,
			)
			_, reopenErr := openAndCloseIdentityStore(t, fixture, tc.stored)

			// Assert: Only the mismatch stops and returns no Store.
			require.ErrorIs(t, rejectErr, db.ErrDatabaseIdentityMismatch)
			require.Nil(t, rejected)
			require.NoError(t, reopenErr)
		})
	}

	for _, name := range []string{
		"missing singleton",
		"unreadable table",
		"invalid stored value",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			// Arrange: Initialize a marker, then apply the named malformed SQL.
			fixture := newDatabaseIdentityFixture(t)
			_, err := openAndCloseIdentityStore(t, fixture, regtest)
			require.NoError(t, err)
			fixture.mutateIdentity(t, fixture.malformations[name])

			// Act: Reopen while the malformed marker still owns its name.
			rejected, rejectErr := openAndCloseIdentityStore(
				t, fixture, regtest,
			)

			// Assert: Persisted malformation uses the mismatch sentinel.
			require.ErrorIs(t, rejectErr, db.ErrDatabaseIdentityMismatch)
			require.Nil(t, rejected)
		})
	}
}
