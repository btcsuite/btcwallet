package db

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/stretchr/testify/require"
)

// TestBuildOutPoint verifies the common hash/index conversion shared by both
// SQL backends when building a valid public outpoint.
//
// Scenario:
// - One normalized outpoint row is read back from the store.
// Setup:
// - Build a valid transaction hash.
// Action:
// - Convert the normalized hash/index pair into a wire.OutPoint.
// Assertions:
// - The public outpoint preserves the original hash and output index.
func TestBuildOutPoint(t *testing.T) {
	t.Parallel()

	// Scenario: One normalized outpoint row is read back from the store.
	// Setup: Build a valid transaction hash.
	hash := chainhash.Hash{1, 2, 3}

	// Act: Build the public outpoint from normalized DB fields.
	outPoint, err := buildOutPoint(hash[:], 7)

	// Assert: The helper preserves the hash and output index.
	require.NoError(t, err)
	require.Equal(t, hash, outPoint.Hash)
	require.Equal(t, uint32(7), outPoint.Index)
}

// TestBuildOutPoint_InvalidHash verifies that buildOutPoint rejects malformed
// hash bytes.
//
// Scenario:
// - A normalized outpoint row carries malformed hash bytes.
// Setup:
// - Use a short hash payload.
// Action:
// - Attempt to convert the malformed row into a wire.OutPoint.
// Assertions:
// - The helper returns an error instead of building a partial outpoint.
func TestBuildOutPoint_InvalidHash(t *testing.T) {
	t.Parallel()

	// Scenario: A normalized outpoint row carries invalid hash bytes.
	// Setup: Use a malformed hash payload.
	malformedHash := []byte{1, 2, 3}

	// Act: Attempt to build the public outpoint.
	_, err := buildOutPoint(malformedHash, 0)

	// Assert: The helper rejects the malformed hash.
	require.Error(t, err)
}

// TestBuildUtxoInfo_Confirmed verifies that buildUtxoInfo preserves confirmed
// UTXO metadata.
//
// Scenario:
// - One confirmed UTXO row is read back from the store.
// Setup:
// - Build a valid hash and confirmed block height.
// Action:
// - Convert the normalized row into a public UtxoInfo value.
// Assertions:
// - The mined height and outpoint metadata are preserved.
func TestBuildUtxoInfo_Confirmed(t *testing.T) {
	t.Parallel()

	// Scenario: One confirmed UTXO row is read back from the store.
	// Setup: Build a valid hash and confirmed block height.
	hash := chainhash.Hash{9}
	confirmedHeight := uint32(33)

	// Act: Build the public UTXO view for the confirmed row.
	confirmed, err := buildUtxoInfo(
		hash[:], 1, 1234, []byte{0x51}, time.Unix(111, 0), true,
		&confirmedHeight,
	)

	// Assert: The helper preserves the mined height and outpoint metadata.
	require.NoError(t, err)
	require.Equal(t, confirmedHeight, confirmed.Height)
	require.Equal(t, hash, confirmed.OutPoint.Hash)
	require.Equal(t, uint32(1), confirmed.OutPoint.Index)
}

// TestBuildUtxoInfo_Unconfirmed verifies that buildUtxoInfo maps unconfirmed
// rows to the public unmined sentinel.
//
// Scenario:
// - One unconfirmed UTXO row is read back from the store.
// Setup:
// - Build a valid hash with no block height.
// Action:
// - Convert the normalized row into a public UtxoInfo value.
// Assertions:
//   - The missing height maps to UnminedHeight and the timestamp is stored in
//     UTC.
func TestBuildUtxoInfo_Unconfirmed(t *testing.T) {
	t.Parallel()

	// Scenario: One unconfirmed UTXO row is read back from the store.
	// Setup: Build a valid hash with no block height.
	hash := chainhash.Hash{9}

	// Act: Build the public UTXO view for the unconfirmed row.
	unconfirmed, err := buildUtxoInfo(
		hash[:], 2, 5678, []byte{0x52}, time.Unix(222, 0), false, nil,
	)

	// Assert: The helper maps the missing height to UnminedHeight and stores
	// timestamps in UTC.
	require.NoError(t, err)
	require.Equal(t, UnminedHeight, unconfirmed.Height)
	require.Equal(t, time.UTC, unconfirmed.Received.Location())
}

// TestBuildLeasedOutput verifies the common conversion used by both SQL
// backends when surfacing one valid active lease.
//
// Scenario:
// - One active lease row is read back from the store.
// Setup:
// - Build a valid hash and 32-byte lock ID.
// Action:
// - Convert the normalized row into a public LeasedOutput value.
// Assertions:
// - The outpoint, lock ID, and UTC expiration are preserved.
func TestBuildLeasedOutput(t *testing.T) {
	t.Parallel()

	// Scenario: One active lease row is read back from the store.
	// Setup: Build a valid hash and 32-byte lock ID.
	hash := chainhash.Hash{4, 5, 6}
	lockID := make([]byte, 32)
	lockID[0] = 7

	// Act: Build the public leased-output view.
	lease, err := buildLeasedOutput(
		hash[:], 9, lockID, time.Unix(333, 0).In(time.FixedZone("X", 3600)),
	)

	// Assert: The helper preserves the outpoint, lock ID, and UTC expiration.
	require.NoError(t, err)
	require.Equal(t, hash, lease.OutPoint.Hash)
	require.Equal(t, uint32(9), lease.OutPoint.Index)
	require.Equal(t, byte(7), lease.LockID[0])
	require.Equal(t, time.UTC, lease.Expiration.Location())
}

// TestBuildLeasedOutput_InvalidLockID verifies that buildLeasedOutput rejects
// malformed lock IDs.
//
// Scenario:
// - A lease row carries an invalid lock ID payload.
// Setup:
// - Build a valid hash with a short lock ID.
// Action:
// - Attempt to convert the malformed row into a public LeasedOutput value.
// Assertions:
// - The helper returns errInvalidLockID.
func TestBuildLeasedOutput_InvalidLockID(t *testing.T) {
	t.Parallel()

	// Scenario: A lease row carries an invalid lock ID payload.
	// Setup: Build a valid hash with a short lock ID.
	hash := chainhash.Hash{4, 5, 6}
	shortLockID := []byte{1, 2, 3}

	// Act: Attempt to build the public leased-output view.
	_, err := buildLeasedOutput(hash[:], 0, shortLockID, time.Now())

	// Assert: The helper returns the invalid-lock-ID sentinel.
	require.ErrorIs(t, err, errInvalidLockID)
}
