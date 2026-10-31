package db

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
)

var (
	// ErrInvalidDatabaseIdentity reports invalid pre-Store identity input.
	ErrInvalidDatabaseIdentity = errors.New("invalid database identity")

	// ErrDatabaseIdentityMismatch reports rejected persisted identity state.
	ErrDatabaseIdentityMismatch = errors.New("database identity mismatch")
)

// DatabaseIdentity copies the tuple so mutation cannot redirect SQL startup.
type DatabaseIdentity struct {
	genesisHash    chainhash.Hash // Binds the Store to a chain, not its name.
	networkMagic   uint32         // Preserves unsigned Net for SQL BIGINT.
	signetDigest   chainhash.Hash // Retains the full challenge hash.
	isSignet       bool           // Classifies renamed signets by genesis.
	hasSignetInput bool           // Distinguishes SQL NULL from a zero hash.
}

// NewDatabaseIdentity copies and validates values, detecting signet by genesis.
func NewDatabaseIdentity(params *chaincfg.Params,
	signetDigest []byte) (DatabaseIdentity, error) {

	if params == nil || params.GenesisHash == nil {
		return DatabaseIdentity{}, fmt.Errorf(
			"%w: chain parameters need a genesis hash",
			ErrInvalidDatabaseIdentity,
		)
	}

	if len(signetDigest) != 0 && len(signetDigest) != chainhash.HashSize {
		return DatabaseIdentity{}, fmt.Errorf(
			"%w: signet digest must be 32 bytes",
			ErrInvalidDatabaseIdentity,
		)
	}

	identity := DatabaseIdentity{
		genesisHash:  *params.GenesisHash,
		networkMagic: uint32(params.Net),
		isSignet: params.GenesisHash.IsEqual(
			chaincfg.SigNetParams.GenesisHash),
		hasSignetInput: len(signetDigest) != 0,
	}
	copy(identity.signetDigest[:], signetDigest)

	return identity, identity.Validate()
}

// Validate rejects zero or inconsistent identity before Store database I/O.
func (i DatabaseIdentity) Validate() error {
	if i.genesisHash == (chainhash.Hash{}) {
		return fmt.Errorf("%w: missing genesis hash",
			ErrInvalidDatabaseIdentity)
	}

	if i.isSignet != i.hasSignetInput {
		return fmt.Errorf("%w: inconsistent signet digest",
			ErrInvalidDatabaseIdentity)
	}

	if i.hasSignetInput && binary.LittleEndian.Uint32(
		i.signetDigest[:4],
	) != i.networkMagic {

		return fmt.Errorf("%w: signet digest does not match network magic",
			ErrInvalidDatabaseIdentity)
	}

	return nil
}

// Values returns receiver-copy SQL slices and nil for an absent signet digest.
func (i DatabaseIdentity) Values() ([]byte, int64, []byte) {
	if !i.hasSignetInput {
		return i.genesisHash[:], int64(i.networkMagic), nil
	}

	return i.genesisHash[:], int64(i.networkMagic), i.signetDigest[:]
}

// Matches compares all fields and distinguishes SQL NULL from empty bytes.
func (i DatabaseIdentity) Matches(genesisHash []byte, networkMagic int64,
	signetDigest []byte) bool {

	return bytes.Equal(genesisHash, i.genesisHash[:]) &&
		networkMagic == int64(i.networkMagic) &&
		(!i.hasSignetInput && signetDigest == nil ||
			i.hasSignetInput && bytes.Equal(
				signetDigest, i.signetDigest[:],
			))
}

// VerifyStoredDatabaseIdentity applies the backend-neutral singleton and tuple
// contract while leaving operational query failures distinguishable.
func VerifyStoredDatabaseIdentity(ctx context.Context,
	identity DatabaseIdentity,
	count func(context.Context) (int64, error),
	read func(context.Context) ([]byte, int64, []byte, error)) error {

	rowCount, err := count(ctx)
	if err != nil {
		return fmt.Errorf("count database identities: %w", err)
	}

	if rowCount != 1 {
		return fmt.Errorf("%w: identity row count is %d",
			ErrDatabaseIdentityMismatch, rowCount)
	}

	genesisHash, networkMagic, signetDigest, err := read(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: singleton row is missing",
			ErrDatabaseIdentityMismatch)
	}

	if err != nil {
		return fmt.Errorf("read database identity: %w", err)
	}

	if !identity.Matches(genesisHash, networkMagic, signetDigest) {
		return ErrDatabaseIdentityMismatch
	}

	return nil
}
