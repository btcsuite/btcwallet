package db

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
)

// ErrInvalidDatabaseIdentity reports invalid pre-Store identity input.
var ErrInvalidDatabaseIdentity = errors.New("invalid database identity")

// ErrDatabaseIdentityMismatch reports failure to establish stored identity.
var ErrDatabaseIdentityMismatch = errors.New("database identity mismatch")

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
	signetDigest := i.signetDigest[:]
	if !i.hasSignetInput {
		signetDigest = nil
	}

	return i.genesisHash[:], int64(i.networkMagic), signetDigest
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
