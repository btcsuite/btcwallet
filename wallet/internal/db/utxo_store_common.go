package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

var (
	// errInvalidLockID indicates that a lease row contained bytes that cannot
	// be represented as a fixed-size LockID.
	errInvalidLockID = errors.New("invalid lock id length")

	// ErrOutputAlreadyLeased reports that a UTXO lease request conflicted with
	// another active lock on the same output.
	ErrOutputAlreadyLeased = errors.New("output already leased")

	// ErrOutputUnlockNotAllowed reports that a UTXO release request used a lock
	// ID different from the active lease.
	ErrOutputUnlockNotAllowed = errors.New("output unlock not allowed")

	// errLeaseOutputNoRow indicates that the backend lease write found no
	// leasable current UTXO row for the requested outpoint.
	errLeaseOutputNoRow = errors.New("lease output no row")
)

// buildOutPoint converts database tx-hash and output-index fields into a
// wire.OutPoint.
func buildOutPoint(hash []byte, outputIndex uint32) (wire.OutPoint, error) {
	txHash, err := chainhash.NewHash(hash)
	if err != nil {
		return wire.OutPoint{}, fmt.Errorf("utxo hash: %w", err)
	}

	return wire.OutPoint{Hash: *txHash, Index: outputIndex}, nil
}

// buildUtxoInfo converts normalized SQL result fields into the public UtxoInfo
// shape returned by the db interfaces.
func buildUtxoInfo(hash []byte, outputIndex uint32, amount int64,
	pkScript []byte, received time.Time, isCoinbase bool,
	blockHeight *uint32) (*UtxoInfo, error) {

	outPoint, err := buildOutPoint(hash, outputIndex)
	if err != nil {
		return nil, err
	}

	height := UnminedHeight
	if blockHeight != nil {
		height = *blockHeight
	}

	return &UtxoInfo{
		OutPoint:     outPoint,
		Amount:       btcutil.Amount(amount),
		PkScript:     pkScript,
		Received:     received.UTC(),
		FromCoinBase: isCoinbase,
		Height:       height,
	}, nil
}

// buildLeasedOutput converts SQL lease-row fields into the public LeasedOutput
// type.
func buildLeasedOutput(hash []byte, outputIndex uint32, lockID []byte,
	expiration time.Time) (*LeasedOutput, error) {

	outPoint, err := buildOutPoint(hash, outputIndex)
	if err != nil {
		return nil, err
	}

	if len(lockID) != len(LockID{}) {
		return nil, fmt.Errorf("lock id: %w", errInvalidLockID)
	}

	var id LockID
	copy(id[:], lockID)

	return &LeasedOutput{
		OutPoint:   outPoint,
		LockID:     id,
		Expiration: expiration.UTC(),
	}, nil
}

// leaseOutputOps is the backend adapter the shared LeaseOutput workflow uses.
//
// The shared lease algorithm is intentionally ordered:
//   - validate the public lease request up front
//   - attempt the atomic lease write or renewal next
//   - if the write reports no row, distinguish a missing UTXO from an active
//     conflicting lease
//   - return the public leased-output view only after the write succeeds
//
// The adapter methods map directly to those stages so the shared helper keeps
// the policy and sequencing while each backend keeps only query details.
type leaseOutputOps interface {
	// acquire attempts to write or renew the lease and returns the stored
	// expiration timestamp when the write succeeds.
	acquire(ctx context.Context, params LeaseOutputParams, nowUTC time.Time,
		expiresAt time.Time) (time.Time, error)

	// hasUtxo reports whether the requested outpoint still exists as a current
	// wallet-owned UTXO.
	hasUtxo(ctx context.Context, params LeaseOutputParams) (bool, error)
}

// leaseOutputWithOps runs the backend-independent LeaseOutput workflow once the
// caller has opened a backend-specific SQL transaction.
//
// The helper owns the lease sequencing so every backend answers the same two
// questions in the same order: did the lease write succeed, and if not, was the
// target output missing or merely already leased by a different lock?
func leaseOutputWithOps(ctx context.Context, params LeaseOutputParams,
	ops leaseOutputOps) (*LeasedOutput, error) {

	if params.Duration <= 0 {
		return nil, fmt.Errorf("%w: lease duration must be positive",
			ErrInvalidParam)
	}

	nowUTC := time.Now().UTC()
	expiresAt := nowUTC.Add(params.Duration)

	expiration, err := ops.acquire(ctx, params, nowUTC, expiresAt)
	if err == nil {
		return &LeasedOutput{
			OutPoint:   params.OutPoint,
			LockID:     LockID(params.ID),
			Expiration: expiration.UTC(),
		}, nil
	}

	if !errors.Is(err, errLeaseOutputNoRow) {
		return nil, fmt.Errorf("acquire utxo lease: %w", err)
	}

	// A no-row acquire means the write path found no leasable row.
	// Distinguish a missing UTXO from an already-active lease before
	// returning a public error.
	exists, err := ops.hasUtxo(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("lookup utxo before lease conflict: %w", err)
	}

	if !exists {
		return nil, fmt.Errorf("utxo %s: %w", params.OutPoint,
			ErrUtxoNotFound)
	}

	return nil, fmt.Errorf("utxo %s: %w", params.OutPoint,
		ErrOutputAlreadyLeased)
}
