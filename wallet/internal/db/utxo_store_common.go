package db

import (
	"bytes"
	"context"
	"database/sql"
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

	// ErrOutputUnlockNotAllowed reports that a UTXO Release request used a lock
	// ID different from the active lease.
	ErrOutputUnlockNotAllowed = errors.New("output unlock not allowed")

	// ErrLeaseOutputNoRow indicates that the backend lease write found no
	// leasable current UTXO row for the requested outpoint.
	ErrLeaseOutputNoRow = errors.New("lease output no row")

	// ErrReleaseOutputUtxoNotFound indicates that ReleaseOutput could not
	// resolve the requested outpoint to a current wallet-owned UTXO row.
	ErrReleaseOutputUtxoNotFound = errors.New(
		"Release output utxo not found",
	)

	// ErrReleaseOutputNoActiveLease indicates that the target UTXO no longer
	// has an active lease row by the time ReleaseOutput checks the fallback
	// path.
	ErrReleaseOutputNoActiveLease = errors.New(
		"Release output no active lease",
	)
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

// KeyScopeFromIDs builds a KeyScope from the raw purpose / coin_type columns
// selected from key_scopes, validating the int64 -> uint32 narrowing.
func KeyScopeFromIDs(purpose, coinType int64) (KeyScope, error) {
	p, err := Int64ToUint32(purpose)
	if err != nil {
		return KeyScope{}, fmt.Errorf("scope purpose: %w", err)
	}

	c, err := Int64ToUint32(coinType)
	if err != nil {
		return KeyScope{}, fmt.Errorf("scope coin type: %w", err)
	}

	return KeyScope{Purpose: p, Coin: c}, nil
}

// KeyScopeFromNullIDs builds a KeyScope from nullable purpose and coin_type
// columns. A false hasScope return means both values are NULL, which is the
// expected shape for raw imported addresses.
func KeyScopeFromNullIDs(purpose,
	coinType sql.NullInt64) (KeyScope, bool, error) {

	switch {
	case !purpose.Valid && !coinType.Valid:
		return KeyScope{}, false, nil

	case purpose.Valid != coinType.Valid:
		return KeyScope{}, false, fmt.Errorf("%w: incomplete key scope",
			errAddressShapeCorruption)
	}

	scope, err := KeyScopeFromIDs(purpose.Int64, coinType.Int64)
	if err != nil {
		return KeyScope{}, false, err
	}

	return scope, true, nil
}

// UtxoAddressShape captures address/account shape metadata selected by UTXO
// read queries.
type UtxoAddressShape struct {
	// IsDerived reports whether the credited address should have a
	// derived_addresses child row.
	IsDerived bool

	// DerivedAddressID is set when the credited address has a derived_addresses
	// child row.
	DerivedAddressID sql.NullInt64

	// AccountID is set when the credited address has derived account ownership
	// metadata.
	AccountID sql.NullInt64

	// AccountIsDerived reports the owning account's structural shape when
	// account metadata is present.
	AccountIsDerived sql.NullBool

	// AccountNumber is set when the owning account is wallet-derived.
	AccountNumber sql.NullInt64
}

// validateImportedUtxoShape verifies that a raw imported address carries no
// derived path row or account metadata.
func validateImportedUtxoShape(shape UtxoAddressShape) error {
	if shape.DerivedAddressID.Valid {
		return fmt.Errorf("%w: raw imported address has path row",
			errAddressShapeCorruption)
	}

	if shape.AccountID.Valid || shape.AccountIsDerived.Valid ||
		shape.AccountNumber.Valid {

		return fmt.Errorf("%w: raw imported address has account metadata",
			errAddressShapeCorruption)
	}

	return nil
}

// ValidateUtxoAddressShape checks that UTXO address/account joins reflect a
// valid persisted address shape.
func ValidateUtxoAddressShape(shape UtxoAddressShape) error {
	if !shape.IsDerived {
		return validateImportedUtxoShape(shape)
	}

	if !shape.DerivedAddressID.Valid {
		return fmt.Errorf("%w: derived address missing path row",
			errAddressShapeCorruption)
	}

	if !shape.AccountID.Valid || !shape.AccountIsDerived.Valid {
		return fmt.Errorf("%w: derived address missing account metadata",
			errAddressShapeCorruption)
	}

	if !shape.AccountIsDerived.Bool {
		if shape.AccountNumber.Valid {
			return fmt.Errorf("%w: non-derived account has derived "+
				"account number", errAccountShapeCorruption)
		}

		return nil
	}

	if !shape.AccountNumber.Valid {
		return fmt.Errorf("%w: derived account missing account number",
			errAccountShapeCorruption)
	}

	return nil
}

// BuildUtxoInfo converts the normalized base SQL result fields into the public
// UtxoInfo shape. Backends set the per-row enrichment fields (AccountName,
// Origin, AddrType, HasScript, IsLocked, Spendable, KeyScope) directly on the
// returned value after this call.
func BuildUtxoInfo(hash []byte, outputIndex uint32, amount int64,
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

// BuildLeasedOutput converts SQL lease-row fields into the public LeasedOutput
// type.
func BuildLeasedOutput(hash []byte, outputIndex uint32, lockID []byte,
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

// LeaseOutputOps is the backend adapter the shared LeaseOutput workflow uses.
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
type LeaseOutputOps interface {
	// Acquire attempts to write or renew the lease and returns the stored
	// expiration timestamp when the write succeeds.
	Acquire(ctx context.Context, params LeaseOutputParams, nowUTC time.Time,
		expiresAt time.Time) (time.Time, error)

	// HasUtxo reports whether the requested outpoint still exists as a current
	// wallet-owned UTXO.
	HasUtxo(ctx context.Context, params LeaseOutputParams) (bool, error)
}

// LeaseOutputWithOps runs the backend-independent LeaseOutput workflow once the
// caller has opened a backend-specific SQL transaction.
//
// The helper owns the lease sequencing so every backend answers the same two
// questions in the same order: did the lease write succeed, and if not, was the
// target output missing or merely already leased by a different lock?
func LeaseOutputWithOps(ctx context.Context, params LeaseOutputParams,
	ops LeaseOutputOps) (*LeasedOutput, error) {

	if params.Duration <= 0 {
		return nil, fmt.Errorf("%w: lease duration must be positive",
			ErrInvalidParam)
	}

	nowUTC := time.Now().UTC()
	expiresAt := nowUTC.Add(params.Duration)

	expiration, err := ops.Acquire(ctx, params, nowUTC, expiresAt)
	if err == nil {
		return &LeasedOutput{
			OutPoint:   params.OutPoint,
			LockID:     LockID(params.ID),
			Expiration: expiration.UTC(),
		}, nil
	}

	if !errors.Is(err, ErrLeaseOutputNoRow) {
		return nil, fmt.Errorf("acquire utxo lease: %w", err)
	}

	// A no-row Acquire means the write path found no leasable row.
	// Distinguish a missing UTXO from an already-active lease before
	// returning a public error.
	exists, err := ops.HasUtxo(ctx, params)
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

// ReleaseOutputOps is the backend adapter the shared ReleaseOutput workflow
// uses.
//
// The shared Release algorithm is intentionally ordered:
//   - resolve the wallet-owned outpoint to a stable UTXO row first
//   - attempt the lease delete by lock ID second
//   - if no row is deleted, check the active lease state for that UTXO
//   - treat a missing active lease as a no-op
//   - map a different active lock to ErrOutputUnlockNotAllowed
//
// The adapter methods map directly to those stages so the shared helper keeps
// the Release policy and sequencing while each backend keeps only query
// details.
type ReleaseOutputOps interface {
	// LookupUtxoID resolves the current wallet-owned outpoint to its stable
	// UTXO row ID.
	LookupUtxoID(ctx context.Context, params ReleaseOutputParams) (int64, error)

	// Release attempts to delete the lease row for the provided UTXO ID and
	// lock ID, returning the number of deleted rows.
	Release(ctx context.Context, walletID uint32, utxoID int64,
		lockID [32]byte) (int64, error)

	// ActiveLockID returns the currently active lock ID for the provided UTXO
	// ID.
	ActiveLockID(ctx context.Context, walletID uint32, utxoID int64,
		nowUTC time.Time) ([]byte, error)
}

// ReleaseOutputWithOps runs the backend-independent ReleaseOutput workflow once
// the caller has opened a backend-specific SQL transaction.
//
// The helper resolves the stable UTXO row first, attempts the lock-specific
// delete second, and only falls back to the active-lock lookup when no row was
// deleted. That keeps a released-or-expired lease as a no-op while still
// surfacing conflicting active locks consistently across backends.
func ReleaseOutputWithOps(ctx context.Context, params ReleaseOutputParams,
	ops ReleaseOutputOps) error {

	nowUTC := time.Now().UTC()

	utxoID, err := ops.LookupUtxoID(ctx, params)
	if err != nil {
		if errors.Is(err, ErrReleaseOutputUtxoNotFound) {
			return fmt.Errorf("utxo %s: %w", params.OutPoint,
				ErrUtxoNotFound)
		}

		return fmt.Errorf("lookup utxo for release: %w", err)
	}

	rows, err := ops.Release(ctx, params.WalletID, utxoID, params.ID)
	if err != nil {
		return fmt.Errorf("release utxo lease: %w", err)
	}

	if rows != 0 {
		return nil
	}

	// No row was deleted, so either the lease already expired or was released,
	// or a different active lock still owns this UTXO.
	activeLockID, err := ops.ActiveLockID(
		ctx, params.WalletID, utxoID, nowUTC,
	)
	if err != nil {
		if errors.Is(err, ErrReleaseOutputNoActiveLease) {
			return nil
		}

		return fmt.Errorf("lookup active utxo lease: %w", err)
	}

	if !bytes.Equal(activeLockID, params.ID[:]) {
		return fmt.Errorf("utxo %s: %w", params.OutPoint,
			ErrOutputUnlockNotAllowed)
	}

	return nil
}
