// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
)

// This file defines the reusable semantic-commit framework the Stage 3 runtime
// operations share. Phase 1A settled the pattern on one operation
// (ReserveBranchIndexRequest/Result); Phase 1B generalizes it so every later
// semantic method follows the same shape:
//
//   - A prepared request type carrying the durable snapshot the caller read
//     outside the write transaction plus the guards the commit must satisfy.
//   - A committed-result type embedding CommittedFacts: fully materialized
//     immutable details and stable event identities. Because the facts are
//     materialized at commit time, cache updates and notification delivery
//     never need the original write transaction (the Notification Contract).
//
// The framework is backend neutral. Both the SQL and KV runtime stores return
// the same committed facts and derive the same event identities from the same
// canonical payloads, so an observable-parity vector can compare their results
// without inspecting backend-internal journals or versions.

// EventID is the stable, backend-independent identity of a post-commit event. A
// semantic operation derives it deterministically from the event's canonical
// payload, so the same committed fact yields the same identity on every backend
// and across a replay of an already committed operation. Notification consumers
// use it to deduplicate events recovered by restart reconciliation.
type EventID [sha256.Size]byte

// Event is a fully materialized post-commit event produced by a semantic
// operation. It carries its own stable identity and an immutable canonical
// payload, so the wallet publishes the corresponding notification after the
// durable commit without reopening a database transaction.
type Event struct {
	// ID is the event's stable, deterministic identity.
	ID EventID

	// Kind names the event category, for example a wallet-tip advance.
	Kind string

	// Payload is the event's canonical immutable detail. It is the exact
	// byte sequence the identity is derived from, so it is identical across
	// backends.
	Payload []byte
}

// CommittedFacts is the shape every semantic result embeds: the operation's
// replay flag and the fully materialized post-commit events it produced.
// Embedding it in each result type is what lets the shared orchestration update
// caches and publish notifications without another database transaction.
type CommittedFacts struct {
	// Replayed reports that the durable state was not changed by this call
	// because the operation had already committed and its result was served
	// from the durable journal. A KV backend, which has no journal, never
	// reports a replay; it re-prepares instead.
	Replayed bool

	// Events are the fully materialized post-commit events the operation
	// produced, in publication order. It is empty for operations that emit no
	// notification, such as an address-index reservation.
	Events []Event
}

// BlockRef is the backend-neutral identity of a block: its height, globally
// unique header hash, and timestamp. It is the block currency the runtime
// exchanges with callers so neither the SQL surrogate block id nor the KV
// recent-block encoding leaks across the contract.
type BlockRef struct {
	// Height is the block height.
	Height int32

	// Hash is the block's globally unique header hash.
	Hash chainhash.Hash

	// Timestamp is the block header timestamp.
	Timestamp time.Time
}

// Guards declares the optimistic-concurrency preconditions a semantic commit
// checks before it mutates any domain. It is the version-domain family of the
// Stage 3 guard set, backed by the wallet runtime-state row's monotonic
// version counters. A nil field is not guarded; a present field both requires
// the current value to equal the pointed-to snapshot and advances it by one in
// the same transaction, so a stale or replayed operation advances no version.
//
// The remaining guards in the Stage 3 guard set are natural-record guards that
// live on each operation's own request rather than here, because they compare a
// specific record instead of a per-wallet version: the expected branch index
// (ReserveBranchIndexRequest.ExpectedIndex, ErrStaleAccountIndex), the expected
// synced tip (AdvanceTipRequest.ExpectedTip, ErrStaleTip), and funding
// reservation ownership (ErrReservationConflict). The KV backend enforces the
// natural-record guards from its own records and does not carry the version
// family at all, since it has no runtime-state row.
type Guards struct {
	// ExpectedStateVersion, when set, guards and advances the address,
	// transaction, and sync state version. A mismatch is ErrStaleWalletState.
	ExpectedStateVersion *int64

	// ExpectedHistoryEpoch, when set, guards and advances the history epoch.
	// A mismatch is ErrStaleHistoryEpoch.
	ExpectedHistoryEpoch *int64

	// ExpectedSecretVersion, when set, guards and advances the secret
	// version. A mismatch is ErrStaleSecretState.
	ExpectedSecretVersion *int64
}

// walletTipPayloadLen is the byte length of a wallet-tip event payload: a
// big-endian height, the 32-byte header hash, and a big-endian Unix timestamp.
const walletTipPayloadLen = 4 + chainhash.HashSize + 8

// WalletTipAdvancedKind is the Kind of the event a wallet-tip advance emits.
const WalletTipAdvancedKind = "wallet-tip-advanced"

// DeriveEventID derives an event's stable identity from its kind and canonical
// payload. It is the single derivation both backends use, so a given kind and
// payload always produce the same EventID regardless of backend or replay.
func DeriveEventID(kind string, payload []byte) EventID {
	digest := sha256.New()
	digest.Write([]byte(kind))
	digest.Write(payload)

	var id EventID
	copy(id[:], digest.Sum(nil))

	return id
}

// WalletTipEvent builds the fully materialized post-commit event for advancing
// the wallet's synced tip to tip. It is defined in the neutral package so the
// SQL and KV backends build a byte-identical payload and therefore an identical
// event identity for the same committed tip.
func WalletTipEvent(tip BlockRef) Event {
	payload := encodeWalletTip(tip)

	return Event{
		ID:      DeriveEventID(WalletTipAdvancedKind, payload),
		Kind:    WalletTipAdvancedKind,
		Payload: payload,
	}
}

// encodeWalletTip packs a block reference into the canonical wallet-tip payload.
func encodeWalletTip(tip BlockRef) []byte {
	payload := make([]byte, walletTipPayloadLen)

	//nolint:gosec // A synced block height is non-negative; the round trip is
	// exact.
	binary.BigEndian.PutUint32(payload[0:4], uint32(tip.Height))
	copy(payload[4:4+chainhash.HashSize], tip.Hash[:])

	//nolint:gosec // A block timestamp is a positive Unix second.
	binary.BigEndian.PutUint64(
		payload[4+chainhash.HashSize:], uint64(tip.Timestamp.Unix()),
	)

	return payload
}

// DecodeWalletTip reconstructs the block reference from a canonical wallet-tip
// payload. It is the inverse of the encoding WalletTipEvent uses, so a backend
// that stores the payload as a durable result fact can rebuild the identical
// tip and event on a replay.
func DecodeWalletTip(payload []byte) (BlockRef, error) {
	if len(payload) != walletTipPayloadLen {
		return BlockRef{}, fmt.Errorf("wallet-tip payload is %d bytes, "+
			"want %d", len(payload), walletTipPayloadLen)
	}

	var tip BlockRef

	//nolint:gosec // The height round-trips the value encodeWalletTip wrote.
	tip.Height = int32(binary.BigEndian.Uint32(payload[0:4]))
	copy(tip.Hash[:], payload[4:4+chainhash.HashSize])

	//nolint:gosec // The timestamp round-trips the value encodeWalletTip wrote.
	seconds := int64(binary.BigEndian.Uint64(payload[4+chainhash.HashSize:]))
	tip.Timestamp = time.Unix(seconds, 0)

	return tip, nil
}
