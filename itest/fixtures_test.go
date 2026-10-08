//go:build itest

package itest

import (
	"math"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/stretchr/testify/require"
)

// Fixture values shared by more than one component's integration tests. They
// live here rather than in one component's test file so that no component owns
// the values another component depends on.
const (
	// maxConfsLimit is used as the MaxConfs bound when a test does not want
	// to constrain the upper confirmation range.
	maxConfsLimit = math.MaxInt32

	// unminedHeight is the height that stands for "no confirming block" in
	// the range ListTxns takes. A negative start includes the unmined
	// transactions before the confirmed ones, a negative end includes them
	// after, and both negative asks for the unmined transactions alone.
	unminedHeight = -1

	// leaseDuration is the standard lease length for tests. It is long
	// enough that the lease never expires mid-test.
	leaseDuration = 10 * time.Minute

	// pollTimeout bounds waits for asynchronous wallet state changes, such
	// as unconfirmed transaction notifications and timer-driven locks.
	pollTimeout = 30 * time.Second

	// The funding and payment amounts shared by the component test cases.
	halfBTC  = btcutil.SatoshiPerBitcoin / 2
	oneBTC   = 1 * btcutil.SatoshiPerBitcoin
	twoBTC   = 2 * btcutil.SatoshiPerBitcoin
	threeBTC = 3 * btcutil.SatoshiPerBitcoin

	// spendFee is the fee in satoshis that the fixtures spending a wallet's
	// own coins leave behind. It clears the relay minimum by a wide margin
	// while staying far below the backend's default maximum fee rate of
	// 10,000 sat/vbyte, above which an otherwise valid transaction is
	// rejected as paying absurdly much.
	spendFee = 10_000
)

// relayFeeRate is the default relay fee, one satoshi per virtual byte. Any
// case that authors a transaction pays it, and it keeps the fee negligible
// against the funding amounts above.
var relayFeeRate = btcunit.NewSatPerKVByte(txrules.DefaultRelayFeePerKb)

// unknownOutpoint returns an outpoint that was never mined and is therefore
// unknown to any wallet.
func unknownOutpoint() wire.OutPoint {
	return wire.OutPoint{Hash: chainhash.Hash{0xaa}, Index: 0}
}

// importedAccountKeys holds deterministic public and private account material
// used to exercise imported-account contracts without sharing wallet state.
// accountPrivateKey is present only so a case can assert private keys are
// refused.
type importedAccountKeys struct {
	scope                waddrmgr.KeyScope
	addrType             waddrmgr.AddressType
	accountKey           *hdkeychain.ExtendedKey
	otherAccountKey      *hdkeychain.ExtendedKey
	accountPrivateKey    *hdkeychain.ExtendedKey
	masterKeyFingerprint uint32
}

// deterministicImportedAccountKeys derives distinct BIP84 account XPubs from a
// fixed root so imported-account cases are reproducible.
func deterministicImportedAccountKeys(
	h *bwtest.HarnessTest) importedAccountKeys {

	h.Helper()

	scope := waddrmgr.KeyScopeBIP0084
	root, err := hdkeychain.NewMaster(
		[]byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		},
		h.NetParams(),
	)
	require.NoError(h, err, "failed to derive deterministic root key")

	defer root.Zero()

	purpose, err := root.Derive(hdkeychain.HardenedKeyStart + scope.Purpose)
	require.NoError(h, err, "failed to derive BIP84 purpose key")

	defer purpose.Zero()

	coinType, err := purpose.Derive(
		hdkeychain.HardenedKeyStart + h.NetParams().HDCoinType,
	)
	require.NoError(h, err, "failed to derive BIP84 coin type key")

	defer coinType.Zero()

	// Neuter hands the public key the same chain code and parent
	// fingerprint slices the private key holds, so the two account private
	// keys below must outlive this call. Zeroing either one rewrites the
	// XPub being returned.
	accountPrivateKey, err := coinType.Derive(hdkeychain.HardenedKeyStart)
	require.NoError(h, err, "failed to derive imported account private key")
	accountKey, err := accountPrivateKey.Neuter()
	require.NoError(h, err, "failed to derive imported account public key")

	otherPrivateKey, err := coinType.Derive(hdkeychain.HardenedKeyStart + 1)
	require.NoError(h, err, "failed to derive second imported private key")
	otherAccountKey, err := otherPrivateKey.Neuter()
	require.NoError(h, err, "failed to derive second imported public key")

	return importedAccountKeys{
		scope:                scope,
		addrType:             waddrmgr.WitnessPubKey,
		accountKey:           accountKey,
		otherAccountKey:      otherAccountKey,
		accountPrivateKey:    accountPrivateKey,
		masterKeyFingerprint: purpose.ParentFingerprint(),
	}
}
