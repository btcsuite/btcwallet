//go:build itest

package itest

import (
	"math"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/wallet/txrules"
)

// Fixture values shared by more than one component's integration tests. They
// live here rather than in one component's test file so that no component owns
// the values another component depends on.
const (
	// maxConfsLimit is used as the MaxConfs bound when a test does not want
	// to constrain the upper confirmation range.
	maxConfsLimit = math.MaxInt32

	// leaseDuration is the standard lease length for tests. It is long
	// enough that the lease never expires mid-test.
	leaseDuration = 10 * time.Minute

	// The funding and payment amounts shared by the component test cases.
	halfBTC  = btcutil.SatoshiPerBitcoin / 2
	oneBTC   = 1 * btcutil.SatoshiPerBitcoin
	twoBTC   = 2 * btcutil.SatoshiPerBitcoin
	threeBTC = 3 * btcutil.SatoshiPerBitcoin
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
