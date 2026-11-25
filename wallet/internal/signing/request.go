package signing

import (
	"errors"
	"fmt"
)

// ErrInvalidMode reports a digest request with an unknown signature mode.
var ErrInvalidMode = errors.New("invalid signature mode")

// Mode selects the signature algorithm and encoding of a digest signature.
type Mode uint8

const (
	// ModeECDSA produces an ECDSASignature.
	ModeECDSA Mode = iota + 1

	// ModeCompactECDSA produces a 65-byte recoverable CompactSignature for
	// the compressed public key.
	ModeCompactECDSA

	// ModeSchnorr produces a BIP-340 SchnorrSignature.
	ModeSchnorr
)

// DigestRequest describes one digest signature.
type DigestRequest struct {
	// Key selects the wallet key to sign with.
	Key KeySelector

	// Digest is the 32-byte message digest. The wallet computes it; the
	// vault does not interpret it.
	Digest [32]byte

	// Mode selects the signature algorithm.
	Mode Mode

	// Tweak is an optional scalar pair applied to the selected key before
	// signing. The zero value signs with the selected key itself. Callers
	// fold any protocol tweak, such as a BIP-341 output tweak, into it.
	Tweak KeyTweak
}

// Validate checks the request fields that need no key. Vault implementations
// call it before they read any secret. The selector must pass
// ValidateKeySelector, so a nil, typed-nil or pointer selector returns
// ErrInvalidKeySelector.
func (r *DigestRequest) Validate() error {
	err := ValidateKeySelector(r.Key)
	if err != nil {
		return err
	}

	switch r.Mode {
	case ModeECDSA, ModeCompactECDSA, ModeSchnorr:
		return nil

	default:
		return fmt.Errorf("%w: %d", ErrInvalidMode, r.Mode)
	}
}
