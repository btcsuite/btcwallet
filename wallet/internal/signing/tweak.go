package signing

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

// ErrInvalidKeyTweak reports a key tweak with a zero multiplier or a scalar at
// or above the curve order, or a tweak that turns the selected key into zero.
var ErrInvalidKeyTweak = errors.New("invalid key tweak")

// KeyTweak is the scalar pair (mul, add) that turns a wallet private key d
// into the effective signing key mul*d + add.
//
// The zero value keeps the original key. The pair can be secret: a Lightning
// revocation add term reveals the revocation key.
type KeyTweak struct {
	mul btcec.ModNScalar
	add btcec.ModNScalar
}

// NewKeyTweak constructs a tweak from big-endian scalars below the curve
// order. A zero multiplier is invalid; the identity is the zero value.
func NewKeyTweak(mul, add [32]byte) (KeyTweak, error) {
	var t KeyTweak
	if t.mul.SetBytes(&mul) != 0 || t.add.SetBytes(&add) != 0 {
		return KeyTweak{}, fmt.Errorf("%w: tweak exceeds the curve "+
			"order", ErrInvalidKeyTweak)
	}

	if t.mul.IsZero() {
		return KeyTweak{}, fmt.Errorf("%w: zero multiplier",
			ErrInvalidKeyTweak)
	}

	one := new(btcec.ModNScalar).SetInt(1)
	if t.mul.Equals(one) && t.add.IsZero() {
		return KeyTweak{}, nil
	}

	return t, nil
}

// Apply replaces a caller-owned key with mul*key + add. The identity leaves
// it unchanged. A zero result returns ErrInvalidKeyTweak.
func (t *KeyTweak) Apply(key *btcec.PrivateKey) error {
	if t == nil || *t == (KeyTweak{}) {
		return nil
	}

	key.Key.Mul(&t.mul).Add(&t.add)

	if key.Key.IsZero() {
		return fmt.Errorf("%w: zero effective key", ErrInvalidKeyTweak)
	}

	return nil
}

// Zero clears both scalars, leaving the identity tweak.
func (t *KeyTweak) Zero() {
	t.mul.Zero()
	t.add.Zero()
}

// PubKey applies the tweak to a public key without its private key.
func (t *KeyTweak) PubKey(base *btcec.PublicKey) (*btcec.PublicKey, error) {
	if t == nil || *t == (KeyTweak{}) {
		return base, nil
	}

	var point, mulPoint, addPoint, result btcec.JacobianPoint
	base.AsJacobian(&point)
	btcec.ScalarMultNonConst(&t.mul, &point, &mulPoint)
	btcec.ScalarBaseMultNonConst(&t.add, &addPoint)
	btcec.AddNonConst(&mulPoint, &addPoint, &result)

	if (result.X.IsZero() && result.Y.IsZero()) || result.Z.IsZero() {
		return nil, fmt.Errorf("%w: zero effective key",
			ErrInvalidKeyTweak)
	}

	result.ToAffine()

	return btcec.NewPublicKey(&result.X, &result.Y), nil
}
