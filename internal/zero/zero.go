// Package zero contains functions to clear data from byte slices and
// multi-precision integers.
package zero

import (
	"math/big"
)

// Bytes sets all bytes in the passed slice to zero.  This is used to
// explicitly clear private key material from memory.
//
// In general, prefer to use the fixed-sized zeroing functions (Bytea*)
// when zeroing bytes as they are much more efficient than the variable
// sized zeroing func Bytes.
func Bytes(b []byte) {
	z := [32]byte{}
	n := uint(copy(b, z[:]))
	for n < uint(len(b)) {
		copy(b[n:], b[:n])
		n <<= 1
	}
}

// Bytea32 clears the 32-byte array by filling it with the zero value.
// This is used to explicitly clear private key material from memory.
func Bytea32(b *[32]byte) {
	*b = [32]byte{}
}

// Bytea64 clears the 64-byte array by filling it with the zero value.
// This is used to explicitly clear sensitive material from memory.
func Bytea64(b *[64]byte) {
	*b = [64]byte{}
}

// BigInt sets all bytes in the passed big int to zero and then sets the
// value to 0.  This differs from simply setting the value in that it
// specifically clears the underlying bytes whereas simply setting the value
// does not.  This is mostly useful to forcefully clear private keys.
func BigInt(x *big.Int) {
	b := x.Bits()
	z := [16]big.Word{}
	n := uint(copy(b, z[:]))
	for n < uint(len(b)) {
		copy(b[n:], b[:n])
		n <<= 1
	}
	x.SetInt64(0)
}
