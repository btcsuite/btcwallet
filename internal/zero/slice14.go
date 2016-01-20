// Copyright (c) 2015 The btcsuite developers
// Copyright (c) 2015 The Decred developers
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Go >= 1.5 optimizes range-based zeroing of the form:
//
//   for i := range slice {
//           slice[i] = 0
//   }
//
// to an optimized implementation using a Duff's device, but older versions
// do not and benefit from this custom implementation.
//
// +build go1.3 go1.4

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
