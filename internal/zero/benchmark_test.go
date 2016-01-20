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

package zero_test

import (
	"testing"

	. "github.com/decred/dcrwallet/internal/zero"
)

var (
	bytes32 = make([]byte, 32) // typical key size
	bytes64 = make([]byte, 64) // passphrase hash size
	bytea32 = new([32]byte)
	bytea64 = new([64]byte)
)

// xor is the "slow" byte zeroing implementation which this package
// originally replaced.  If this function benchmarks faster than the
// functions exported by this package in a future Go version (perhaps
// by calling runtime.memclr), replace the "optimized" versions with
// this.
func xor(b []byte) {
	for i := range b {
		b[i] ^= b[i]
	}
}

// zrange is an alternative zero implementation that, while currently
// slower than the functions provided by this package, may be faster
// in a future Go release.  Switch to this or the xor implementation
// if they ever become faster.
func zrange(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func BenchmarkXor32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		xor(bytes32)
	}
}

func BenchmarkXor64(b *testing.B) {
	for i := 0; i < b.N; i++ {
		xor(bytes64)
	}
}

func BenchmarkRange32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		zrange(bytes32)
	}
}

func BenchmarkRange64(b *testing.B) {
	for i := 0; i < b.N; i++ {
		zrange(bytes64)
	}
}

func BenchmarkBytes32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Bytes(bytes32)
	}
}

func BenchmarkBytes64(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Bytes(bytes64)
	}
}

func BenchmarkBytea32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Bytea32(bytea32)
	}
}

func BenchmarkBytea64(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Bytea64(bytea64)
	}
}
