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

package zero

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
