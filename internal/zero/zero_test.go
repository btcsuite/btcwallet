// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package zero_test

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	. "github.com/btcsuite/btcwallet/internal/zero"
)

func makeOneBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 1
	}
	return b
}

func checkZeroBytes(b []byte) error {
	for i, v := range b {
		if v != 0 {
			return fmt.Errorf("b[%d] = %d", i, v)
		}
	}
	return nil
}

func TestBytes(t *testing.T) {
	tests := []int{
		0,
		31,
		32,
		33,
		127,
		128,
		129,
		255,
		256,
		256,
		257,
		383,
		384,
		385,
		511,
		512,
		513,
	}

	for i, n := range tests {
		b := makeOneBytes(n)
		Bytes(b)
		err := checkZeroBytes(b)
		if err != nil {
			t.Errorf("Test %d (n=%d) failed: %v", i, n, err)
			continue
		}
	}
}

func checkZeroWords(b []big.Word) error {
	for i, v := range b {
		if v != 0 {
			return fmt.Errorf("b[%d] = %d", i, v)
		}
	}
	return nil
}

var bigZero = new(big.Int)

func TestBigInt(t *testing.T) {
	tests := []string{
		// 16 0xFFFFFFFF 32-bit uintptrs
		strings.Repeat("FFFFFFFF", 16),

		// 17 32-bit uintptrs, minimum value which enters loop on 32-bit
		"01" + strings.Repeat("00000000", 16),

		// 32 0xFFFFFFFF 32-bit uintptrs, maximum value which enters loop exactly once on 32-bit
		strings.Repeat("FFFFFFFF", 32),

		// 33 32-bit uintptrs, minimum value which enters loop twice on 32-bit
		"01" + strings.Repeat("00000000", 32),

		// 16 0xFFFFFFFFFFFFFFFF 64-bit uintptrs
		strings.Repeat("FFFFFFFFFFFFFFFF", 16),

		// 17 64-bit uintptrs, minimum value which enters loop on 64-bit
		"01" + strings.Repeat("0000000000000000", 16),

		// 32 0xFFFFFFFFFFFFFFFF 64-bit uintptrs, maximum value which enters loop exactly once on 64-bit
		strings.Repeat("FFFFFFFFFFFFFFFF", 32),

		// 33 64-bit uintptrs, minimum value which enters loop twice on 64-bit
		"01" + strings.Repeat("0000000000000000", 32),
	}

	for i, s := range tests {
		v, ok := new(big.Int).SetString(s, 16)
		if !ok {
			t.Errorf("Test %d includes invalid hex number %s", i, s)
			continue
		}

		BigInt(v)
		err := checkZeroWords(v.Bits())
		if err != nil {
			t.Errorf("Test %d (s=%s) failed: %v", i, s, err)
			continue
		}
		if v.Cmp(bigZero) != 0 {
			t.Errorf("Test %d (s=%s) zeroed big.Int represents non-zero number %v", i, s, v)
			continue
		}
	}
}

func TestBytea32(t *testing.T) {
	const sz = 32
	var b [sz]byte
	copy(b[:], makeOneBytes(sz))

	Bytea32(&b)

	err := checkZeroBytes(b[:])
	if err != nil {
		t.Error(err)
	}
}

func TestBytea64(t *testing.T) {
	const sz = 64
	var b [sz]byte
	copy(b[:], makeOneBytes(sz))

	Bytea64(&b)

	err := checkZeroBytes(b[:])
	if err != nil {
		t.Error(err)
	}
}
