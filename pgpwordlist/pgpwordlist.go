/*
 * Copyright (c) 2015-2016 The Decred developers
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package pgpwordlist

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
)

func doubleSha256(b []byte) [sha256.Size]byte {
	intermediateHash := sha256.Sum256(b)
	return sha256.Sum256(intermediateHash[:])
}

// ToString converts a byteslice to a string of words from the
// PGP word list.
func ToString(b []byte) (string, error) {
	if b == nil {
		return "", fmt.Errorf("missing data to string encode")
	}

	var buf bytes.Buffer

	for i, e := range b {
		toUse := uint16(0)
		toUse = uint16(uint8(e)) * 2

		// Odd numbered bytes.
		if i%2 != 0 {
			toUse++
		}

		buf.WriteString(WordList[toUse])

		// Skip last space.
		if i != len(b)-1 {
			buf.WriteString(" ")
		}
	}

	return buf.String(), nil
}

// ToStringChecksum converts a byteslice to a string of words from the
// PGP word list, along with a one word checksum appended to the end.
// The checksum is the first byte of the sha256d hash.
func ToStringChecksum(b []byte) (string, error) {
	str, err := ToString(b)
	if err != nil {
		return "", err
	}

	hash := doubleSha256(b)

	toUse := uint16(0)
	toUse = uint16(uint8(hash[0])) * 2

	// Odd numbered byte for last char.
	if (len(b) % 2) != 0 {
		toUse++
	}

	return str + " " + WordList[toUse], nil
}

// ToBytes converts a string to a byte slice using the PGP word
// list. Notably, it strips words of their case, so any case input
// is valid.
func ToBytes(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("missing string data to decode")
	}

	sLower := strings.ToLower(s)
	strSlice := strings.Split(sLower, " ")

	var buf bytes.Buffer

	for _, w := range strSlice {
		bLong, exists := WordMap[w]
		if !exists {
			return nil, fmt.Errorf("unidentifiable word %v", w)
		}

		b := uint8(bLong / 2)

		buf.WriteByte(byte(b))
	}

	return buf.Bytes(), nil
}

// ToBytesChecksum converts a string to a byte slice using the PGP
// word list. Notably, it strips words of their case, so any case
// input is valid. Unlike ToBytes, it uses a sha256d hash to verify
// the integrity of the data after.
func ToBytesChecksum(s string) ([]byte, error) {
	b, err := ToBytes(s)
	if err != nil {
		return nil, err
	}
	bdata := b[:len(b)-1]

	hash := doubleSha256(bdata)
	toUse := uint16(0)
	toUse = uint16(uint8(hash[0])) * 2
	// Odd numbered byte for last char.
	if (len(b) % 2) == 0 {
		toUse++
	}
	checksumCalc := WordList[toUse]

	strSlice := strings.Split(s, " ")
	checksum := strings.ToLower(strSlice[len(strSlice)-1])

	if checksum != strings.ToLower(checksumCalc) {
		return nil, fmt.Errorf("checksum failure: got %v, expected %v",
			checksum, checksumCalc)
	}

	return bdata, nil
}
