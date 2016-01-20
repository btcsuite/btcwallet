/*
// Copyright (c) 2015 The Decred developers
 * Copyright (c) 2015 The decred developers
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
	"testing"

	"github.com/stretchr/testify/assert"
)

type Vector struct {
	str string
	b   []byte
}

func TestEncode(t *testing.T) {
	for _, vector := range testVectors() {
		str, err := ToString(vector.b)
		assert.NoError(t, err)

		b, err := ToBytes(vector.str)
		assert.NoError(t, err)

		assert.Equal(t, vector.str, str)
		assert.Equal(t, vector.b, b)
	}
}

func TestChecksums(t *testing.T) {
	for _, vector := range testVectorsChecksums() {
		str, err := ToStringChecksum(vector.b)
		assert.NoError(t, err)

		b, err := ToBytesChecksum(vector.str)
		assert.NoError(t, err)

		assert.Equal(t, vector.str, str)
		assert.Equal(t, vector.b, b)
	}
}

func testVectors() []Vector {
	return []Vector{
		Vector{
			str: "topmost Istanbul Pluto vagabond treadmill Pacific brackish dictator goldfish Medusa afflict bravado chatter revolver Dupont midsummer stopwatch whimsical cowbell bottomless",
			b: []byte{0xE5, 0x82, 0x94, 0xF2, 0xE9, 0xA2, 0x27, 0x48,
				0x6E, 0x8B, 0x06, 0x1B, 0x31, 0xCC, 0x52, 0x8F, 0xD7,
				0xFA, 0x3F, 0x19},
		},
		Vector{
			str: "stairway souvenir flytrap recipe adrift upcoming artist positive spearhead Pandora spaniel stupendous tonic concurrent transit Wichita lockup visitor flagpole escapade",
			b: []byte{0xD1, 0xD4, 0x64, 0xC0, 0x04, 0xF0, 0x0F, 0xB5,
				0xC9, 0xA4, 0xC8, 0xD8, 0xE4, 0x33, 0xE7, 0xFB, 0x7F,
				0xF5, 0x62, 0x56},
		},
	}
}

func testVectorsChecksums() []Vector {
	return []Vector{
		Vector{
			str: "topmost Istanbul Pluto vagabond treadmill Pacific brackish dictator goldfish Medusa afflict bravado chatter revolver Dupont midsummer stopwatch whimsical cowbell bottomless fracture",
			b: []byte{0xE5, 0x82, 0x94, 0xF2, 0xE9, 0xA2, 0x27, 0x48,
				0x6E, 0x8B, 0x06, 0x1B, 0x31, 0xCC, 0x52, 0x8F, 0xD7,
				0xFA, 0x3F, 0x19},
		},
		Vector{
			str: "stairway souvenir flytrap recipe adrift upcoming artist positive spearhead Pandora spaniel stupendous tonic concurrent transit Wichita lockup visitor flagpole escapade merit",
			b: []byte{0xD1, 0xD4, 0x64, 0xC0, 0x04, 0xF0, 0x0F, 0xB5,
				0xC9, 0xA4, 0xC8, 0xD8, 0xE4, 0x33, 0xE7, 0xFB, 0x7F,
				0xF5, 0x62, 0x56},
		},
		Vector{
			str: "tissue disbelief stairway component atlas megaton bedlamp certify tumor monument necklace fascinate tunnel fascinate dreadful armistice upshot Apollo exceed aftermath billiard sardonic vapor microscope brackish suspicious woodlark torpedo hamlet sensation assume recipe",
			b: []byte{0xE3, 0x4C, 0xD1, 0x32, 0x12, 0x8C, 0x19, 0x29,
				0xEC, 0x96, 0x86, 0x5C, 0xED, 0x5C, 0x4D, 0x0B, 0xF4,
				0x0A, 0x5D, 0x02, 0x1F, 0xCE, 0xF5, 0x8D, 0x27, 0xDB,
				0xFE, 0xE3, 0x71, 0xD2, 0x10},
		},
		Vector{
			str: "aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark adroitness aardvark insurgent",
			b: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}
}
