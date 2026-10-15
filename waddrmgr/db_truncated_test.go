package waddrmgr

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// recoverPanic runs fn and returns the recovered panic, if any.
func recoverPanic(fn func()) (p interface{}) {
	defer func() { p = recover() }()
	fn()
	return nil
}

// TestDeserializeTruncatedRecords feeds each waddrmgr record decoder a record whose
// embedded length field is larger than the data that follows. A corrupted
// database entry should be reported as ErrDatabase, not crash the wallet.
func TestDeserializeTruncatedRecords(t *testing.T) {
	bigLen := func(prefix []byte) []byte {
		b := append([]byte{}, prefix...)
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], 1000)
		return append(b, l[:]...)
	}
	rawRow := func(raw []byte) *dbAddressRow {
		return &dbAddressRow{rawData: raw}
	}

	cases := []struct {
		name string
		fn   func()
	}{
		{"deserializeAccountRow", func() {
			deserializeAccountRow(nil, bigLen([]byte{0}))
		}},
		{"deserializeDefaultAccountRow", func() {
			raw := append(bigLen(nil), make([]byte, 16)...)
			deserializeDefaultAccountRow(nil, &dbAccountRow{rawData: raw})
		}},
		{"deserializeAddressRow", func() {
			deserializeAddressRow(bigLen(make([]byte, 14)))
		}},
		{"deserializeImportedAddress", func() {
			deserializeImportedAddress(rawRow(append(bigLen(nil),
				make([]byte, 4)...)))
		}},
		{"deserializeScriptAddress", func() {
			deserializeScriptAddress(rawRow(append(bigLen(nil),
				make([]byte, 4)...)))
		}},
		{"deserializeWitnessScriptAddress", func() {
			deserializeWitnessScriptAddress(rawRow(append(
				bigLen([]byte{0, 0}), make([]byte, 4)...)))
		}},
	}
	for _, c := range cases {
		if p := recoverPanic(c.fn); p != nil {
			t.Errorf("%s panics on a truncated record: %v", c.name,
				fmt.Sprint(p))
		}
	}
}

// FuzzDeserializeRecords decodes arbitrary bytes as account and
// address records, including the type-specific raw data.
func FuzzDeserializeRecords(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0})
	f.Add(make([]byte, 40))
	f.Fuzz(func(t *testing.T, data []byte) {
		if acct, err := deserializeAccountRow(nil, data); err == nil {
			deserializeDefaultAccountRow(nil, acct)
		}
		if row, err := deserializeAddressRow(data); err == nil {
			deserializeChainedAddress(row)
			deserializeImportedAddress(row)
			deserializeScriptAddress(row)
			deserializeWitnessScriptAddress(row)
		}
	})
}
