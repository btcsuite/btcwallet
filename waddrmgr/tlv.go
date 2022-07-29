package waddrmgr

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	typeTapscriptType           tlv.Type = 1
	typeTapscriptControlBlock   tlv.Type = 2
	typeTapscriptLeaves         tlv.Type = 3
	typeTapscriptRevealedScript tlv.Type = 4
	typeTapscriptRootHash       tlv.Type = 5
	typeTapscriptFullOutputKey  tlv.Type = 6

	typeTapLeafVersion tlv.Type = 1
	typeTapLeafScript  tlv.Type = 2
)

// tlvEncodeTaprootScript encodes the given internal key and full set of taproot
// script leaves into a byte slice encoded as a TLV stream.
func tlvEncodeTaprootScript(s *Tapscript) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("cannot encode nil script")
	}

	typ := uint8(s.Type)
	tlvRecords := []tlv.Record{
		tlv.MakePrimitiveRecord(typeTapscriptType, &typ),
	}

	if s.ControlBlock != nil {
		if s.ControlBlock.InternalKey == nil {
			return nil, fmt.Errorf("control block is missing " +
				"internal key")
		}

		blockBytes, err := s.ControlBlock.ToBytes()
		if err != nil {
			return nil, fmt.Errorf("error encoding control block: "+
				"%v", err)
		}
		tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(
			typeTapscriptControlBlock, &blockBytes,
		))
	}

	if len(s.Leaves) > 0 {
		tlvRecords = append(tlvRecords, tlv.MakeDynamicRecord(
			typeTapscriptLeaves, &s.Leaves, func() uint64 {
				return recordSize(leavesEncoder, &s.Leaves)
			}, leavesEncoder, leavesDecoder,
		))
	}

	if len(s.RevealedScript) > 0 {
		tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(
			typeTapscriptRevealedScript, &s.RevealedScript,
		))
	}

	if len(s.RootHash) > 0 {
		tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(
			typeTapscriptRootHash, &s.RootHash,
		))
	}

	if s.FullOutputKey != nil {
		keyBytes := schnorr.SerializePubKey(s.FullOutputKey)
		tlvRecords = append(tlvRecords, tlv.MakePrimitiveRecord(
			typeTapscriptFullOutputKey, &keyBytes,
		))
	}

	tlvStream, err := tlv.NewStream(tlvRecords...)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = tlvStream.Encode(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// tlvDecodeTaprootTaprootScript decodes the given byte slice as a TLV stream
// and attempts to parse the taproot internal key and full set of leaves from
// it.
func tlvDecodeTaprootTaprootScript(tlvData []byte) (*Tapscript, error) {

	var (
		typ                uint8
		controlBlockBytes  []byte
		fullOutputKeyBytes []byte
		s                  = &Tapscript{}
	)

	tlvStream, err := tlv.NewStream(
		tlv.MakePrimitiveRecord(typeTapscriptType, &typ),
		tlv.MakePrimitiveRecord(
			typeTapscriptControlBlock, &controlBlockBytes,
		),
		tlv.MakeDynamicRecord(
			typeTapscriptLeaves, &s.Leaves, func() uint64 {
				return recordSize(leavesEncoder, &s.Leaves)
			}, leavesEncoder, leavesDecoder,
		),
		tlv.MakePrimitiveRecord(
			typeTapscriptRevealedScript, &s.RevealedScript,
		),
		tlv.MakePrimitiveRecord(
			typeTapscriptRootHash, &s.RootHash,
		),
		tlv.MakePrimitiveRecord(
			typeTapscriptFullOutputKey, &fullOutputKeyBytes,
		),
	)
	if err != nil {
		return nil, err
	}

	parsedTypes, err := tlvStream.DecodeWithParsedTypes(bytes.NewReader(
		tlvData,
	))
	if err != nil {
		return nil, err
	}

	s.Type = TapscriptType(typ)
	if t, ok := parsedTypes[typeTapscriptControlBlock]; ok && t == nil {
		s.ControlBlock, err = txscript.ParseControlBlock(
			controlBlockBytes,
		)
		if err != nil {
			return nil, fmt.Errorf("error decoding control block: "+
				"%v", err)
		}
	}

	if t, ok := parsedTypes[typeTapscriptFullOutputKey]; ok && t == nil {
		s.FullOutputKey, err = schnorr.ParsePubKey(fullOutputKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("error decoding full output "+
				"key: %v", err)
		}
	}

	return s, nil
}

// leavesEncoder is a custom TLV decoder for a slice of tap leaf records.
func leavesEncoder(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*[]txscript.TapLeaf); ok {
		for _, c := range *v {
			leafVersion := uint8(c.LeafVersion)
			tlvRecords := []tlv.Record{
				tlv.MakePrimitiveRecord(
					typeTapLeafVersion, &leafVersion,
				),
			}

			if len(c.Script) > 0 {
				tlvRecords = append(
					tlvRecords, tlv.MakePrimitiveRecord(
						typeTapLeafScript, &c.Script,
					),
				)

			}

			tlvStream, err := tlv.NewStream(tlvRecords...)
			if err != nil {
				return err
			}

			var leafTLVBytes bytes.Buffer
			err = tlvStream.Encode(&leafTLVBytes)
			if err != nil {
				return err
			}

			// We encode the record with a varint length followed by
			// the _raw_ TLV bytes.
			tlvLen := uint64(len(leafTLVBytes.Bytes()))
			if err := tlv.WriteVarInt(w, tlvLen, buf); err != nil {
				return err
			}

			_, err = w.Write(leafTLVBytes.Bytes())
			if err != nil {
				return err
			}
		}

		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "[]txscript.TapLeaf")
}

// leavesDecoder is a custom TLV decoder for a slice of tap leaf records.
func leavesDecoder(r io.Reader, val interface{}, buf *[8]byte, l uint64) error {
	if v, ok := val.(*[]txscript.TapLeaf); ok {
		var leaves []txscript.TapLeaf

		// Using the length information given, we'll create a new
		// limited reader that'll return an EOF once the end has been
		// reached so the stream stops consuming bytes.
		innerTlvReader := io.LimitedReader{
			R: r,
			N: int64(l),
		}

		for {
			// Read out the varint that encodes the size of this
			// inner TLV record.
			blobSize, err := tlv.ReadVarInt(r, buf)
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}

			innerInnerTlvReader := io.LimitedReader{
				R: &innerTlvReader,
				N: int64(blobSize),
			}

			var (
				leafVersion uint8
				script      []byte
			)
			tlvStream, err := tlv.NewStream(
				tlv.MakePrimitiveRecord(
					typeTapLeafVersion, &leafVersion,
				),
				tlv.MakePrimitiveRecord(
					typeTapLeafScript, &script,
				),
			)
			if err != nil {
				return err
			}

			parsedTypes, err := tlvStream.DecodeWithParsedTypes(
				&innerInnerTlvReader,
			)
			if err != nil {
				return err
			}

			leaf := txscript.TapLeaf{
				LeafVersion: txscript.TapscriptLeafVersion(
					leafVersion,
				),
			}

			// Only set script when actually parsed to make
			// difference between nil and empty slice work
			// correctly. The parsedTypes entry must be nil if it
			// was parsed fully.
			if t, ok := parsedTypes[typeTapLeafScript]; ok && t == nil {
				leaf.Script = script
			}

			leaves = append(leaves, leaf)
		}

		*v = leaves
		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "[]txscript.TapLeaf", l, l)
}

// recordSize returns the amount of bytes this TLV record will occupy when
// encoded.
func recordSize(encoder tlv.Encoder, v interface{}) uint64 {
	var (
		b   bytes.Buffer
		buf [8]byte
	)

	// We know that encoding works since the tests pass in the build this
	// file is checked into, so we'll simplify things and simply encode it
	// ourselves then report the total amount of bytes used.
	if err := encoder(&b, v, &buf); err != nil {
		// This should never error out, but we log it just in case it
		// does.
		log.Errorf("encoding the record failed: %v", err)
	}

	return uint64(len(b.Bytes()))
}
