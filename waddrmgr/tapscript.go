package waddrmgr

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
)

// TapscriptType is a special type denoting the different variants of
// tapscripts.
type TapscriptType uint8

const (
	// TapscriptTypeFullTree is the type of tapscript that knows its full
	// tree with all individual leaves present.
	TapscriptTypeFullTree TapscriptType = 0

	// TapscriptTypePartialReveal is the type of tapscript that only knows
	// a single revealed leaf and the merkle/inclusion proof for the rest of
	// the tree.
	TapscriptTypePartialReveal TapscriptType = 1
)

// Tapscript is a struct that holds either a full taproot tapscript with all
// individual leaves or a single leaf and the corresponding proof to arrive at
// the root hash.
type Tapscript struct {
	// Type is the type of the tapscript.
	Type TapscriptType

	// ControlBlock houses the main information about the internal key and
	// the resulting key's parity. And, in case of the
	// TapscriptTypePartialReveal type, the control block also contains the
	// inclusion proof and the leaf version for the revealed script.
	ControlBlock *txscript.ControlBlock

	// Leaves is the full set of tap leaves in their proper order. This is
	// only set if the Type is TapscriptTypeFullTree.
	Leaves []txscript.TapLeaf

	// RevealedScript is the script of the single revealed script. Is only
	// set if the Type is TapscriptTypePartialReveal.
	RevealedScript []byte
}

// TaprootKey calculates the tweaked taproot key from the given internal key and
// the tree information in this tapscript struct. If any information required to
// calculate the root hash is missing, this method returns an error.
func (t *Tapscript) TaprootKey() (*btcec.PublicKey, error) {
	if t.ControlBlock == nil || t.ControlBlock.InternalKey == nil {
		return nil, fmt.Errorf("internal key is missing")
	}

	switch t.Type {
	case TapscriptTypeFullTree:
		if len(t.Leaves) == 0 {
			return nil, fmt.Errorf("missing leaves")
		}

		tree := txscript.AssembleTaprootScriptTree(t.Leaves...)
		rootHash := tree.RootNode.TapHash()
		return txscript.ComputeTaprootOutputKey(
			t.ControlBlock.InternalKey, rootHash[:],
		), nil

	case TapscriptTypePartialReveal:
		if len(t.RevealedScript) == 0 {
			return nil, fmt.Errorf("revealed script missing")
		}

		rootHash := t.ControlBlock.RootHash(t.RevealedScript)
		return txscript.ComputeTaprootOutputKey(
			t.ControlBlock.InternalKey, rootHash,
		), nil

	default:
		return nil, fmt.Errorf("unknown tapscript type %d", t.Type)
	}
}
