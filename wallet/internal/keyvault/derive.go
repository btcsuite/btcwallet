package keyvault

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// DeriveAccountChildKey parses a serialized account-level extended private key
// and derives the private key at path.Branch and path.Index below it.
//
// The caller keeps ownership of accountPriv and must zero the returned key;
// intermediate keys are zeroed here. Parsing makes an immutable string copy of
// accountPriv that cannot be cleared (ADR 0010).
//
// It is exported only for key use that still happens outside the SQL vault:
// Wallet paths that decrypt through UnsafeVault, and kvdb wallets.
//
// TODO(gus): unexport once signing moves into the vault and kvdb support is
// removed.
func DeriveAccountChildKey(accountPriv []byte,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	account, err := hdkeychain.NewKeyFromString(string(accountPriv))
	if err != nil {
		return nil, fmt.Errorf("parse account priv: %w", err)
	}
	defer account.Zero()

	branch, err := DeriveChild(account, path.Branch)
	if err != nil {
		return nil, fmt.Errorf("derive branch: %w", err)
	}
	defer branch.Zero()

	leaf, err := DeriveChild(branch, path.Index)
	if err != nil {
		return nil, fmt.Errorf("derive index: %w", err)
	}
	defer leaf.Zero()

	privKey, err := leaf.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("derive private key: %w", err)
	}

	return privKey, nil
}

// DeriveChild derives child index i from parent using the
// BIP-32-spec-compliant Derive when safe, falling back to the legacy
// DeriveNonStandard path for parents flagged by IsAffectedByIssue172.
//
// Background: an early version of btcd's hdkeychain (and any wallet
// built on top of it, including every wallet that ever ran through
// waddrmgr) used a buggy CKDpriv implementation — see BIP-32 issue
// #172. The bug: when the secp256k1 modular reduction of the derived
// scalar happened to produce a value < 2^248, big.Int.Bytes() stripped
// the leading zero byte(s) and the persisted private key came out
// shorter than 32 bytes. Probability per hardened derivation is
// ~1 in 256.
//
// The two algorithms diverge ONLY when len(parent.key) < 32: Derive
// right-aligns the parent's key into the 33-byte HMAC input buffer
// (left-padding with zeros, per spec), while DeriveNonStandard
// left-aligns (leaving the high byte zero). For full 32-byte parents
// the two algorithms produce byte-identical output. So:
//
//   - All existing btcwallet wallets had every hardened derivation go
//     through DeriveNonStandard. Any parent that already lives on
//     disk and is 32 bytes long would produce the same child under
//     either algorithm. Any parent that is <32 bytes (flagged by
//     IsAffectedByIssue172) was derived under the buggy path, so its
//     existing on-disk children were also computed under that path;
//     re-deriving them under Derive would yield different keys and
//     the wallet would lose track of the UTXOs at the affected
//     addresses. Hence the runtime fallback.
//
//   - New wallets created today start with a 32-byte master key and,
//     through this helper, never go through DeriveNonStandard
//     unnecessarily. They organically end up on the spec path. The
//     occasional short child Derive itself produces is then routed
//     back to DeriveNonStandard for its descendants, keeping the
//     wallet self-consistent.
//
// We cannot eliminate the DeriveNonStandard fallback until every
// supported wallet's persisted key set passes IsAffectedByIssue172
// (i.e. every persisted ext-key is full-width). That's a future
// migration / deprecation step; this helper bridges the two worlds
// in the meantime.
func DeriveChild(parent *hdkeychain.ExtendedKey,
	i uint32) (*hdkeychain.ExtendedKey, error) {

	if parent.IsAffectedByIssue172() {
		//nolint:wrapcheck,staticcheck
		return parent.DeriveNonStandard(i)
	}

	return parent.Derive(i) //nolint:wrapcheck
}
