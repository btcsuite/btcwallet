// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet provides the AddressManager interface for generating and
// inspecting wallet addresses and scripts.
//
//nolint:wrapcheck
package wallet

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
)

// MaxBulkAddressCount bounds one atomic allocation and registration request.
const MaxBulkAddressCount uint32 = 100

var (
	// ErrAddressDerivationExhausted means too few normal children remain to
	// fill a batch. All attempted indexes, including valid candidates, are
	// consumed without inserting or returning any batch addresses.
	ErrAddressDerivationExhausted = errors.New("address derivation exhausted")

	// errMissingAccountPubKey is returned by deriveAddressData when the
	// AddressDerivationParams arrive without the account-level extended public
	// key required to derive an address. The wallet's account loader is
	// expected to fill this in for every SQL-store account before address
	// derivation.
	errMissingAccountPubKey = errors.New(
		"missing account public key for derivation",
	)

	// ErrDerivationPathNotFound is returned when the derivation path for a
	// given script cannot be found. This may be because the script does
	// not belong to the wallet, is imported, or is not a pubkey-based
	// script.
	ErrDerivationPathNotFound = errors.New("derivation path not found")

	// ErrAddressNotFound is returned when an address is not known to the
	// wallet.
	ErrAddressNotFound = errors.New("address not found")

	// ErrUnknownAddrType is an error returned when a wallet function is
	// called with an unknown address type.
	ErrUnknownAddrType = errors.New("unknown address type")

	// ErrImportedAccountNoAddrGen is an error returned when a new address
	// is requested for the default imported account within the wallet.
	ErrImportedAccountNoAddrGen = errors.New("addresses cannot be " +
		"generated for the default imported account")

	// ErrNotPubKeyAddress is an error returned when a function requires a
	// public key address, but a different type of address is provided.
	ErrNotPubKeyAddress = errors.New(
		"address is not a p2wkh or np2wkh address",
	)

	// ErrUnableToExtractAddress is returned when an address cannot be
	// extracted from a pkscript.
	ErrUnableToExtractAddress = errors.New("unable to extract address")
)

// addressManagerPageLimit is the transitional address iteration page size.
// TODO(yy): Make this configurable once the address store is fully wired.
const addressManagerPageLimit = 500

// AddressProperty represents an address and its balance.
type AddressProperty struct {
	// Address is the address.
	Address address.Address

	// Balance is the total unspent balance of the address, including both
	// confirmed and unconfirmed funds.
	Balance btcutil.Amount
}

// AddressInfo describes wallet-owned metadata about one managed address.
type AddressInfo struct {
	// Addr is the bitcoin address itself.
	Addr address.Address

	// AddrType identifies the wallet-managed address type for this concrete
	// address.
	AddrType waddrmgr.AddressType

	// Imported reports whether the address was imported instead of derived
	// from a wallet scope.
	Imported bool

	// Internal reports whether the address belongs to the wallet's internal
	// branch.
	Internal bool

	// Compressed reports whether the underlying pubkey address uses
	// compressed keys.
	Compressed bool

	// PubKey is set for managed pubkey addresses.
	PubKey *btcec.PublicKey

	// Derivation is set when the wallet knows how to derive the address from a
	// wallet scope.
	Derivation *AddressDerivation
}

// AddressDerivation captures the wallet derivation metadata for one address.
type AddressDerivation struct {
	// KeyScope identifies the scope that owns the address.
	KeyScope waddrmgr.KeyScope

	// Account is the BIP-32 account within the scope.
	Account uint32

	// Branch is the BIP-32 branch within the scope.
	Branch uint32

	// Index is the child index within the branch.
	Index uint32

	// MasterKeyFingerprint is the root fingerprint used by
	// hardware-wallet-aware flows.
	MasterKeyFingerprint uint32
}

// KeyOrigin identifies the wallet-root account from which a key is derived.
// Child coordinates belong to AllocatedKey so they are not repeated here.
type KeyOrigin struct {
	// KeyScope identifies the account's purpose and coin type.
	KeyScope waddrmgr.KeyScope

	// Account is the wallet-derived BIP44 account number within KeyScope.
	Account uint32

	// MasterKeyFingerprint preserves the account's stored root fingerprint.
	MasterKeyFingerprint uint32
}

// AllocatedKey contains a persisted child key and its position in the account.
// Imported xpubs retain child coordinates without claiming a wallet-root path.
type AllocatedKey struct {
	// PubKey is the public key of the allocated child.
	PubKey *btcec.PublicKey

	// Branch identifies the external or internal account branch.
	Branch uint32

	// Index is the allocated child index within Branch.
	Index uint32

	// Origin is nil for imported accounts without a wallet-root account path.
	// Callers can use their account selector with Branch and Index to derive
	// the same child again even when Origin is nil.
	Origin *KeyOrigin
}

// OutputScriptInfo captures the address metadata and scripts needed to spend a
// wallet-controlled output.
type OutputScriptInfo struct {
	AddressInfo

	// WitnessProgram is the script passed as the witness subscript for witness
	// signing. For native P2WPKH and P2TR spends, this is the output pkScript
	// itself. For nested P2WPKH-in-P2SH spends, this is the inner witness
	// program, for example `OP_0 <20-byte-key-hash>`.
	WitnessProgram []byte

	// RedeemScript is the redeem script committed to by the outer P2SH output.
	// For nested P2WPKH-in-P2SH spends, this is the inner witness program, for
	// example `OP_0 <20-byte-key-hash>`. Native witness spends, such as P2WPKH
	// and P2TR, leave this nil.
	RedeemScript []byte

	// SigScript is the final scriptSig wrapper needed to spend outputs that are
	// wrapped in P2SH.
	// For nested P2WPKH-in-P2SH spends, this is a single push of RedeemScript.
	// Native witness spends leave this nil.
	SigScript []byte

	// Script is the plaintext redeem or witness script for a script-based
	// output (P2SH multisig, P2WSH, taproot script-path). It is decrypted
	// from the address's stored encrypted script and, for taproot
	// script-path imports, is the single revealed leaf script. It is nil
	// for single-key (pubkey-spend) outputs, whose subscript is derived
	// from the public key instead.
	Script []byte
}

// AddressManager provides an interface for generating and inspecting wallet
// addresses and scripts.
type AddressManager interface {
	// AllocateNextKey creates and persists the next child key and returns
	// its public key, child coordinates and available wallet-root origin.
	AllocateNextKey(ctx context.Context, selector AccountSelector,
		internal bool) (*AllocatedKey, error)

	// NewBulkAddresses force-allocates 1..MaxBulkAddressCount fresh addresses
	// for the selected account and branch (internal when true). SQL wallets
	// register the complete committed batch before returning it. Errors return
	// no batch but may leave durable allocation progress; callers must not
	// assume retrying will reuse it. Kvdb and NoChainSync are unsupported.
	NewBulkAddresses(ctx context.Context, selector AccountSelector,
		internal bool, count uint32) ([]AddressInfo, error)

	// NewAddress returns a receiving address for the selected account and
	// branch (internal when true). SQL wallets return the oldest unused
	// child, allocating exactly one only when none exists, and register it
	// before returning. Kvdb allocates the next child on every call.
	// NoChainSync accounts return ErrAccountOperationUnsupported. Use
	// NewBulkAddresses for deliberate fresh allocation.
	NewAddress(ctx context.Context, selector AccountSelector,
		internal bool) (AddressInfo, error)

	// GetAddressInfo returns detailed information about a managed address. If
	// the address is not known to the wallet, the returned error wraps
	// ErrAddressNotFound for errors.Is matching.
	GetAddressInfo(ctx context.Context, a address.Address) (AddressInfo, error)

	// ListAddresses lists all addresses for a given account, including
	// their balances.
	ListAddresses(ctx context.Context, accountName string,
		addrType waddrmgr.AddressType) ([]AddressProperty, error)

	// ImportPublicKey imports a single public key without private signing
	// material. SQL wallets accept the import only when the wallet is
	// watch-only under ADR 0012. The legacy kvdb backend retains its
	// grandfathered mixed-mode behavior until migration.
	ImportPublicKey(ctx context.Context, pubKey *btcec.PublicKey,
		addrType waddrmgr.AddressType) error

	// ImportTaprootScript imports a taproot script for tracking. Script
	// presence describes a spending condition, not private signing authority.
	// SQL wallets accept the script-only import only when the wallet is
	// watch-only under ADR 0012. The legacy kvdb backend retains its
	// grandfathered mixed-mode behavior until migration.
	ImportTaprootScript(ctx context.Context,
		tapscript waddrmgr.Tapscript) (AddressInfo, error)

	// ScriptForOutput returns the wallet metadata and spending scripts for a
	// given UTXO.
	ScriptForOutput(ctx context.Context, output wire.TxOut) (
		OutputScriptInfo, error)

	// GetDerivationInfo returns the BIP-32 derivation path for a given
	// address.
	GetDerivationInfo(ctx context.Context,
		addr address.Address) (*psbt.Bip32Derivation, error)
}

// A compile time check to ensure that Wallet implements the interface.
var _ AddressManager = (*Wallet)(nil)

// addressInfoFromManagedAddress converts one legacy managed address into the
// wallet-owned metadata shape used by the prep work.
//
//nolint:unparam // Preserve the legacy caller error shape during migration.
func addressInfoFromManagedAddress(
	managedAddr waddrmgr.ManagedAddress) (AddressInfo, error) {

	info := AddressInfo{
		Addr:       managedAddr.Address(),
		AddrType:   managedAddr.AddrType(),
		Imported:   managedAddr.Imported(),
		Internal:   managedAddr.Internal(),
		Compressed: managedAddr.Compressed(),
	}

	pubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		return info, nil
	}

	info.PubKey = pubKeyAddr.PubKey()

	keyScope, derivationPath, ok := pubKeyAddr.DerivationInfo()
	if !ok {
		return info, nil
	}

	// A managed address that exposes DerivationInfo is wallet-seed derived
	// and always has a real BIP44 account number, so it is safe to expose
	// as a public derivation path.
	info.Derivation = &AddressDerivation{
		KeyScope:             keyScope,
		Account:              derivationPath.Account,
		Branch:               derivationPath.Branch,
		Index:                derivationPath.Index,
		MasterKeyFingerprint: derivationPath.MasterKeyFingerprint,
	}

	return info, nil
}

// addressPageRequest returns the standard page request used by address-manager
// iteration helpers.
func addressPageRequest() (page.Request[uint32], error) {
	return page.NewRequest[uint32](addressManagerPageLimit)
}

// addressInfoFromStoreAddress converts one db-native address record into the
// wallet-owned address metadata shape exposed by the public API.
func addressInfoFromStoreAddress(storeAddr *db.AddressInfo,
	chainParams *chaincfg.Params) (AddressInfo, error) {

	addr := extractAddrFromPKScript(storeAddr.ScriptPubKey, chainParams)
	if addr == nil {
		return AddressInfo{}, fmt.Errorf("%w: from pkscript %x",
			ErrUnableToExtractAddress, storeAddr.ScriptPubKey)
	}

	addrType, err := addresstype.ToWallet(
		storeAddr.AddrType, storeAddr.HasScript,
	)
	if err != nil {
		return AddressInfo{}, fmt.Errorf("%w: %v", ErrUnknownAddrType,
			storeAddr.AddrType)
	}

	internal := storeAddr.HasDerivationPath && storeAddr.Branch == 1

	info := AddressInfo{
		Addr:       addr,
		AddrType:   addrType,
		Imported:   !storeAddr.HasDerivationPath,
		Internal:   internal,
		Compressed: storeAddressPubKeyCompressed(storeAddr.PubKey),
	}

	if len(storeAddr.PubKey) == 0 {
		return info, nil
	}

	pubKey, err := btcec.ParsePubKey(storeAddr.PubKey)
	if err != nil {
		return AddressInfo{}, fmt.Errorf("parse pubkey: %w", err)
	}

	info.PubKey = pubKey

	// A derivation describes a wallet BIP44 path, so it needs a
	// wallet-derived account number. Raw single imports have none, and
	// neither do imported-xpub children: the store masks an imported
	// account's number to 0, which is the wallet's own default derived
	// account, so publishing a derivation for them would hand callers a
	// path into the wrong account. Both cases expose no derivation at all,
	// and signing refuses them with ErrNoAssocPrivateKey before any secret
	// lookup.
	if storeAddr.AccountNumber == nil {
		return info, nil
	}

	info.Derivation = &AddressDerivation{
		KeyScope: waddrmgr.KeyScope{
			Purpose: storeAddr.KeyScope.Purpose,
			Coin:    storeAddr.KeyScope.Coin,
		},
		Account:              *storeAddr.AccountNumber,
		Branch:               storeAddr.Branch,
		Index:                storeAddr.Index,
		MasterKeyFingerprint: storeAddr.MasterKeyFingerprint,
	}

	return info, nil
}

// deriveStoreAddress derives one address, its pkScript, and the leaf compressed
// public key from account public material, using only in-memory HD math and the
// account's address schema — no walletdb and no walletdb-backed
// waddrmgr.Manager. It is the single encoder shared by SQL address generation
// (deriveAddressData) and SQL recovery lookahead, so both produce identical
// addresses for a given (account, branch, index).
func deriveStoreAddress(params db.AddressDerivationParams,
	chainParams *chaincfg.Params) (address.Address, []byte, []byte, error) {

	if len(params.AccountPubKey) == 0 {
		account := "none"
		if params.DerivedAccountNumber != nil {
			account = strconv.FormatUint(
				uint64(*params.DerivedAccountNumber), 10,
			)
		}

		return nil, nil, nil, fmt.Errorf("%w: scope=%v account=%s",
			errMissingAccountPubKey, params.Scope, account)
	}

	accountPubKey, err := hdkeychain.NewKeyFromString(
		string(params.AccountPubKey),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse account "+
			"pubkey: %w", err)
	}

	branchKey, err := deriveChildKey(accountPubKey, params.Branch)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive branch: %w", err)
	}
	defer branchKey.Zero()

	addrKey, err := deriveStoreAddressChild(branchKey, params.Index)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive address "+
			"index: %w", err)
	}
	defer addrKey.Zero()

	pubKey, err := addrKey.ECPubKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive address "+
			"pubkey: %w", err)
	}

	pubKeyBytes := pubKey.SerializeCompressed()

	walletAddrType, err := addresstype.ToWallet(params.AddrType, false)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("address type: %w", err)
	}

	addr, err := walletAddrType.AddrFromPubKeyBytes(
		pubKeyBytes, chainParams,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive address: %w", err)
	}

	scriptPubKey, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pay to addr: %w", err)
	}

	return addr, scriptPubKey, pubKeyBytes, nil
}

// deriveStoreAddressChild marks invalid leaf derivations as consumed children
// while preserving the HD cause used by recovery to skip invalid indexes.
func deriveStoreAddressChild(branchKey *hdkeychain.ExtendedKey,
	index uint32) (*hdkeychain.ExtendedKey, error) {

	key, err := deriveChildKey(branchKey, index)
	if errors.Is(err, hdkeychain.ErrInvalidChild) {
		return nil, fmt.Errorf("%w: %w", db.ErrAddressChildUnavailable, err)
	}

	return key, err
}

// deriveAddressData derives one SQL-store address from account public material
// for the configured network.
func deriveAddressData(chainParams *chaincfg.Params,
	params db.AddressDerivationParams) (*db.DerivedAddressData, error) {

	_, scriptPubKey, pubKeyBytes, err := deriveStoreAddress(
		params, chainParams,
	)
	if err != nil {
		return nil, err
	}

	return &db.DerivedAddressData{
		ScriptPubKey: scriptPubKey,
		PubKey:       pubKeyBytes,
	}, nil
}

// deriveAddressData derives one SQL-store address from account public material.
func (w *Wallet) deriveAddressData(_ context.Context,
	params db.AddressDerivationParams) (*db.DerivedAddressData, error) {

	return deriveAddressData(w.cfg.ChainParams, params)
}

// storeAddressPubKeyCompressed reports whether store pubkey bytes use the
// compressed secp256k1 encoding.
func storeAddressPubKeyCompressed(pubKey []byte) bool {
	return len(pubKey) == btcec.PubKeyBytesLenCompressed
}

// addrBalances returns wallet address balances from store UTXO rows.
func (w *Wallet) addrBalances(ctx context.Context) (map[string]btcutil.Amount,
	error) {

	balances := make(map[string]btcutil.Amount)

	utxos, err := w.store.ListUTXOs(ctx, db.ListUtxosQuery{
		WalletID: w.id,
	})
	if err != nil {
		return nil, fmt.Errorf("list utxos: %w", err)
	}

	for i := range utxos {
		addr := extractAddrFromPKScript(
			utxos[i].PkScript, w.cfg.ChainParams,
		)
		if addr == nil {
			continue
		}

		balances[addr.String()] += utxos[i].Amount
	}

	return balances, nil
}

// allocateNextKeyReq keeps key allocation inside existing Wallet admission
// and reuses the address metadata response without creating a receiving path.
type allocateNextKeyReq struct {
	reqCtx

	selector AccountSelector
	internal bool
	respChan chan allocateNextKeyResp
}

// allocateNextKeyResp delivers the committed child even without a root origin.
type allocateNextKeyResp struct {
	key *AllocatedKey
	err error
}

// newBulkAddressesReq joins allocation and registration to Wallet shutdown.
type newBulkAddressesReq struct {
	reqCtx

	params   db.NewDerivedAddressParams
	count    uint32
	respChan chan bulkAddressesResp
}

// bulkAddressesResp publishes a complete watched batch or only its error.
type bulkAddressesResp struct {
	addresses []AddressInfo
	err       error
}

// newAddressReq keeps selection, fallback allocation, and registration in one
// admission.
type newAddressReq struct {
	reqCtx

	selector AccountSelector
	internal bool
	respChan chan addressInfoResp
}

// getAddressInfoReq borrows the destination until the accepted lookup ends.
type getAddressInfoReq struct {
	reqCtx

	addr     address.Address
	respChan chan addressInfoResp
}

// addressInfoResp returns metadata once the accepted lookup completes.
type addressInfoResp struct {
	info AddressInfo
	err  error
}

// listAddressesReq keeps balance and address iteration under one admission.
type listAddressesReq struct {
	reqCtx

	accountName string
	addrType    waddrmgr.AddressType
	respChan    chan listAddressesResp
}

// listAddressesResp returns the list after balance and address iteration end.
type listAddressesResp struct {
	addresses []AddressProperty
	err       error
}

// importPublicKeyReq borrows the key through persistence and registration.
type importPublicKeyReq struct {
	reqCtx

	pubKey      *btcec.PublicKey
	addrType    waddrmgr.AddressType
	respErrChan chan error
}

// importTaprootScriptReq retains the supplied script through vault encryption.
type importTaprootScriptReq struct {
	reqCtx

	tapscript waddrmgr.Tapscript
	respChan  chan addressInfoResp
}

// scriptForOutputReq borrows script bytes until spending lookups complete.
type scriptForOutputReq struct {
	reqCtx

	output   wire.TxOut
	respChan chan outputScriptResp
}

// outputScriptResp returns spending metadata after dependency access ends.
type outputScriptResp struct {
	info OutputScriptInfo
	err  error
}

// getDerivationInfoReq borrows its destination until path lookup completes.
type getDerivationInfoReq struct {
	reqCtx

	addr     address.Address
	respChan chan derivationInfoResp
}

// derivationInfoResp preserves a path result across cancellation and shutdown.
type derivationInfoResp struct {
	info *psbt.Bip32Derivation
	err  error
}

// NewAddress returns a receiving address for the selected account and branch.
// Internal selects the change branch. The address type always comes from the
// stored account schema.
//
// SQL wallets return the unused child with the lowest derivation index on the
// selected branch, so repeated calls reuse the same address until the wallet
// records it as used. Only when the branch has no unused child is exactly one
// fresh child allocated, using the same atomic path as NewBulkAddresses. The
// selected address is registered from the chain tip before it is returned;
// Neutrino keeps its existing history behavior. Once admitted, registration
// completes even if the caller cancels, and every error returns a zero
// AddressInfo. A failed or canceled delivery leaves the committed child
// unused, so a later call selects it again instead of allocating another.
// ErrIndeterminateCommit never implies that a child is reusable.
//
// Kvdb wallets allocate and notify the next child on every call.
//
// NoChainSync accounts return ErrAccountOperationUnsupported before any
// address is selected, allocated, or registered, because their address use is
// not tracked automatically. Callers that deliberately need fresh addresses
// should use NewBulkAddresses; large unused gaps can hinder seed recovery.
func (w *Wallet) NewAddress(ctx context.Context, selector AccountSelector,
	internal bool) (AddressInfo, error) {

	err := selector.validate()
	if err != nil {
		return AddressInfo{}, fmt.Errorf("%w: %w", ErrInvalidParam, err)
	}

	err = w.state.validateStarted()
	if err != nil {
		return AddressInfo{}, err
	}

	// The reserved import bucket holds raw addresses, not an account xpub.
	// Reject it before admission, as bulk allocation does.
	if isImportedAddrAccountSelector(selector) {
		return AddressInfo{}, ErrImportedAccountNoAddrGen
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := newAddressReq{
		reqCtx:   reqCtx{ctx: ctx},
		selector: selector,
		internal: internal,
		respChan: make(chan addressInfoResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return AddressInfo{}, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.info, result.err
}

// AllocateNextKey creates and persists the next child key and returns its
// public key, child coordinates and available wallet-root origin.
func (w *Wallet) AllocateNextKey(ctx context.Context, selector AccountSelector,
	internal bool) (*AllocatedKey, error) {

	// Validate the selector and lifecycle before admitting allocation work.
	err := selector.validate()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidParam, err)
	}

	err = w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	// Carry the selector into the serialized handler so the Store can resolve
	// and validate the account inside its allocation transaction.
	r := allocateNextKeyReq{
		reqCtx:   reqCtx{ctx: ctx},
		selector: selector,
		internal: internal,
		respChan: make(chan allocateNextKeyResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return nil, err
	}

	// Join admitted work even after cancellation so shutdown cannot close
	// the Store before allocation finishes and its outcome is returned.
	result := <-r.respChan

	if result.err != nil {
		return nil, allocateNextKeyErr(result.err)
	}

	return result.key, nil
}

// allocateNextKeyErr translates native allocator failures into wallet errors.
func allocateNextKeyErr(err error) error {
	// Ambiguity wins over cancellation, without exposing the private runtime
	// identity. Legacy exhaustion uses the same public sentinel as SQL.
	switch {
	case errors.Is(err, dbruntime.ErrAmbiguousTxCommit):
		return fmt.Errorf("%w: %s", ErrIndeterminateCommit, err.Error())
	case isAddrMgrErr(err, waddrmgr.ErrTooManyAddresses):
		return publicAccountErr(err, ErrAddressDerivationExhausted)
	default:
		return bulkAddressErr(err)
	}
}

// handleAllocateNextKey returns a committed child's existing metadata without
// entering the receiving handler's chain-registration path.
func (w *Wallet) handleAllocateNextKey(r allocateNextKeyReq) {
	// Resolve and validate the selector inside the allocator's transaction.
	params := db.NewDerivedAddressParams{
		WalletID:      w.id,
		Scope:         db.KeyScope(r.selector.keyScope),
		AccountNumber: (*uint32)(r.selector.accountNumber),
		Change:        r.internal,
	}
	if r.selector.accountName != nil {
		params.AccountName = *r.selector.accountName
	}

	stored, err := w.store.NewDerivedAddress(r.ctx, params)
	if err != nil {
		r.respChan <- allocateNextKeyResp{err: err}

		return
	}

	// Reuse ordinary lookup conversion for the public key and known root
	// origin. Imported xpub children still retain their stored coordinates.
	info, err := addressInfoFromStoreAddress(stored, w.cfg.ChainParams)
	if err != nil {
		r.respChan <- allocateNextKeyResp{err: err}

		return
	}

	key := &AllocatedKey{
		PubKey: info.PubKey,
		Branch: stored.Branch,
		Index:  stored.Index,
	}

	// Attach only known root-account metadata; a missing origin does not
	// discard the imported child's committed branch or index.
	if path := info.Derivation; path != nil {
		key.Origin = &KeyOrigin{
			KeyScope:             path.KeyScope,
			Account:              path.Account,
			MasterKeyFingerprint: path.MasterKeyFingerprint,
		}
	}

	r.respChan <- allocateNextKeyResp{key: key}
}

// isImportedAddrAccountSelector reports whether the selector names the reserved
// raw-import bucket, which has no account key to derive addresses from.
func isImportedAddrAccountSelector(selector AccountSelector) bool {
	return selector.accountName != nil &&
		*selector.accountName == waddrmgr.ImportedAddrAccountName
}

// newDerivedAddressParams copies a validated semantic selector into Store
// allocation parameters. The Store resolves it inside the write transaction,
// including the receiving-policy guard.
func (w *Wallet) newDerivedAddressParams(selector AccountSelector,
	internal bool) db.NewDerivedAddressParams {

	params := db.NewDerivedAddressParams{
		WalletID:         w.id,
		Scope:            db.KeyScope(selector.keyScope),
		AccountNumber:    (*uint32)(selector.accountNumber),
		Change:           internal,
		RequireChainSync: true,
	}
	if selector.accountName != nil {
		params.AccountName = *selector.accountName
	}

	return params
}

// NewBulkAddresses force-allocates fresh addresses instead of reusing unused
// children. Large unused gaps can hinder seed recovery. Count must be 1..100;
// internal selects the change branch. SQL commits atomically, then registers
// the entire batch using the existing chain backend behavior (including
// Neutrino history). Kvdb and NoChainSync accounts are unsupported.
// Every error returns a nil batch, even when allocation committed. Cancellation
// cannot abandon admitted registration; ErrIndeterminateCommit never implies
// that children are reusable. Terminal exhaustion inserts no batch addresses
// but consumes all attempted indexes, including valid candidates.
func (w *Wallet) NewBulkAddresses(ctx context.Context, selector AccountSelector,
	internal bool, count uint32) ([]AddressInfo, error) {

	if count == 0 || count > MaxBulkAddressCount {
		return nil, fmt.Errorf("%w: count must be 1..%d",
			ErrInvalidParam, MaxBulkAddressCount)
	}

	err := selector.validate()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidParam, err)
	}

	err = w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	// The reserved import bucket holds raw addresses, not an account xpub.
	// Reject it before admission, as NewAddress does.
	if isImportedAddrAccountSelector(selector) {
		return nil, ErrImportedAccountNoAddrGen
	}

	r := newBulkAddressesReq{
		reqCtx:   reqCtx{ctx: ctx},
		params:   w.newDerivedAddressParams(selector, internal),
		count:    count,
		respChan: make(chan bulkAddressesResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return nil, err
	}

	// Once admitted, join all dependency access even if the caller cancels.
	result := <-r.respChan

	return result.addresses, result.err
}

// handleNewBulkAddresses commits a batch before registering its destinations.
// Only the Wallet lifetime can cancel registration of already committed rows.
func (w *Wallet) handleNewBulkAddresses(r newBulkAddressesReq) {
	// Serialize with NewAddress so its oldest-unused selection never races
	// a concurrent allocation on the same wallet. Registration runs unlocked.
	w.addrMu.Lock()
	stored, err := w.allocateDerivedAddresses(r.ctx, r.params, r.count)
	w.addrMu.Unlock()

	if err != nil {
		r.respChan <- bulkAddressesResp{err: err}

		return
	}

	batch, err := w.deliverStoreAddresses(r.ctx, stored)
	r.respChan <- bulkAddressesResp{addresses: batch, err: err}
}

// allocateDerivedAddresses allocates count fresh SQL children and exposes
// wallet-owned error identities.
//
// NOTE: The caller must hold addrMu.
func (w *Wallet) allocateDerivedAddresses(ctx context.Context,
	params db.NewDerivedAddressParams, count uint32) ([]db.AddressInfo,
	error) {

	stored, err := w.store.NewDerivedAddresses(ctx, params, count)
	if err != nil {
		return nil, bulkAddressErr(err)
	}

	return stored, nil
}

// deliverStoreAddresses converts committed addresses to public metadata and
// registers them from the chain tip before the caller may observe them. Only
// the Wallet lifetime can cancel registration; caller cancellation is checked
// afterwards so committed destinations are never left half-registered.
func (w *Wallet) deliverStoreAddresses(ctx context.Context,
	stored []db.AddressInfo) ([]AddressInfo, error) {

	// Reuse the public metadata conversion, including imported-xpub semantics.
	batch := make([]AddressInfo, 0, len(stored))

	addrs := make([]address.Address, 0, len(stored))
	for i := range stored {
		info, err := addressInfoFromStoreAddress(&stored[i], w.cfg.ChainParams)
		if err != nil {
			return nil, err
		}

		batch = append(batch, info)
		addrs = append(addrs, info.Addr)
	}

	//nolint:contextcheck // Only the Wallet lifetime may cancel registration.
	err := w.cfg.Chain.WatchAddrsFromTip(w.lifetimeCtx, addrs)
	if err != nil {
		return nil, err
	}

	err = ctx.Err()
	if err != nil {
		return nil, err
	}

	return batch, nil
}

// bulkAddressErr exposes wallet-owned allocation identities. Ambiguity wins
// over cancellation because it represents potentially committed child indexes.
func bulkAddressErr(err error) error {
	switch {
	case errors.Is(err, dbruntime.ErrAmbiguousTxCommit):
		return fmt.Errorf("%w: %s", ErrIndeterminateCommit, err.Error())
	case errors.Is(err, db.ErrMaxAddressIndexReached):
		return publicAccountErr(err, ErrAddressDerivationExhausted)
	case errors.Is(err, db.ErrAccountOperationUnsupported):
		return publicAccountErr(err, ErrAccountOperationUnsupported)
	case isAccountMissing(err):
		return publicAccountErr(err, ErrAccountNotFound)
	default:
		return publicAccountErr(err, nil)
	}
}

// handleNewAddress delivers the result of an accepted component request.
func (w *Wallet) handleNewAddress(r newAddressReq) {
	info, err := w.newAddress(r.ctx, r.selector, r.internal)
	r.respChan <- addressInfoResp{info: info, err: err}
}

// newAddress resolves the receiving account, then selects or allocates one
// address through the backend-specific path inside its accepted request.
func (w *Wallet) newAddress(ctx context.Context, selector AccountSelector,
	internal bool) (AddressInfo, error) {

	// A ready receiver must not start dependency work for a canceled caller.
	err := ctx.Err()
	if err != nil {
		return AddressInfo{}, err
	}

	accountName, err := w.receivingAccountName(ctx, selector)
	if err != nil {
		return AddressInfo{}, err
	}

	if w.usesKVDBStore() {
		return w.newKVDBAddress(ctx, selector, accountName, internal)
	}

	stored, err := w.oldestUnusedOrNewAddress(
		ctx, selector, accountName, internal,
	)
	if err != nil {
		return AddressInfo{}, err
	}

	delivered, err := w.deliverStoreAddresses(ctx, []db.AddressInfo{stored})
	if err != nil {
		return AddressInfo{}, err
	}

	return delivered[0], nil
}

// receivingAccountName resolves the selector to its account name and enforces
// the receiving policy before any address is read, allocated, or watched.
func (w *Wallet) receivingAccountName(ctx context.Context,
	selector AccountSelector) (string, error) {

	query := db.GetAccountQuery{
		WalletID:      w.id,
		Scope:         db.KeyScope(selector.keyScope),
		Name:          selector.accountName,
		AccountNumber: (*uint32)(selector.accountNumber),
		SkipBalance:   true,
	}

	account, err := w.cache.GetAccount(ctx, query)
	if err != nil {
		// A missing scope also means the requested account is absent.
		var publicErr error
		if isAccountMissing(err) {
			publicErr = ErrAccountNotFound
		}

		return "", publicAccountErr(err, publicErr)
	}

	// A numbered selector may still resolve to the raw-import bucket.
	if account.AccountName == waddrmgr.ImportedAddrAccountName {
		return "", ErrImportedAccountNoAddrGen
	}

	if account.NoChainSync {
		return "", fmt.Errorf("%w: account %q has chain "+
			"synchronization disabled", ErrAccountOperationUnsupported,
			account.AccountName)
	}

	return account.AccountName, nil
}

// oldestUnusedOrNewAddress returns the unused SQL child with the lowest index
// on the selected branch, or allocates exactly one when none exists. It owns
// addrMu for the whole selection so concurrent callers on an empty branch
// observe one allocation and return the same child.
func (w *Wallet) oldestUnusedOrNewAddress(ctx context.Context,
	selector AccountSelector, accountName string,
	internal bool) (db.AddressInfo, error) {

	w.addrMu.Lock()
	defer w.addrMu.Unlock()

	// Waiting for the lock may outlast the caller; do no work for it then.
	err := ctx.Err()
	if err != nil {
		return db.AddressInfo{}, err
	}

	oldest, found, err := w.oldestUnusedAddressLocked(
		ctx, selector.keyScope, accountName, internal,
	)
	if err != nil {
		return db.AddressInfo{}, err
	}

	if found {
		return oldest, nil
	}

	// Keep the original selector so the Store resolves the same account the
	// public batch API would, including numbered selectors.
	stored, err := w.allocateDerivedAddresses(
		ctx, w.newDerivedAddressParams(selector, internal), 1,
	)
	if err != nil {
		return db.AddressInfo{}, err
	}

	return stored[0], nil
}

// oldestUnusedAddressLocked scans every stored address of the account and
// returns the unused derived child with the lowest index on the requested
// branch. Iteration follows row IDs rather than child indexes, so all pages
// are inspected.
//
// NOTE: The caller must hold addrMu.
func (w *Wallet) oldestUnusedAddressLocked(ctx context.Context,
	scope waddrmgr.KeyScope, accountName string,
	internal bool) (db.AddressInfo, bool, error) {

	req, err := addressPageRequest()
	if err != nil {
		return db.AddressInfo{}, false, err
	}

	dbScope := db.KeyScope(scope)
	addresses := w.store.IterAddresses(ctx, db.ListAddressesQuery{
		WalletID:    w.id,
		AccountName: &accountName,
		Scope:       &dbScope,
		Page:        req,
	})

	var (
		oldest db.AddressInfo
		found  bool
	)

	for storeAddr, err := range addresses {
		if err != nil {
			return db.AddressInfo{}, false, err
		}

		if !storeAddr.HasDerivationPath || storeAddr.IsUsed ||
			(storeAddr.Branch == 1) != internal {

			continue
		}

		if found && storeAddr.Index >= oldest.Index {
			continue
		}

		oldest = storeAddr
		found = true
	}

	return oldest, found, nil
}

// newKVDBAddress allocates and notifies the next kvdb child. Kvdb has no batch
// allocator or address-use tracking to reuse, so it always moves forward.
func (w *Wallet) newKVDBAddress(ctx context.Context, selector AccountSelector,
	accountName string, internal bool) (AddressInfo, error) {

	// Require receiving admission during the allocation's existing account
	// read, so excluded accounts consume no child.
	storeAddr, err := w.store.NewDerivedAddress(
		ctx, db.NewDerivedAddressParams{
			WalletID:         w.id,
			AccountName:      accountName,
			Scope:            db.KeyScope(selector.keyScope),
			Change:           internal,
			RequireChainSync: true,
		},
	)
	if err != nil {
		return AddressInfo{}, bulkAddressErr(err)
	}

	info, err := addressInfoFromStoreAddress(storeAddr, w.cfg.ChainParams)
	if err != nil {
		return AddressInfo{}, err
	}

	// Notify the rpc server about the newly created address.
	err = w.cfg.Chain.NotifyReceived([]address.Address{info.Addr})
	if err != nil {
		return AddressInfo{}, err
	}

	return info, nil
}

// GetAddressInfo returns detailed information regarding a wallet address. If
// the address is not known to the wallet, the returned error wraps
// ErrAddressNotFound for errors.Is matching.
func (w *Wallet) GetAddressInfo(ctx context.Context, a address.Address) (
	AddressInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return AddressInfo{}, err
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := getAddressInfoReq{
		reqCtx:   reqCtx{ctx: ctx},
		addr:     a,
		respChan: make(chan addressInfoResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return AddressInfo{}, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.info, result.err
}

// handleGetAddressInfo delivers the result of an accepted component request.
func (w *Wallet) handleGetAddressInfo(r getAddressInfoReq) {
	// Reuse metadata lookup shared with nested signing and script queries.
	info, err := w.getAddressInfo(r.ctx, r.addr)
	r.respChan <- addressInfoResp{info: info, err: err}
}

// getAddressInfo resolves metadata while its outer request owns Store access.
func (w *Wallet) getAddressInfo(ctx context.Context, a address.Address) (
	AddressInfo, error) {

	scriptPubKey, err := txscript.PayToAddrScript(a)
	if err != nil {
		return AddressInfo{}, fmt.Errorf("pay to addr script: %w", err)
	}

	storeAddr, err := w.store.GetAddress(
		ctx, db.GetAddressQuery{
			WalletID:     w.id,
			ScriptPubKey: scriptPubKey,
		},
	)
	if err != nil {
		// Store implementations normalize backend-specific misses before
		// this boundary. Translate only that normalized form so raw legacy
		// manager errors remain unexpected errors.
		if errors.Is(err, db.ErrAddressNotFound) {
			return AddressInfo{}, fmt.Errorf("%w: addr=%v",
				ErrAddressNotFound, a)
		}

		return AddressInfo{}, err
	}

	return addressInfoFromStoreAddress(storeAddr, w.cfg.ChainParams)
}

// ListAddresses lists all addresses for a given account, including their
// balances.
func (w *Wallet) ListAddresses(ctx context.Context, accountName string,
	addrType waddrmgr.AddressType) ([]AddressProperty, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := listAddressesReq{
		reqCtx:      reqCtx{ctx: ctx},
		accountName: accountName,
		addrType:    addrType,
		respChan:    make(chan listAddressesResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return nil, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.addresses, result.err
}

// handleListAddresses reads addresses and balances within one accepted request.
// The admitted caller waits for this result before reusing its inputs.
func (w *Wallet) handleListAddresses(r listAddressesReq) {
	req, err := addressPageRequest()
	if err != nil {
		r.respChan <- listAddressesResp{err: err}

		return
	}

	query, storeAddrType, err := listAddressesQuery(
		w.id, req, r.accountName, r.addrType,
	)
	if err != nil {
		r.respChan <- listAddressesResp{err: err}

		return
	}

	balances, err := w.addrBalances(r.ctx)
	if err != nil {
		r.respChan <- listAddressesResp{err: err}

		return
	}

	properties := make([]AddressProperty, 0)

	addresses := w.store.IterAddresses(r.ctx, query)
	for storeAddr, err := range addresses {
		if err != nil {
			r.respChan <- listAddressesResp{err: err}

			return
		}

		if r.accountName == db.DefaultImportedAccountName &&
			!walletAddressTypeMatches(storeAddr, storeAddrType) {

			continue
		}

		addr := extractAddrFromPKScript(
			storeAddr.ScriptPubKey, w.cfg.ChainParams,
		)
		if addr == nil {
			continue
		}

		properties = append(properties, AddressProperty{
			Address: addr,
			Balance: balances[addr.String()],
		})
	}

	r.respChan <- listAddressesResp{addresses: properties}
}

// walletAddressTypeMatches reports whether a store address row matches a
// wallet-facing address type selector.
func walletAddressTypeMatches(info db.AddressInfo,
	addrType addresstype.StoreType) bool {

	return info.AddrType == addrType.Type &&
		info.HasScript == addrType.HasScript
}

// listAddressesQuery builds the store query for a wallet-facing account name.
// The reserved imported alias has no account row in the SQL store, so it uses a
// wallet-wide query and returns the address type needed for local filtering.
func listAddressesQuery(walletID uint32, req page.Request[uint32],
	accountName string, addrType waddrmgr.AddressType) (
	db.ListAddressesQuery, addresstype.StoreType, error) {

	query := db.ListAddressesQuery{
		WalletID: walletID,
		Page:     req,
	}

	if accountName == db.DefaultImportedAccountName {
		storeAddrType, err := addresstype.FromWallet(addrType)
		if err != nil {
			return query, addresstype.StoreType{}, fmt.Errorf(
				"%w: %v", ErrUnknownAddrType, addrType,
			)
		}

		return query, storeAddrType, nil
	}

	keyScope, err := addrType.KeyScope()
	if err != nil {
		return query, addresstype.StoreType{}, fmt.Errorf(
			"%w: %v", ErrUnknownAddrType, addrType,
		)
	}

	scope := db.KeyScope(keyScope)
	query.AccountName = &accountName
	query.Scope = &scope

	return query, addresstype.StoreType{}, nil
}

// ImportPublicKey imports a single public key without private signing material.
// SQL wallets accept the import only when the wallet is watch-only under ADR
// 0012. The legacy kvdb backend retains its grandfathered mixed-mode behavior
// until migration.
func (w *Wallet) ImportPublicKey(ctx context.Context, pubKey *btcec.PublicKey,
	addrType waddrmgr.AddressType) error {

	err := w.state.validateStarted()
	if err != nil {
		return err
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := importPublicKeyReq{
		reqCtx:      reqCtx{ctx: ctx},
		pubKey:      pubKey,
		addrType:    addrType,
		respErrChan: make(chan error, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	return <-r.respErrChan
}

// handleImportPublicKey persists and registers an accepted public-key import.
// The admitted caller waits for this result before reusing its inputs.
func (w *Wallet) handleImportPublicKey(r importPublicKeyReq) {
	storeAddrType, err := addresstype.FromWallet(r.addrType)
	if err != nil {
		r.respErrChan <- fmt.Errorf("%w: %v", ErrUnknownAddrType, r.addrType)

		return
	}

	serializedPubKey := r.pubKey.SerializeCompressed()

	addr, err := r.addrType.AddrFromPubKeyBytes(
		serializedPubKey, w.cfg.ChainParams,
	)
	if err != nil {
		r.respErrChan <- fmt.Errorf("derive imported address: %w", err)

		return
	}

	scriptPubKey, err := txscript.PayToAddrScript(addr)
	if err != nil {
		r.respErrChan <- fmt.Errorf("pay to addr script: %w", err)

		return
	}

	_, err = w.store.NewImportedAddress(
		r.ctx, db.NewImportedAddressParams{
			WalletID:     w.id,
			AddressType:  storeAddrType.Type,
			ScriptPubKey: scriptPubKey,
			PubKey:       serializedPubKey,
		},
	)
	if err != nil {
		r.respErrChan <- err

		return
	}

	r.respErrChan <- w.cfg.Chain.NotifyReceived([]address.Address{addr})
}

// ImportTaprootScript imports a taproot script for tracking. Script presence
// describes a spending condition, not private signing authority. SQL wallets
// accept the script-only import only when the wallet is watch-only under ADR
// 0012. The legacy kvdb backend retains its grandfathered mixed-mode behavior
// until migration.
func (w *Wallet) ImportTaprootScript(ctx context.Context,
	tapscript waddrmgr.Tapscript) (AddressInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return AddressInfo{}, err
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := importTaprootScriptReq{
		reqCtx:    reqCtx{ctx: ctx},
		tapscript: tapscript,
		respChan:  make(chan addressInfoResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return AddressInfo{}, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.info, result.err
}

// handleImportTaprootScript encrypts and registers the accepted script
// import.
// The admitted caller waits for this result before reusing its inputs.
func (w *Wallet) handleImportTaprootScript(r importTaprootScriptReq) {
	taprootKey, err := r.tapscript.TaprootKey()
	if err != nil {
		r.respChan <- addressInfoResp{err: err}

		return
	}

	addr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(taprootKey), w.cfg.ChainParams,
	)
	if err != nil {
		r.respChan <- addressInfoResp{
			err: fmt.Errorf("taproot address: %w", err),
		}

		return
	}

	scriptPubKey, err := txscript.PayToAddrScript(addr)
	if err != nil {
		r.respChan <- addressInfoResp{
			err: fmt.Errorf("pay to addr script: %w", err),
		}

		return
	}

	encryptedScript, err := encryptTaprootScript(w.keyVault, &r.tapscript)
	if err != nil {
		r.respChan <- addressInfoResp{err: err}

		return
	}

	storeInfo, err := w.store.NewImportedAddress(
		r.ctx, db.NewImportedAddressParams{
			WalletID:        w.id,
			AddressType:     db.TaprootPubKey,
			ScriptPubKey:    scriptPubKey,
			EncryptedScript: encryptedScript,
		},
	)
	if err != nil {
		r.respChan <- addressInfoResp{err: err}

		return
	}

	storeInfo.HasScript = true

	info, err := addressInfoFromStoreAddress(storeInfo, w.cfg.ChainParams)
	if err != nil {
		r.respChan <- addressInfoResp{err: err}

		return
	}

	err = w.cfg.Chain.NotifyReceived([]address.Address{addr})
	if err != nil {
		r.respChan <- addressInfoResp{err: err}

		return
	}

	r.respChan <- addressInfoResp{info: info}
}

// encryptTaprootScript encodes and encrypts taproot script data before the
// encrypted blob is handed to the store.
//
// The wallet's watch-only mode does not enter into it: every vault seals script
// bodies with its script operation, and each backend resolves that to whatever
// key its own format keeps for the purpose.
func encryptTaprootScript(vault keyvault.Vault,
	tapscript *waddrmgr.Tapscript) ([]byte, error) {

	encodedScript, err := waddrmgr.EncodeTaprootScript(tapscript)
	if err != nil {
		return nil, fmt.Errorf("encode tapscript: %w", err)
	}

	encryptedScript, err := vault.Encrypt(waddrmgr.CKTPublic, encodedScript)
	if err != nil {
		return nil, fmt.Errorf("encrypt tapscript: %w", err)
	}

	return encryptedScript, nil
}

// ScriptForOutput returns the address metadata and spending scripts for a given
// UTXO.
//
// This method is essential for constructing the necessary scripts to spend a
// transaction output. It provides the components required to build the
// scriptSig and witness fields of a transaction input.
//
// How it works:
// The method first identifies which of the wallet's addresses corresponds to
// the output's script. It then determines the correct script format (redeem
// script, witness program) based on the address type.
//
// Logical Steps:
//  1. Look up the output's pkScript in the database to find the
//     corresponding managed address.
//  2. Verify that the address is a public key address that the wallet can
//     sign for (e.g., P2WKH, NP2WKH, P2TR).
//  3. Based on the address type, construct the appropriate scripts:
//     - For nested P2WKH (NP2WKH), it returns the inner witness program as the
//     redeem script and also builds the single-push sigScript wrapper used in
//     the final input.
//     - For native SegWit outputs (P2WKH, P2TR), the `witnessProgram` is the
//     output's `pkScript`, while the redeem script and sigScript are nil.
//
// Database Actions:
//   - This method performs a read-only database access to fetch address
//     details from the `waddrmgr` namespace.
//
// Time Complexity:
//   - The operation is dominated by the database lookup for the address, which
//     is typically fast (O(log N) or O(1) with indexing). The script
//     generation is a constant-time operation.
func (w *Wallet) ScriptForOutput(ctx context.Context, output wire.TxOut) (
	OutputScriptInfo, error) {

	err := w.state.validateStarted()
	if err != nil {
		return OutputScriptInfo{}, err
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := scriptForOutputReq{
		reqCtx:   reqCtx{ctx: ctx},
		output:   output,
		respChan: make(chan outputScriptResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return OutputScriptInfo{}, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.info, result.err
}

// handleScriptForOutput delivers the result of an accepted component request.
func (w *Wallet) handleScriptForOutput(r scriptForOutputReq) {
	// Reuse script lookup without re-entering admission from signing or PSBTs.
	info, err := w.scriptForOutput(r.ctx, r.output)
	r.respChan <- outputScriptResp{info: info, err: err}
}

// scriptForOutput resolves spending data without re-entering admission.
func (w *Wallet) scriptForOutput(ctx context.Context, output wire.TxOut) (
	OutputScriptInfo, error) {

	// First, we'll extract the address from the output's pkScript.
	addr := extractAddrFromPKScript(output.PkScript, w.cfg.ChainParams)
	if addr == nil {
		return OutputScriptInfo{}, fmt.Errorf("%w: from pkscript %x",
			ErrUnableToExtractAddress, output.PkScript)
	}

	addressInfo, err := w.getAddressInfo(ctx, addr)
	if err != nil {
		return OutputScriptInfo{}, fmt.Errorf("unable to get address info "+
			"for %s: %w", addr.String(), err)
	}

	// Script-based outputs (P2SH multisig, P2WSH, taproot script-path) have
	// no single spending public key; their subscript is the stored,
	// encrypted redeem or witness script. Resolve it through the store and
	// key vault rather than the pubkey-derived script path below.
	if isScriptSpendAddress(addressInfo) {
		script, err := w.scriptForAddressInfo(
			ctx, addressInfo, output.PkScript,
		)
		if err != nil {
			return OutputScriptInfo{}, err
		}

		return OutputScriptInfo{
			AddressInfo: addressInfo,
			Script:      script,
		}, nil
	}

	witnessProgram, redeemScript, sigScript, err := buildScriptsForAddressInfo(
		addressInfo, output.PkScript, w.cfg.ChainParams,
	)
	if err != nil {
		return OutputScriptInfo{}, err
	}

	return OutputScriptInfo{
		AddressInfo:    addressInfo,
		WitnessProgram: witnessProgram,
		RedeemScript:   redeemScript,
		SigScript:      sigScript,
	}, nil
}

// buildScriptsForAddressInfo constructs the witness program, redeem script,
// and final sigScript for a wallet-owned address metadata record.
func buildScriptsForAddressInfo(addressInfo AddressInfo, pkScript []byte,
	_ *chaincfg.Params) ([]byte, []byte, []byte, error) {

	if addressInfo.PubKey == nil {
		return nil, nil, nil, fmt.Errorf("%w: addr %s", ErrNotPubKeyAddress,
			addressInfo.Addr)
	}

	// For nested witness spends, the redeem script committed to by the outer
	// P2SH output is the inner witness program, while the sigScript is a single
	// push of that redeem script. For all other supported single-key families,
	// the previous output pkScript remains the correct subscript for signing.
	witnessProgram := pkScript

	var (
		redeemScript []byte
		sigScript    []byte
		err          error
	)

	spendType := addressInfo.AddrType.SpendType()
	if spendType == waddrmgr.SpendTypeNestedWitnessKey {
		redeemScript, err = txscript.NewScriptBuilder().
			AddOp(txscript.OP_0).
			AddData(address.Hash160(addressInfo.PubKey.SerializeCompressed())).
			Script()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("build nested witness "+
				"program: %w", err)
		}

		sigScript, err = txscript.NewScriptBuilder().
			AddData(redeemScript).
			Script()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("encode redeem script: %w", err)
		}

		witnessProgram = redeemScript
	} else if spendType != waddrmgr.SpendTypeLegacyKey &&
		spendType != waddrmgr.SpendTypeWitnessKey &&
		spendType != waddrmgr.SpendTypeTaprootKeyPath {

		return nil, nil, nil, fmt.Errorf("%w: %v", ErrUnsupportedAddressType,
			addressInfo.AddrType)
	}

	return witnessProgram, redeemScript, sigScript, nil
}

// GetDerivationInfo returns the BIP-32 derivation path for a given address.
func (w *Wallet) GetDerivationInfo(ctx context.Context,
	addr address.Address) (*psbt.Bip32Derivation, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	// Admission keeps dependency access joined through concurrent Stop.
	r := getDerivationInfoReq{
		reqCtx:   reqCtx{ctx: ctx},
		addr:     addr,
		respChan: make(chan derivationInfoResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return nil, err
	}

	// Once admitted, wait for the result even if cancellation arrives.
	result := <-r.respChan

	return result.info, result.err
}

// handleGetDerivationInfo resolves the path under its accepted outer request.
// The admitted caller waits for this result before reusing its inputs.
func (w *Wallet) handleGetDerivationInfo(r getDerivationInfoReq) {
	// We'll use the address to look up the derivation path.
	addressInfo, err := w.getAddressInfo(r.ctx, r.addr)
	if err != nil {
		r.respChan <- derivationInfoResp{err: err}

		return
	}

	responseInfo, responseErr := derivationForAddressInfo(addressInfo)
	r.respChan <- derivationInfoResp{info: responseInfo, err: responseErr}
}

// derivationForAddressInfo constructs a PSBT Bip32Derivation struct from a
// wallet-owned address metadata record.
func derivationForAddressInfo(addressInfo AddressInfo) (
	*psbt.Bip32Derivation, error) {

	// Imported addresses don't have derivation paths.
	if addressInfo.Imported {
		return nil, fmt.Errorf("%w: addr=%v is imported",
			ErrDerivationPathNotFound, addressInfo.Addr)
	}

	// Only public key addresses carry derivation metadata.
	if addressInfo.PubKey == nil {
		return nil, fmt.Errorf("%w: addr=%v not found",
			ErrDerivationPathNotFound, addressInfo.Addr)
	}

	// Rebuild the BIP-32 path from the wallet-owned derivation metadata.
	if addressInfo.Derivation == nil {
		return nil, fmt.Errorf("%w: derivation info not found for %v",
			ErrDerivationPathNotFound, addressInfo.Addr)
	}

	keyScope := addressInfo.Derivation.KeyScope
	if keyScope == (waddrmgr.KeyScope{}) {
		return nil, fmt.Errorf("%w: derivation scope not found for %v",
			ErrDerivationPathNotFound, addressInfo.Addr)
	}

	derivationInfo := &psbt.Bip32Derivation{
		PubKey:               addressInfo.PubKey.SerializeCompressed(),
		MasterKeyFingerprint: addressInfo.Derivation.MasterKeyFingerprint,
		Bip32Path: []uint32{
			keyScope.Purpose + hdkeychain.HardenedKeyStart,
			keyScope.Coin + hdkeychain.HardenedKeyStart,
			addressInfo.Derivation.Account +
				hdkeychain.HardenedKeyStart,
			addressInfo.Derivation.Branch,
			addressInfo.Derivation.Index,
		},
	}

	return derivationInfo, nil
}
