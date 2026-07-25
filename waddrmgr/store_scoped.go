package waddrmgr

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/internal/zero"
)

// AddressPlanConflictError reports that an account changed after its next
// address was prepared from a detached durable snapshot.
type AddressPlanConflictError struct {
	// Scope identifies the account's key scope.
	Scope KeyScope

	// Account identifies the account whose indexes changed.
	Account uint32

	// Reason describes the durable state mismatch.
	Reason string
}

// Error describes the stale next-address plan.
func (e *AddressPlanConflictError) Error() string {
	return fmt.Sprintf("next address plan for %s account %d is stale: %s",
		e.Scope, e.Account, e.Reason)
}

// nextAddressPlan contains a fully derived address and the exact durable state
// transition needed to publish it. Its cryptographic preparation is private to
// waddrmgr; Store users can only compare, write, and apply the prepared result.
type nextAddressPlan struct {
	manager   *ScopedKeyManager
	account   AccountState
	address   AddressState
	managed   ManagedAddress
	addressID []byte
	hash      [sha256.Size]byte

	nextExternal   uint32
	nextInternal   uint32
	deriveOnUnlock bool
	applyOnce      sync.Once
}

// Address returns the prepared managed address.
func (p *nextAddressPlan) Address() ManagedAddress {
	return p.managed
}

// Commit revalidates the expected account indexes, writes the exact prepared
// address state, and arranges cache publication after commit.
func (p *nextAddressPlan) Commit(tx ManagerReadWriteTx) error {
	state, err := tx.Account(p.account.Scope, p.account.Account)
	if err != nil {
		return err
	}
	if state.NextExternalIndex != p.account.NextExternalIndex ||
		state.NextInternalIndex != p.account.NextInternalIndex {

		return &AddressPlanConflictError{
			Scope:   p.account.Scope,
			Account: p.account.Account,
			Reason:  "derivation indexes changed",
		}
	}

	if err := tx.PutAddress(p.addressID, p.address); err != nil {
		return err
	}
	if err := tx.SetAccountIndexes(
		p.account.Scope, p.account.Account, p.nextExternal,
		p.nextInternal,
	); err != nil {

		return err
	}

	tx.OnCommit(p.Apply)

	return nil
}

// Reconcile compares durable state with the exact initial and committed plan
// states. A durable result remains proven when a later allocation has advanced
// the same account beyond this plan.
func (p *nextAddressPlan) Reconcile(store ManagerReadStore) (bool, bool,
	bool, error) {

	state, err := store.Account(p.account.Scope, p.account.Account)
	if err != nil {
		return false, false, false, err
	}

	storedAddress, addressErr := store.Address(
		p.account.Scope, p.addressID,
	)
	addressDurable := addressErr == nil &&
		samePreparedAddress(storedAddress, p.address)
	if addressErr != nil && !IsError(addressErr, ErrAddressNotFound) {
		return false, false, false, addressErr
	}

	exactIndexes := state.NextExternalIndex == p.nextExternal &&
		state.NextInternalIndex == p.nextInternal
	if addressDurable && state.NextExternalIndex >= p.nextExternal &&
		state.NextInternalIndex >= p.nextInternal {

		return true, false, exactIndexes, nil
	}

	absent := IsError(addressErr, ErrAddressNotFound) &&
		state.NextExternalIndex == p.account.NextExternalIndex &&
		state.NextInternalIndex == p.account.NextInternalIndex

	return false, absent, false, nil
}

// Apply publishes a proven durable next-address plan to manager caches once.
func (p *nextAddressPlan) Apply() {
	p.applyOnce.Do(func() {
		s := p.manager
		s.mtx.Lock()
		defer s.mtx.Unlock()

		info := s.acctInfo[p.account.Account]
		if info != nil {
			info.nextExternalIndex = p.nextExternal
			info.nextInternalIndex = p.nextInternal
			info.storeStale = false
			if *p.address.Branch == InternalBranch {
				info.lastInternalAddr = p.managed
			} else {
				info.lastExternalAddr = p.managed
			}
		}

		key := addrKey(p.addressID)
		s.addrs[key] = p.managed
		s.used[key] = false
		s.storeAddrs[string(p.hash[:])] = p.managed
		if p.deriveOnUnlock {
			s.deriveOnUnlock = append(
				s.deriveOnUnlock, &unlockDeriveInfo{
					managedAddr: p.managed,
					branch:      *p.address.Branch,
					index:       *p.address.Index,
				},
			)
		}
	})
}

// samePreparedAddress reports whether a durable address row is exactly the
// non-hash state prepared before its transaction began.
func samePreparedAddress(a, b AddressState) bool {
	return a.Scope == b.Scope && a.Account == b.Account &&
		a.Type == b.Type && a.AddedAt.Equal(b.AddedAt) &&
		a.SyncStatus == b.SyncStatus && equalUint32(a.Branch, b.Branch) &&
		equalUint32(a.Index, b.Index) &&
		bytes.Equal(a.EncryptedPubKey, b.EncryptedPubKey) &&
		bytes.Equal(a.EncryptedPrivKey, b.EncryptedPrivKey) &&
		bytes.Equal(a.EncryptedHash, b.EncryptedHash) &&
		bytes.Equal(a.EncryptedScript, b.EncryptedScript) &&
		equalUint8(a.WitnessVersion, b.WitnessVersion) &&
		equalBool(a.IsSecretScript, b.IsSecretScript) && a.Used == b.Used
}

// equalUint32 compares optional uint32 values.
func equalUint32(a, b *uint32) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// equalUint8 compares optional uint8 values.
func equalUint8(a, b *uint8) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// equalBool compares optional bool values.
func equalBool(a, b *bool) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// managedAddressFromStoreState reconstructs one managed address from durable
// state. The scoped manager mutex must be held for writes.
func (s *ScopedKeyManager) managedAddressFromStoreState(
	state AddressState) (ManagedAddress, error) {

	switch state.Type {
	case AddressChain:
		if state.Branch == nil || state.Index == nil {
			return nil, errors.New("stored chain address path is missing")
		}

		info := s.acctInfo[state.Account]
		if info == nil {
			str := fmt.Sprintf("account %d not found", state.Account)
			return nil, managerError(ErrAccountNotFound, str, nil)
		}

		watchOnly := s.rootManager.WatchOnly() ||
			len(info.acctKeyEncrypted) == 0
		private := !s.rootManager.IsLocked() && !watchOnly
		key, err := s.deriveKey(
			info, *state.Branch, *state.Index, private,
		)
		if err != nil {
			return nil, err
		}
		defer key.Zero()

		path := DerivationPath{
			InternalAccount:      state.Account,
			Account:              info.acctKeyPub.ChildIndex(),
			Branch:               *state.Branch,
			Index:                *state.Index,
			MasterKeyFingerprint: info.masterKeyFingerprint,
		}
		managed, err := newManagedAddressFromExtKey(
			s, path, key, s.accountAddrType(
				info, *state.Branch == InternalBranch,
			), info,
		)
		if err != nil {
			return nil, err
		}
		if *state.Branch == InternalBranch {
			managed.internal = true
		}

		if !private && !watchOnly {
			s.deriveOnUnlock = append(
				s.deriveOnUnlock, &unlockDeriveInfo{
					managedAddr: managed,
					branch:      *state.Branch,
					index:       *state.Index,
				},
			)
		}

		return managed, nil

	case AddressImported:
		pubBytes, err := s.rootManager.cryptoKeyPub.Decrypt(
			state.EncryptedPubKey,
		)
		if err != nil {
			return nil, managerError(
				ErrCrypto, "failed to decrypt imported public key", err,
			)
		}
		defer zero.Bytes(pubBytes)

		pubKey, err := btcec.ParsePubKey(pubBytes)
		if err != nil {
			return nil, managerError(
				ErrCrypto, "invalid imported public key", err,
			)
		}

		managed, err := newManagedAddressWithoutPrivKey(
			s, ImportedDerivationPath, pubKey,
			len(pubBytes) == btcec.PubKeyBytesLenCompressed,
			s.addrSchema.ExternalAddrType,
		)
		if err != nil {
			return nil, err
		}
		managed.privKeyEncrypted = copyBytes(state.EncryptedPrivKey)
		managed.imported = true

		return managed, nil

	case AddressScript:
		scriptHash, err := s.rootManager.cryptoKeyPub.Decrypt(
			state.EncryptedHash,
		)
		if err != nil {
			return nil, managerError(
				ErrCrypto, "failed to decrypt imported script hash", err,
			)
		}
		defer zero.Bytes(scriptHash)

		return newScriptAddress(
			s, state.Account, scriptHash, state.EncryptedScript,
		)

	case AddressWitnessScript, AddressTaprootScript:
		if state.WitnessVersion == nil || state.IsSecretScript == nil {
			return nil, errors.New("stored witness script metadata is missing")
		}

		scriptIdent, err := s.rootManager.cryptoKeyPub.Decrypt(
			state.EncryptedHash,
		)
		if err != nil {
			return nil, managerError(
				ErrCrypto, "failed to decrypt imported script identity", err,
			)
		}
		defer zero.Bytes(scriptIdent)

		return newWitnessScriptAddress(
			s, state.Account, scriptIdent, state.EncryptedScript,
			*state.WitnessVersion, *state.IsSecretScript,
		)

	default:
		return nil, fmt.Errorf("%w: type %d in scope %s",
			ErrStoreAddressTypeUnsupported, state.Type, s.scope)
	}
}

// AddressFromStore returns and caches one managed address from durable state.
func (s *ScopedKeyManager) AddressFromStore(store ManagerReadStore,
	addr address.Address) (ManagedAddress, error) {

	if pubKeyAddr, ok := addr.(*address.AddressPubKey); ok {
		addr = pubKeyAddr.AddressPubKeyHash()
	}

	key := addrKey(addr.ScriptAddress())
	s.mtx.RLock()
	managed := s.addrs[key]
	s.mtx.RUnlock()
	if managed != nil {
		return managed, nil
	}

	state, err := store.Address(s.scope, addr.ScriptAddress())
	if err != nil {
		return nil, err
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if managed = s.addrs[key]; managed != nil {
		return managed, nil
	}

	managed, err = s.managedAddressFromStoreState(state)
	if err != nil {
		return nil, err
	}
	s.addrs[key] = managed
	s.storeAddrs[string(state.Hash)] = managed
	s.used[key] = state.Used

	return managed, nil
}

// AddrAccountFromStore returns the account associated with a durable address.
func (s *ScopedKeyManager) AddrAccountFromStore(store ManagerReadStore,
	addr address.Address) (uint32, error) {

	state, err := store.Address(s.scope, addr.ScriptAddress())
	if err != nil {
		return 0, err
	}

	return state.Account, nil
}

// LookupAccountFromStore returns the account number associated with a name.
func (s *ScopedKeyManager) LookupAccountFromStore(store ManagerReadStore,
	name string) (uint32, error) {

	state, err := store.AccountByName(s.scope, name)
	if err != nil {
		return 0, err
	}

	return state.Account, nil
}

// AccountNameFromStore returns one durable account name.
func (s *ScopedKeyManager) AccountNameFromStore(store ManagerReadStore,
	account uint32) (string, error) {

	state, err := store.Account(s.scope, account)
	if err != nil {
		return "", err
	}

	return state.Name, nil
}

// ForEachAccountFromStore visits every durable account in storage order.
func (s *ScopedKeyManager) ForEachAccountFromStore(store ManagerReadStore,
	fn func(uint32) error) error {

	accounts, err := store.Accounts(s.scope)
	if err != nil {
		return err
	}

	for _, account := range accounts {
		if err := fn(account.Account); err != nil {
			return err
		}
	}

	return nil
}

// ForEachAccountAddressFromStore visits each durable address in one account.
func (s *ScopedKeyManager) ForEachAccountAddressFromStore(
	store ManagerReadStore, account uint32,
	fn func(ManagedAddress) error) error {

	states, err := store.AccountAddresses(s.scope, account)
	if err != nil {
		return err
	}

	for _, state := range states {
		s.mtx.Lock()
		managed := s.storeAddrs[string(state.Hash)]
		var stateErr error
		if managed == nil {
			managed, stateErr = s.managedAddressFromStoreState(state)
		}
		if stateErr == nil && managed != nil {
			key := addrKey(managed.Address().ScriptAddress())
			s.addrs[key] = managed
			s.storeAddrs[string(state.Hash)] = managed
			s.used[key] = state.Used
		}
		s.mtx.Unlock()
		if stateErr != nil {
			return stateErr
		}

		if err := fn(managed); err != nil {
			return err
		}
	}

	return nil
}

// forEachActiveAddressFromStore visits active durable addresses, optionally
// restricting the result to internal addresses.
func (s *ScopedKeyManager) forEachActiveAddressFromStore(
	store ManagerReadStore, internalOnly bool,
	fn func(address.Address) error) error {

	states, err := store.ActiveAddresses(s.scope)
	if err != nil {
		return err
	}

	for _, state := range states {
		s.mtx.Lock()
		managed := s.storeAddrs[string(state.Hash)]
		var stateErr error
		if managed == nil {
			managed, stateErr = s.managedAddressFromStoreState(state)
		}
		if stateErr == nil && managed != nil {
			key := addrKey(managed.Address().ScriptAddress())
			s.addrs[key] = managed
			s.storeAddrs[string(state.Hash)] = managed
			s.used[key] = state.Used
		}
		s.mtx.Unlock()
		if stateErr != nil {
			return stateErr
		}
		if internalOnly && !managed.Internal() {
			continue
		}

		if err := fn(managed.Address()); err != nil {
			return err
		}
	}

	return nil
}

// ForEachActiveAddressFromStore visits every active durable address.
func (s *ScopedKeyManager) ForEachActiveAddressFromStore(
	store ManagerReadStore, fn func(address.Address) error) error {

	return s.forEachActiveAddressFromStore(store, false, fn)
}

// ForEachInternalActiveAddressFromStore visits active durable change
// addresses.
func (s *ScopedKeyManager) ForEachInternalActiveAddressFromStore(
	store ManagerReadStore, fn func(address.Address) error) error {

	return s.forEachActiveAddressFromStore(store, true, fn)
}

// ManagedAddressFromStoreStates reconstructs one address from detached account
// and address rows without reading a Store or changing manager caches.
func (s *ScopedKeyManager) ManagedAddressFromStoreStates(
	account AccountState, state AddressState) (ManagedAddress, error) {

	if state.Scope != s.scope {
		return nil, fmt.Errorf("address scope %s does not match manager %s",
			state.Scope, s.scope)
	}
	if state.Type != AddressChain {
		s.mtx.Lock()
		defer s.mtx.Unlock()

		return s.managedAddressFromStoreState(state)
	}
	if account.Scope != state.Scope || account.Account != state.Account {
		return nil, fmt.Errorf("account state does not own stored address")
	}
	if state.Branch == nil || state.Index == nil {
		return nil, errors.New("stored chain address path is missing")
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	info, err := s.accountInfoFromState(account)
	if err != nil {
		return nil, err
	}
	defer zeroAccountInfo(info)

	watchOnly := s.rootManager.WatchOnly() ||
		len(info.acctKeyEncrypted) == 0
	private := !s.rootManager.IsLocked() && !watchOnly
	key, err := s.deriveKey(info, *state.Branch, *state.Index, private)
	if err != nil {
		return nil, err
	}
	defer key.Zero()

	path := DerivationPath{
		InternalAccount:      state.Account,
		Account:              info.acctKeyPub.ChildIndex(),
		Branch:               *state.Branch,
		Index:                *state.Index,
		MasterKeyFingerprint: info.masterKeyFingerprint,
	}
	managed, err := newManagedAddressFromExtKey(
		s, path, key, s.accountAddrType(
			info, *state.Branch == InternalBranch,
		), info,
	)
	if err != nil {
		return nil, err
	}
	if *state.Branch == InternalBranch {
		managed.internal = true
	}

	return managed, nil
}

// PrepareNextInternalAddress derives a complete internal-address plan from an
// owned account snapshot. No Store transaction may be active while it runs.
//
//nolint:revive // Callers only need the opaque plan's exported methods.
func (s *ScopedKeyManager) PrepareNextInternalAddress(
	state AccountState) (*nextAddressPlan, error) {

	if state.Scope != s.scope {
		return nil, fmt.Errorf("account scope %s does not match manager %s",
			state.Scope, s.scope)
	}
	if state.Account > MaxAccountNum {
		return nil, managerError(
			ErrAccountNumTooHigh, errAcctTooHigh, nil,
		)
	}
	if state.NextInternalIndex >= MaxAddressesPerAccount {
		return nil, managerError(
			ErrTooManyAddresses, "maximum address count reached", nil,
		)
	}

	state = copyAccountState(state)

	s.mtx.Lock()
	defer s.mtx.Unlock()

	info, err := s.accountInfoFromState(state)
	if err != nil {
		return nil, err
	}
	defer zeroAccountInfo(info)

	watchOnly := s.rootManager.WatchOnly() ||
		len(info.acctKeyEncrypted) == 0
	accountKey := info.acctKeyPub
	if !s.rootManager.IsLocked() && !watchOnly {
		if info.acctKeyPriv == nil {
			return nil, managerError(
				ErrLocked, "private account key is unavailable", nil,
			)
		}
		accountKey = info.acctKeyPriv
	}

	branch := uint32(InternalBranch)
	branchKey, err := accountKey.DeriveNonStandard( // nolint:staticcheck
		branch,
	)
	if err != nil {
		return nil, managerError(
			ErrKeyChain, "failed to derive internal branch", err,
		)
	}
	defer branchKey.Zero()

	index := state.NextInternalIndex
	var child *hdkeychain.ExtendedKey
	for {
		child, err = branchKey.DeriveNonStandard(index) // nolint:staticcheck
		if errors.Is(err, hdkeychain.ErrInvalidChild) {
			index++
			if index >= MaxAddressesPerAccount {
				return nil, managerError(
					ErrTooManyAddresses,
					"maximum address count reached", nil,
				)
			}

			continue
		}
		if err != nil {
			return nil, managerError(
				ErrKeyChain, fmt.Sprintf(
					"failed to generate child %d", index,
				), err,
			)
		}

		break
	}
	child.SetNet(s.rootManager.chainParams)
	defer child.Zero()

	path := DerivationPath{
		InternalAccount:      state.Account,
		Account:              info.acctKeyPub.ChildIndex(),
		Branch:               branch,
		Index:                index,
		MasterKeyFingerprint: info.masterKeyFingerprint,
	}
	managed, err := newManagedAddressFromExtKey(
		s, path, child, s.accountAddrType(info, true), info,
	)
	if err != nil {
		return nil, err
	}
	managed.internal = true

	addressID := append([]byte(nil), managed.Address().ScriptAddress()...)
	addressIndex := index
	addressState := AddressState{
		Scope:      s.scope,
		Account:    state.Account,
		Type:       AddressChain,
		AddedAt:    time.Unix(time.Now().Unix(), 0),
		SyncStatus: AddressSyncFull,
		Branch:     &branch,
		Index:      &addressIndex,
	}

	return &nextAddressPlan{
		manager:        s,
		account:        state,
		address:        addressState,
		managed:        managed,
		addressID:      addressID,
		hash:           sha256.Sum256(addressID),
		nextExternal:   state.NextExternalIndex,
		nextInternal:   index + 1,
		deriveOnUnlock: !child.IsPrivate() && !watchOnly,
	}, nil
}

// zeroAccountInfo clears detached extended-key material after preparation.
func zeroAccountInfo(info *accountInfo) {
	if info == nil {
		return
	}
	if info.acctKeyPriv != nil {
		info.acctKeyPriv.Zero()
	}
	if info.acctKeyPub != nil {
		info.acctKeyPub.Zero()
	}
	zero.Bytes(info.acctKeyEncrypted)
}

// nextAddressFromStore derives and persists one address on the selected branch
// while publishing cache changes only after commit.
func (s *ScopedKeyManager) nextAddressFromStore(tx ManagerReadWriteTx,
	account uint32, internal bool) (ManagedAddress, *AccountProperties,
	error) {

	if account > MaxAccountNum {
		return nil, nil, managerError(
			ErrAccountNumTooHigh, errAcctTooHigh, nil,
		)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	state, err := tx.Account(s.scope, account)
	if err != nil {
		return nil, nil, err
	}

	branch := uint32(ExternalBranch)
	nextIndex := state.NextExternalIndex
	if internal {
		branch = InternalBranch
		nextIndex = state.NextInternalIndex
	}
	if nextIndex >= MaxAddressesPerAccount {
		return nil, nil, managerError(
			ErrTooManyAddresses, "maximum address count reached", nil,
		)
	}

	cacheInfo := s.acctInfo[account]
	info := cacheInfo
	if info == nil {
		info, err = s.accountInfoFromState(state)
		if err != nil {
			return nil, nil, err
		}
	}

	watchOnly := s.rootManager.WatchOnly() ||
		len(info.acctKeyEncrypted) == 0
	accountKey := info.acctKeyPub
	if !s.rootManager.IsLocked() && !watchOnly {
		if info.acctKeyPriv == nil {
			return nil, nil, managerError(
				ErrLocked, "private account key is unavailable", nil,
			)
		}
		accountKey = info.acctKeyPriv
	}

	branchKey, err := accountKey.DeriveNonStandard(branch) // nolint:staticcheck
	if err != nil {
		return nil, nil, managerError(
			ErrKeyChain, fmt.Sprintf("failed to derive branch %d", branch),
			err,
		)
	}
	defer branchKey.Zero()

	index := nextIndex
	var child *hdkeychain.ExtendedKey
	for {
		child, err = branchKey.DeriveNonStandard(index) // nolint:staticcheck
		if errors.Is(err, hdkeychain.ErrInvalidChild) {
			index++
			if index >= MaxAddressesPerAccount {
				return nil, nil, managerError(
					ErrTooManyAddresses,
					"maximum address count reached", nil,
				)
			}
			continue
		}
		if err != nil {
			return nil, nil, managerError(
				ErrKeyChain, fmt.Sprintf(
					"failed to generate child %d", index,
				), err,
			)
		}
		break
	}
	child.SetNet(s.rootManager.chainParams)
	deriveOnUnlock := !child.IsPrivate() && !watchOnly

	path := DerivationPath{
		InternalAccount:      account,
		Account:              info.acctKeyPub.ChildIndex(),
		Branch:               branch,
		Index:                index,
		MasterKeyFingerprint: info.masterKeyFingerprint,
	}
	managed, err := newManagedAddressFromExtKey(
		s, path, child, s.accountAddrType(info, internal), info,
	)
	child.Zero()
	if err != nil {
		return nil, nil, err
	}
	if internal {
		managed.internal = true
	}

	addressIndex := index
	err = tx.PutAddress(
		managed.Address().ScriptAddress(), AddressState{
			Scope:      s.scope,
			Account:    account,
			Type:       AddressChain,
			AddedAt:    time.Now(),
			SyncStatus: AddressSyncFull,
			Branch:     &branch,
			Index:      &addressIndex,
		},
	)
	if err != nil {
		return nil, nil, err
	}

	newNextIndex := index + 1
	nextExternal := state.NextExternalIndex
	nextInternal := state.NextInternalIndex
	if internal {
		nextInternal = newNextIndex
	} else {
		nextExternal = newNextIndex
	}
	err = tx.SetAccountIndexes(
		s.scope, account, nextExternal, nextInternal,
	)
	if err != nil {
		return nil, nil, err
	}

	props, err := s.accountPropertiesFromInfo(account, info)
	if err != nil {
		return nil, nil, err
	}
	props.ExternalKeyCount = nextExternal
	props.InternalKeyCount = nextInternal
	props.AccountName = state.Name

	tx.OnCommit(func() {
		s.mtx.Lock()
		defer s.mtx.Unlock()

		if current := s.acctInfo[account]; current != nil {
			cacheInfo = current
		} else {
			cacheInfo = info
			s.acctInfo[account] = info
		}
		cacheInfo.acctName = state.Name
		cacheInfo.nextExternalIndex = nextExternal
		cacheInfo.nextInternalIndex = nextInternal
		cacheInfo.storeStale = false
		if internal {
			cacheInfo.lastInternalAddr = managed
		} else {
			cacheInfo.lastExternalAddr = managed
		}

		key := addrKey(managed.Address().ScriptAddress())
		s.addrs[key] = managed
		s.used[key] = false
		hash := sha256.Sum256(managed.Address().ScriptAddress())
		s.storeAddrs[string(hash[:])] = managed
		if deriveOnUnlock {
			s.deriveOnUnlock = append(s.deriveOnUnlock, &unlockDeriveInfo{
				managedAddr: managed,
				branch:      branch,
				index:       index,
			})
		}
	})

	return managed, props, nil
}

// NextInternalAddressFromStore derives and persists one internal address.
func (s *ScopedKeyManager) NextInternalAddressFromStore(
	tx ManagerReadWriteTx, account uint32) (ManagedAddress,
	*AccountProperties, error) {

	return s.nextAddressFromStore(tx, account, true)
}

// LastExternalAddressFromStore returns the latest durable external address.
func (s *ScopedKeyManager) LastExternalAddressFromStore(
	store ManagerReadStore, account uint32) (ManagedAddress, error) {

	_, err := s.AccountPropertiesFromStore(store, account)
	if err != nil {
		return nil, err
	}

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	info := s.acctInfo[account]
	if info != nil && info.nextExternalIndex > 0 {
		return info.lastExternalAddr, nil
	}

	return nil, managerError(
		ErrAddressNotFound, "no previous external address", nil,
	)
}

// LastInternalAddressFromStore returns the latest durable internal address.
func (s *ScopedKeyManager) LastInternalAddressFromStore(
	store ManagerReadStore, account uint32) (ManagedAddress, error) {

	_, err := s.AccountPropertiesFromStore(store, account)
	if err != nil {
		return nil, err
	}

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	info := s.acctInfo[account]
	if info != nil && info.nextInternalIndex > 0 {
		return info.lastInternalAddr, nil
	}

	return nil, managerError(
		ErrAddressNotFound, "no previous internal address", nil,
	)
}

// DeriveFromKeyPathFromStore derives a managed address using durable account
// state without requiring that account to have been published to the cache.
func (s *ScopedKeyManager) DeriveFromKeyPathFromStore(store ManagerReadStore,
	path DerivationPath) (ManagedAddress, error) {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	state, err := store.Account(s.scope, path.InternalAccount)
	if err != nil {
		return nil, err
	}

	info := s.acctInfo[path.InternalAccount]
	if info == nil {
		info, err = s.accountInfoFromState(state)
		if err != nil {
			return nil, err
		}
	}

	private := !s.rootManager.IsLocked() &&
		!s.rootManager.WatchOnly() && info.acctKeyPriv != nil
	key, err := s.deriveKey(info, path.Branch, path.Index, private)
	if err != nil {
		return nil, err
	}

	return s.keyToManaged(key, path, info)
}

// DeriveFromKeyPathFromAccountState derives an address from detached durable
// account state without reading a Store or changing manager caches. It is used
// to prepare recovery lookahead while no database transaction is active.
func (s *ScopedKeyManager) DeriveFromKeyPathFromAccountState(
	state AccountState, path DerivationPath) (ManagedAddress, error) {

	if state.Scope != s.scope {
		return nil, fmt.Errorf("account scope %s does not match manager %s",
			state.Scope, s.scope)
	}
	if state.Account != path.InternalAccount {
		return nil, fmt.Errorf("account %d does not match derivation account %d",
			state.Account, path.InternalAccount)
	}

	// Recovery only needs public addresses. Avoid decrypting or retaining
	// private account material in the detached derivation state.
	state.EncryptedPrivKey = nil

	s.mtx.Lock()
	defer s.mtx.Unlock()

	info, err := s.accountInfoFromState(state)
	if err != nil {
		return nil, err
	}
	defer info.acctKeyPub.Zero()

	key, err := s.deriveKey(info, path.Branch, path.Index, false)
	if err != nil {
		return nil, err
	}

	managed, err := newManagedAddressFromExtKey(
		s, path, key, s.accountAddrType(
			info, path.Branch == InternalBranch,
		), info,
	)
	key.Zero()
	if err != nil {
		return nil, err
	}
	if path.Branch == InternalBranch {
		managed.internal = true
	}

	return managed, nil
}

// newAccountFromStore derives and persists one private HD account. The scoped
// manager mutex must be held for writes.
func (s *ScopedKeyManager) newAccountFromStore(tx ManagerReadWriteTx,
	account uint32, name string) (*AccountProperties, error) {

	if err := ValidateAccountName(name); err != nil {
		return nil, err
	}

	_, err := tx.AccountByName(s.scope, name)
	if err == nil {
		return nil, managerError(
			ErrDuplicateAccount,
			"account with the same name already exists", nil,
		)
	}
	if !IsError(err, ErrAccountNotFound) {
		return nil, err
	}

	scopeState, err := tx.KeyScope(s.scope)
	if err != nil {
		return nil, err
	}
	serializedKey, err := s.rootManager.cryptoKeyPriv.Decrypt(
		scopeState.EncryptedCoinPrivKey,
	)
	if err != nil {
		return nil, managerError(
			ErrLocked, "failed to decrypt cointype private key", err,
		)
	}
	defer zero.Bytes(serializedKey)

	coinTypeKey, err := hdkeychain.NewKeyFromString(string(serializedKey))
	if err != nil {
		return nil, managerError(
			ErrKeyChain, "failed to decode cointype private key", err,
		)
	}
	defer coinTypeKey.Zero()

	acctKeyPriv, err := deriveAccountKey(coinTypeKey, account)
	if err != nil {
		return nil, managerError(
			ErrKeyChain, "failed to derive account private key", err,
		)
	}
	defer acctKeyPriv.Zero()

	acctKeyPub, err := acctKeyPriv.Neuter()
	if err != nil {
		return nil, managerError(
			ErrKeyChain, "failed to derive account public key", err,
		)
	}
	defer acctKeyPub.Zero()

	pubEncrypted, err := s.rootManager.cryptoKeyPub.Encrypt(
		[]byte(acctKeyPub.String()),
	)
	if err != nil {
		return nil, managerError(
			ErrCrypto, "failed to encrypt account public key", err,
		)
	}
	privEncrypted, err := s.rootManager.cryptoKeyPriv.Encrypt(
		[]byte(acctKeyPriv.String()),
	)
	if err != nil {
		return nil, managerError(
			ErrCrypto, "failed to encrypt account private key", err,
		)
	}

	state := AccountState{
		Scope:            s.scope,
		Account:          account,
		Type:             AccountDefault,
		Name:             name,
		EncryptedPubKey:  pubEncrypted,
		EncryptedPrivKey: privEncrypted,
	}
	if err := tx.PutAccount(state); err != nil {
		return nil, err
	}
	if err := tx.SetLastAccount(s.scope, account); err != nil {
		return nil, err
	}

	info, err := s.accountInfoFromState(state)
	if err != nil {
		return nil, err
	}
	props, err := s.accountPropertiesFromInfo(account, info)
	if err != nil {
		return nil, err
	}

	tx.OnCommit(func() {
		s.mtx.Lock()
		defer s.mtx.Unlock()

		s.acctInfo[account] = info
	})

	return props, nil
}

// NewAccountFromStore creates the next private HD account.
func (s *ScopedKeyManager) NewAccountFromStore(tx ManagerReadWriteTx,
	name string) (uint32, *AccountProperties, error) {

	if s.rootManager.WatchOnly() {
		return 0, nil, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}
	if s.rootManager.IsLocked() {
		return 0, nil, managerError(ErrLocked, errLocked, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	scopeState, err := tx.KeyScope(s.scope)
	if err != nil {
		return 0, nil, err
	}
	account := scopeState.LastAccount + 1
	props, err := s.newAccountFromStore(tx, account, name)

	return account, props, err
}

// NewRawAccountFromStore creates a private HD account with an explicit number.
func (s *ScopedKeyManager) NewRawAccountFromStore(
	tx ManagerReadWriteTx, account uint32) error {

	if s.rootManager.WatchOnly() {
		return managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}
	if s.rootManager.IsLocked() {
		return managerError(ErrLocked, errLocked, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	_, err := s.newAccountFromStore(
		tx, account, fmt.Sprintf("act:%v", account),
	)
	return err
}

// NewAccountWatchingOnlyFromStore creates the next imported extended-public-key
// account.
func (s *ScopedKeyManager) NewAccountWatchingOnlyFromStore(
	tx ManagerReadWriteTx, name string, pubKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32,
	addrSchema *ScopeAddrSchema) (uint32, *AccountProperties, error) {

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if err := ValidateAccountName(name); err != nil {
		return 0, nil, err
	}
	_, err := tx.AccountByName(s.scope, name)
	if err == nil {
		return 0, nil, managerError(
			ErrDuplicateAccount,
			"account with the same name already exists", nil,
		)
	}
	if !IsError(err, ErrAccountNotFound) {
		return 0, nil, err
	}

	scopeState, err := tx.KeyScope(s.scope)
	if err != nil {
		return 0, nil, err
	}
	account := scopeState.LastAccount + 1
	pubEncrypted, err := s.rootManager.cryptoKeyPub.Encrypt(
		[]byte(pubKey.String()),
	)
	if err != nil {
		return 0, nil, managerError(
			ErrCrypto, "failed to encrypt account public key", err,
		)
	}

	state := AccountState{
		Scope:                s.scope,
		Account:              account,
		Type:                 AccountWatchOnly,
		Name:                 name,
		EncryptedPubKey:      pubEncrypted,
		MasterKeyFingerprint: masterKeyFingerprint,
		AddrSchema:           addrSchema,
	}
	if err := tx.PutAccount(state); err != nil {
		return 0, nil, err
	}
	if err := tx.SetLastAccount(s.scope, account); err != nil {
		return 0, nil, err
	}

	info, err := s.accountInfoFromState(state)
	if err != nil {
		return 0, nil, err
	}
	props, err := s.accountPropertiesFromInfo(account, info)
	if err != nil {
		return 0, nil, err
	}

	tx.OnCommit(func() {
		s.mtx.Lock()
		defer s.mtx.Unlock()

		s.acctInfo[account] = info
	})

	return account, props, nil
}

// RenameAccountFromStore persists a new account name and publishes it after
// commit.
func (s *ScopedKeyManager) RenameAccountFromStore(tx ManagerReadWriteTx,
	account uint32, name string) (*AccountProperties, error) {

	if isReservedAccountNum(account) {
		return nil, managerError(
			ErrInvalidAccount, "reserved account cannot be renamed", nil,
		)
	}
	if err := ValidateAccountName(name); err != nil {
		return nil, err
	}
	_, err := tx.AccountByName(s.scope, name)
	if err == nil {
		return nil, managerError(
			ErrDuplicateAccount,
			"account with the same name already exists", nil,
		)
	}
	if !IsError(err, ErrAccountNotFound) {
		return nil, err
	}

	state, err := tx.Account(s.scope, account)
	if err != nil {
		return nil, err
	}
	if err := tx.RenameAccount(s.scope, account, name); err != nil {
		return nil, err
	}
	state.Name = name

	s.mtx.Lock()
	info := s.acctInfo[account]
	if info == nil {
		info, err = s.accountInfoFromState(state)
	}
	if err != nil {
		s.mtx.Unlock()
		return nil, err
	}
	props, err := s.accountPropertiesFromInfo(account, info)
	s.mtx.Unlock()
	if err != nil {
		return nil, err
	}
	props.AccountName = name

	tx.OnCommit(func() {
		s.mtx.Lock()
		defer s.mtx.Unlock()

		info.acctName = name
		s.acctInfo[account] = info
	})

	return props, nil
}

// importedKeyID returns the durable identifier for an imported public key.
func (s *ScopedKeyManager) importedKeyID(serializedPubKey []byte,
	addrType AddressType) ([]byte, error) {

	switch addrType {
	case PubKeyHash, WitnessPubKey:
		return address.Hash160(serializedPubKey), nil

	case NestedWitnessPubKey:
		pubKeyHash := address.Hash160(serializedPubKey)
		witnessAddr, err := address.NewAddressWitnessPubKeyHash(
			pubKeyHash, s.rootManager.chainParams,
		)
		if err != nil {
			return nil, err
		}
		witnessScript, err := txscript.PayToAddrScript(witnessAddr)
		if err != nil {
			return nil, err
		}

		return address.Hash160(witnessScript), nil

	case TaprootPubKey:
		pubKey, err := btcec.ParsePubKey(serializedPubKey)
		if err != nil {
			return nil, err
		}
		taprootKey := txscript.ComputeTaprootKeyNoScript(pubKey)

		return schnorr.SerializePubKey(taprootKey), nil

	default:
		return nil, fmt.Errorf("unsupported address type %v", addrType)
	}
}

// lowerStartBlockFromStore atomically lowers the durable import start block.
func lowerStartBlockFromStore(tx ManagerReadWriteStore,
	block *BlockStamp) (bool, error) {

	if block == nil {
		return false, nil
	}

	syncState, err := tx.SyncState()
	if err != nil {
		return false, err
	}
	if block.Height >= syncState.StartBlock.Height {
		return false, nil
	}

	syncState.StartBlock = *block
	if err := tx.PutSyncState(syncState); err != nil {
		return false, err
	}

	return true, nil
}

// putImportedKeyFromStore persists an imported key and any earlier start block.
func (s *ScopedKeyManager) putImportedKeyFromStore(tx ManagerReadWriteTx,
	serializedPubKey, encryptedPrivKey []byte, addrType AddressType,
	block *BlockStamp) ([]byte, bool, error) {

	addressID, err := s.importedKeyID(serializedPubKey, addrType)
	if err != nil {
		return nil, false, err
	}

	_, err = tx.Address(s.scope, addressID)
	if err == nil {
		str := fmt.Sprintf(
			"address for public key %x already exists", serializedPubKey,
		)
		return nil, false, managerError(ErrDuplicateAddress, str, nil)
	}
	if !IsError(err, ErrAddressNotFound) {
		return nil, false, err
	}

	encryptedPubKey, err := s.rootManager.cryptoKeyPub.Encrypt(
		serializedPubKey,
	)
	if err != nil {
		return nil, false, managerError(
			ErrCrypto, "failed to encrypt imported public key", err,
		)
	}

	err = tx.PutAddress(addressID, AddressState{
		Scope:            s.scope,
		Account:          ImportedAddrAccount,
		Type:             AddressImported,
		AddedAt:          time.Now(),
		SyncStatus:       AddressSyncNone,
		EncryptedPubKey:  encryptedPubKey,
		EncryptedPrivKey: encryptedPrivKey,
	})
	if err != nil {
		return nil, false, err
	}

	updateStart, err := lowerStartBlockFromStore(tx, block)
	if err != nil {
		return nil, false, err
	}

	return addressID, updateStart, nil
}

// cacheImportedAddress publishes an imported managed address after commit. The
// scoped manager mutex must be held for writes.
func (s *ScopedKeyManager) cacheImportedAddress(addressID []byte,
	managed ManagedAddress) {

	key := addrKey(addressID)
	s.addrs[key] = managed
	s.used[key] = false
	hash := sha256.Sum256(addressID)
	s.storeAddrs[string(hash[:])] = managed
}

// ImportPublicKeyFromStore imports one public key through a writable store.
func (s *ScopedKeyManager) ImportPublicKeyFromStore(tx ManagerReadWriteTx,
	pubKey *btcec.PublicKey, block *BlockStamp) (ManagedAddress, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	serialized := pubKey.SerializeCompressed()
	addressID, updateStart, err := s.putImportedKeyFromStore(
		tx, serialized, nil, s.addrSchema.ExternalAddrType, block,
	)
	if err != nil {
		return nil, err
	}

	managed, err := newManagedAddressWithoutPrivKey(
		s, ImportedDerivationPath, pubKey, true,
		s.addrSchema.ExternalAddrType,
	)
	if err != nil {
		return nil, err
	}
	managed.imported = true

	tx.OnCommit(func() {
		s.mtx.Lock()
		s.cacheImportedAddress(addressID, managed)
		s.mtx.Unlock()
		if updateStart {
			s.rootManager.mtx.Lock()
			if block.Height <
				s.rootManager.syncState.startBlock.Height {

				s.rootManager.syncState.startBlock = *block
			}
			s.rootManager.mtx.Unlock()
		}
	})

	return managed, nil
}

// ImportPrivateKeyFromStore imports one private key through a writable store.
func (s *ScopedKeyManager) ImportPrivateKeyFromStore(tx ManagerReadWriteTx,
	wif *btcutil.WIF, block *BlockStamp) (ManagedPubKeyAddress, error) {

	if !wif.IsForNet(s.rootManager.chainParams) {
		str := fmt.Sprintf("private key is not for network %s",
			s.rootManager.chainParams.Name)
		return nil, managerError(ErrWrongNet, str, nil)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.rootManager.IsLocked() && !s.rootManager.WatchOnly() {
		return nil, managerError(ErrLocked, errLocked, nil)
	}

	var encryptedPrivKey []byte
	if !s.rootManager.WatchOnly() {
		privKeyBytes := wif.PrivKey.Serialize()
		var err error
		encryptedPrivKey, err = s.rootManager.cryptoKeyPriv.Encrypt(
			privKeyBytes,
		)
		zero.Bytes(privKeyBytes)
		if err != nil {
			return nil, managerError(
				ErrCrypto, "failed to encrypt imported private key", err,
			)
		}
	}

	serialized := wif.SerializePubKey()
	addressID, updateStart, err := s.putImportedKeyFromStore(
		tx, serialized, encryptedPrivKey,
		s.addrSchema.ExternalAddrType, block,
	)
	if err != nil {
		return nil, err
	}

	var managed *managedAddress
	if s.rootManager.WatchOnly() {
		managed, err = newManagedAddressWithoutPrivKey(
			s, ImportedDerivationPath, wif.PrivKey.PubKey(),
			wif.CompressPubKey, s.addrSchema.ExternalAddrType,
		)
	} else {
		managed, err = newManagedAddress(
			s, ImportedDerivationPath, wif.PrivKey,
			wif.CompressPubKey, s.addrSchema.ExternalAddrType, nil,
		)
	}
	if err != nil {
		return nil, err
	}
	managed.imported = true

	tx.OnCommit(func() {
		s.mtx.Lock()
		s.cacheImportedAddress(addressID, managed)
		s.mtx.Unlock()
		if updateStart {
			s.rootManager.mtx.Lock()
			if block.Height <
				s.rootManager.syncState.startBlock.Height {

				s.rootManager.syncState.startBlock = *block
			}
			s.rootManager.mtx.Unlock()
		}
	})

	return managed, nil
}

// importScriptFromStore persists one legacy, witness, or taproot script.
func (s *ScopedKeyManager) importScriptFromStore(tx ManagerReadWriteTx,
	identity Identity, script []byte, block *BlockStamp, addrType AddressType,
	witnessVersion byte, isSecretScript bool) (ManagedScriptAddress, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	if isSecretScript && s.rootManager.IsLocked() {
		return nil, managerError(ErrLocked, errLocked, nil)
	}
	if isSecretScript && s.rootManager.WatchOnly() {
		return nil, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	scriptID := identity()
	_, err := tx.Address(s.scope, scriptID)
	if err == nil {
		str := fmt.Sprintf(
			"address for script hash/key %x already exists", scriptID,
		)
		return nil, managerError(ErrDuplicateAddress, str, nil)
	}
	if !IsError(err, ErrAddressNotFound) {
		return nil, err
	}

	encryptedHash, err := s.rootManager.cryptoKeyPub.Encrypt(scriptID)
	if err != nil {
		return nil, managerError(
			ErrCrypto, "failed to encrypt script identity", err,
		)
	}
	cryptoKey := s.rootManager.cryptoKeyScript
	if !isSecretScript {
		cryptoKey = s.rootManager.cryptoKeyPub
	}
	encryptedScript, err := cryptoKey.Encrypt(script)
	if err != nil {
		return nil, managerError(
			ErrCrypto, "failed to encrypt imported script", err,
		)
	}

	storeType := AddressScript
	var version *uint8
	var secret *bool
	if addrType == WitnessScript || addrType == TaprootScript {
		storeType = AddressWitnessScript
		if addrType == TaprootScript {
			storeType = AddressTaprootScript
		}
		version = &witnessVersion
		secret = &isSecretScript
	}
	err = tx.PutAddress(scriptID, AddressState{
		Scope:           s.scope,
		Account:         ImportedAddrAccount,
		Type:            storeType,
		AddedAt:         time.Now(),
		SyncStatus:      AddressSyncNone,
		EncryptedHash:   encryptedHash,
		EncryptedScript: encryptedScript,
		WitnessVersion:  version,
		IsSecretScript:  secret,
	})
	if err != nil {
		return nil, err
	}

	updateStart, err := lowerStartBlockFromStore(tx, block)
	if err != nil {
		return nil, err
	}

	var managed ManagedScriptAddress
	if addrType == WitnessScript || addrType == TaprootScript {
		managed, err = newWitnessScriptAddress(
			s, ImportedAddrAccount, scriptID, encryptedScript,
			witnessVersion, isSecretScript,
		)
	} else {
		managed, err = newScriptAddress(
			s, ImportedAddrAccount, scriptID, encryptedScript,
		)
	}
	if err != nil {
		return nil, err
	}
	if setter, ok := managed.(clearTextScriptSetter); ok {
		setter.setClearTextScript(script)
	}

	tx.OnCommit(func() {
		s.mtx.Lock()
		s.cacheImportedAddress(scriptID, managed)
		s.mtx.Unlock()
		if updateStart {
			s.rootManager.mtx.Lock()
			if block.Height <
				s.rootManager.syncState.startBlock.Height {

				s.rootManager.syncState.startBlock = *block
			}
			s.rootManager.mtx.Unlock()
		}
	})

	return managed, nil
}

// ImportScriptFromStore imports one legacy pay-to-script-hash script.
func (s *ScopedKeyManager) ImportScriptFromStore(tx ManagerReadWriteTx,
	script []byte, block *BlockStamp) (ManagedScriptAddress, error) {

	return s.importScriptFromStore(
		tx, ScriptHashIdentity(script), script, block, Script, 0, true,
	)
}

// ImportWitnessScriptFromStore imports one witness script.
func (s *ScopedKeyManager) ImportWitnessScriptFromStore(
	tx ManagerReadWriteTx, script []byte, block *BlockStamp,
	witnessVersion byte, isSecretScript bool) (ManagedScriptAddress, error) {

	return s.importScriptFromStore(
		tx, WitnessScriptHashIdentity(script), script, block,
		WitnessScript, witnessVersion, isSecretScript,
	)
}

// ImportTaprootScriptFromStore imports one tapscript tree or full-key spend.
func (s *ScopedKeyManager) ImportTaprootScriptFromStore(
	tx ManagerReadWriteTx, tapscript *Tapscript, block *BlockStamp,
	witnessVersion byte,
	isSecretScript bool) (ManagedTaprootScriptAddress, error) {

	if witnessVersion != witnessVersionV1 {
		return nil, fmt.Errorf(
			"invalid witness version %d for taproot script",
			witnessVersion,
		)
	}

	taprootKey, err := tapscript.TaprootKey()
	if err != nil {
		return nil, fmt.Errorf("error calculating script root: %w", err)
	}
	script, err := tlvEncodeTaprootScript(tapscript)
	if err != nil {
		return nil, fmt.Errorf("error encoding taproot script: %w", err)
	}

	managed, err := s.importScriptFromStore(
		tx, TaprootIdentity(taprootKey), script, block, TaprootScript,
		witnessVersion, isSecretScript,
	)
	if err != nil {
		return nil, err
	}

	return managed.(ManagedTaprootScriptAddress), nil
}

// MarkUsedFromStore marks an address used and updates the cache after commit.
func (s *ScopedKeyManager) MarkUsedFromStore(tx ManagerReadWriteTx,
	addr address.Address) error {

	addressID := addr.ScriptAddress()
	if err := tx.MarkAddressUsed(s.scope, addressID); err != nil {
		return err
	}

	tx.OnCommit(func() {
		s.mtx.Lock()
		defer s.mtx.Unlock()
		s.used[addrKey(addressID)] = true
	})

	return nil
}
