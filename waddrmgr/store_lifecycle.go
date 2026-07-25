package waddrmgr

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/lightninglabs/neutrino/cache/lru"
)

// createStoreKeyScope derives and persists one default manager key scope.
func createStoreKeyScope(store ManagerReadWriteStore, scope KeyScope,
	schema ScopeAddrSchema, root *hdkeychain.ExtendedKey,
	cryptoKeyPub, cryptoKeyPriv EncryptorDecryptor) error {

	coinTypeKeyPriv, err := deriveCoinTypeKey(root, scope)
	if err != nil {
		return managerError(
			ErrKeyChain, "failed to derive cointype extended key", err,
		)
	}
	defer coinTypeKeyPriv.Zero()

	acctKeyPriv, err := deriveAccountKey(coinTypeKeyPriv, DefaultAccountNum)
	if errors.Is(err, hdkeychain.ErrInvalidChild) {
		return managerError(
			ErrKeyChain, "the provided seed is unusable",
			hdkeychain.ErrUnusableSeed,
		)
	}
	if err != nil {
		return err
	}
	defer acctKeyPriv.Zero()

	if err := checkBranchKeys(acctKeyPriv); err != nil {
		if errors.Is(err, hdkeychain.ErrInvalidChild) {
			return managerError(
				ErrKeyChain, "the provided seed is unusable",
				hdkeychain.ErrUnusableSeed,
			)
		}

		return err
	}

	coinTypeKeyPub, err := coinTypeKeyPriv.Neuter()
	if err != nil {
		return managerError(
			ErrKeyChain, "failed to convert cointype private key", err,
		)
	}
	defer coinTypeKeyPub.Zero()

	acctKeyPub, err := acctKeyPriv.Neuter()
	if err != nil {
		return managerError(
			ErrKeyChain, "failed to convert public key for account", err,
		)
	}
	defer acctKeyPub.Zero()

	coinPubEnc, err := cryptoKeyPub.Encrypt(
		[]byte(coinTypeKeyPub.String()),
	)
	if err != nil {
		return managerError(
			ErrCrypto, "failed to encrypt cointype public key", err,
		)
	}

	coinPrivEnc, err := cryptoKeyPriv.Encrypt(
		[]byte(coinTypeKeyPriv.String()),
	)
	if err != nil {
		return managerError(
			ErrCrypto, "failed to encrypt cointype private key", err,
		)
	}

	acctPubEnc, err := cryptoKeyPub.Encrypt([]byte(acctKeyPub.String()))
	if err != nil {
		return managerError(
			ErrCrypto, "failed to encrypt public key for account", err,
		)
	}

	acctPrivEnc, err := cryptoKeyPriv.Encrypt([]byte(acctKeyPriv.String()))
	if err != nil {
		return managerError(
			ErrCrypto, "failed to encrypt private key for account", err,
		)
	}

	err = store.PutKeyScope(KeyScopeState{
		Scope:                scope,
		AddrSchema:           schema,
		EncryptedCoinPubKey:  coinPubEnc,
		EncryptedCoinPrivKey: coinPrivEnc,
		LastAccount:          DefaultAccountNum,
	})
	if err != nil {
		return err
	}

	err = store.PutAccount(AccountState{
		Scope:            scope,
		Account:          DefaultAccountNum,
		Type:             AccountDefault,
		Name:             defaultAccountName,
		EncryptedPubKey:  acctPubEnc,
		EncryptedPrivKey: acctPrivEnc,
	})
	if err != nil {
		return err
	}

	return store.PutAccount(AccountState{
		Scope:           scope,
		Account:         ImportedAddrAccount,
		Type:            AccountDefault,
		Name:            ImportedAddrAccountName,
		EncryptedPubKey: []byte{},
	})
}

// CreateFromStore initializes a manager through a backend-neutral writable
// store. The caller must provide a single-attempt creation transaction.
func CreateFromStore(store ManagerReadWriteStore,
	rootKey *hdkeychain.ExtendedKey, pubPassphrase, privPassphrase []byte,
	chainParams *chaincfg.Params, config *ScryptOptions,
	birthday time.Time) error {

	isWatchingOnly := rootKey == nil
	if !isWatchingOnly && len(privPassphrase) == 0 {
		return managerError(
			ErrEmptyPassphrase, "private passphrase may not be empty", nil,
		)
	}
	if config == nil {
		config = &DefaultScryptOptions
	}

	masterKeyPub, err := newSecretKey(&pubPassphrase, config)
	if err != nil {
		return managerError(
			ErrCrypto, "failed to create master public key", err,
		)
	}
	defer masterKeyPub.Zero()

	cryptoKeyPub, err := newCryptoKey()
	if err != nil {
		return managerError(
			ErrCrypto, "failed to generate crypto public key", err,
		)
	}
	defer cryptoKeyPub.Zero()

	cryptoKeyPubEnc, err := masterKeyPub.Encrypt(cryptoKeyPub.Bytes())
	if err != nil {
		return managerError(
			ErrCrypto, "failed to encrypt crypto public key", err,
		)
	}

	state := ManagerState{
		Version:               latestMgrVersion,
		CreatedAt:             time.Now(),
		WatchOnly:             isWatchingOnly,
		MasterPubParams:       masterKeyPub.Marshal(),
		EncryptedCryptoPubKey: cryptoKeyPubEnc,
	}

	var cryptoKeyPriv EncryptorDecryptor
	if !isWatchingOnly {
		masterKeyPriv, err := newSecretKey(&privPassphrase, config)
		if err != nil {
			return managerError(
				ErrCrypto, "failed to create master private key", err,
			)
		}
		defer masterKeyPriv.Zero()

		privateKey, err := newCryptoKey()
		if err != nil {
			return managerError(
				ErrCrypto, "failed to generate crypto private key", err,
			)
		}
		defer privateKey.Zero()
		cryptoKeyPriv = privateKey

		cryptoKeyScript, err := newCryptoKey()
		if err != nil {
			return managerError(
				ErrCrypto, "failed to generate crypto script key", err,
			)
		}
		defer cryptoKeyScript.Zero()

		state.MasterPrivParams = masterKeyPriv.Marshal()
		state.EncryptedCryptoPrivKey, err = masterKeyPriv.Encrypt(
			privateKey.Bytes(),
		)
		if err != nil {
			return managerError(
				ErrCrypto, "failed to encrypt crypto private key", err,
			)
		}

		state.EncryptedCryptoScriptKey, err = masterKeyPriv.Encrypt(
			cryptoKeyScript.Bytes(),
		)
		if err != nil {
			return managerError(
				ErrCrypto, "failed to encrypt crypto script key", err,
			)
		}

		rootPubKey, err := rootKey.Neuter()
		if err != nil {
			return managerError(
				ErrKeyChain, "failed to neuter master extended key", err,
			)
		}
		defer rootPubKey.Zero()

		state.EncryptedMasterHDPrivKey, err = privateKey.Encrypt(
			[]byte(rootKey.String()),
		)
		if err != nil {
			return managerError(
				ErrCrypto, "failed to encrypt master private key", err,
			)
		}

		state.EncryptedMasterHDPubKey, err = cryptoKeyPub.Encrypt(
			[]byte(rootPubKey.String()),
		)
		if err != nil {
			return managerError(
				ErrCrypto, "failed to encrypt master public key", err,
			)
		}
	}

	err = store.PutManagerState(state)
	if err != nil {
		return err
	}

	genesis := BlockStamp{
		Hash:      *chainParams.GenesisHash,
		Height:    0,
		Timestamp: chainParams.GenesisBlock.Header.Timestamp,
	}
	err = store.PutSyncState(SyncState{
		StartBlock: genesis,
		SyncedTo:   genesis,
		Birthday:   birthday.Add(-48 * time.Hour),
	})
	if err != nil {
		return err
	}

	if isWatchingOnly {
		return nil
	}

	for _, scope := range DefaultKeyScopes {
		err := createStoreKeyScope(
			store, scope, ScopeAddrMap[scope], rootKey,
			cryptoKeyPub, cryptoKeyPriv,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// PassphraseChange contains a prepared manager passphrase cache update. The
// caller must Apply it after a successful commit or Close it on every failure.
type PassphraseChange struct {
	manager          *Manager
	private          bool
	masterKey        *snacl.SecretKey
	encryptedPriv    []byte
	encryptedScript  []byte
	passphraseSalt   [saltSize]byte
	hashedPassphrase [sha512.Size]byte
	applied          bool
}

// Apply publishes a prepared passphrase change after durable commit.
func (c *PassphraseChange) Apply() {
	if c == nil || c.applied {
		return
	}

	c.manager.mtx.Lock()
	defer c.manager.mtx.Unlock()

	if c.private {
		c.manager.masterKeyPriv.Zero()
		c.manager.masterKeyPriv = c.masterKey
		c.manager.cryptoKeyPrivEncrypted = c.encryptedPriv
		c.manager.cryptoKeyScriptEncrypted = c.encryptedScript
		c.manager.privPassphraseSalt = c.passphraseSalt
		c.manager.hashedPrivPassphrase = c.hashedPassphrase
	} else {
		c.manager.masterKeyPub.Zero()
		c.manager.masterKeyPub = c.masterKey
	}

	c.masterKey = nil
	c.applied = true
}

// Close zeros an unapplied prepared passphrase key.
func (c *PassphraseChange) Close() {
	if c == nil || c.masterKey == nil {
		return
	}

	c.masterKey.Zero()
	c.masterKey = nil
}

// ChangePassphraseFromStore prepares and persists one manager passphrase
// change without publishing new encryption state before commit.
func (m *Manager) ChangePassphraseFromStore(store ManagerReadWriteStore,
	oldPassphrase, newPassphrase []byte, private bool,
	config *ScryptOptions) (*PassphraseChange, error) {

	if private && m.WatchOnly() {
		return nil, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}
	if config == nil {
		config = &DefaultScryptOptions
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	var keyName string
	secretKey := snacl.SecretKey{Key: &snacl.CryptoKey{}}
	if private {
		keyName = "private"
		secretKey.Parameters = m.masterKeyPriv.Parameters
	} else {
		keyName = "public"
		secretKey.Parameters = m.masterKeyPub.Parameters
	}
	if err := secretKey.DeriveKey(&oldPassphrase); err != nil {
		if errors.Is(err, snacl.ErrInvalidPassword) {
			str := fmt.Sprintf(
				"invalid passphrase for %s master key", keyName,
			)
			return nil, managerError(ErrWrongPassphrase, str, nil)
		}

		str := fmt.Sprintf("failed to derive %s master key", keyName)
		return nil, managerError(ErrCrypto, str, err)
	}
	defer secretKey.Zero()

	newMasterKey, err := newSecretKey(&newPassphrase, config)
	if err != nil {
		return nil, managerError(
			ErrCrypto, "failed to create new master key", err,
		)
	}

	state, err := store.ManagerState()
	if err != nil {
		newMasterKey.Zero()
		return nil, err
	}

	change := &PassphraseChange{
		manager:   m,
		private:   private,
		masterKey: newMasterKey,
	}

	if private {
		_, err := rand.Read(change.passphraseSalt[:])
		if err != nil {
			change.Close()
			return nil, managerError(
				ErrCrypto, "failed to read passphrase salt", err,
			)
		}

		decPriv, err := secretKey.Decrypt(m.cryptoKeyPrivEncrypted)
		if err != nil {
			change.Close()
			return nil, managerError(
				ErrCrypto, "failed to decrypt crypto private key", err,
			)
		}
		change.encryptedPriv, err = newMasterKey.Encrypt(decPriv)
		zero.Bytes(decPriv)
		if err != nil {
			change.Close()
			return nil, managerError(
				ErrCrypto, "failed to encrypt crypto private key", err,
			)
		}

		decScript, err := secretKey.Decrypt(m.cryptoKeyScriptEncrypted)
		if err != nil {
			change.Close()
			return nil, managerError(
				ErrCrypto, "failed to decrypt crypto script key", err,
			)
		}
		change.encryptedScript, err = newMasterKey.Encrypt(decScript)
		zero.Bytes(decScript)
		if err != nil {
			change.Close()
			return nil, managerError(
				ErrCrypto, "failed to encrypt crypto script key", err,
			)
		}

		if m.IsLocked() {
			newMasterKey.Zero()
		} else {
			salted := append(change.passphraseSalt[:], newPassphrase...)
			change.hashedPassphrase = sha512.Sum512(salted)
			zero.Bytes(salted)
		}

		state.MasterPrivParams = newMasterKey.Marshal()
		state.EncryptedCryptoPrivKey = change.encryptedPriv
		state.EncryptedCryptoScriptKey = change.encryptedScript
	} else {
		encryptedPub, err := newMasterKey.Encrypt(m.cryptoKeyPub.Bytes())
		if err != nil {
			change.Close()
			return nil, managerError(
				ErrCrypto, "failed to encrypt crypto public key", err,
			)
		}

		state.MasterPubParams = newMasterKey.Marshal()
		state.EncryptedCryptoPubKey = encryptedPub
	}

	if err := store.PutManagerState(state); err != nil {
		change.Close()
		return nil, err
	}

	return change, nil
}

// newStoreScopedKeyManager constructs an empty store-backed scoped manager.
func (m *Manager) newStoreScopedKeyManager(scope KeyScope,
	addrSchema ScopeAddrSchema) *ScopedKeyManager {

	return &ScopedKeyManager{
		scope:       scope,
		addrSchema:  addrSchema,
		rootManager: m,
		addrs:       make(map[addrKey]ManagedAddress),
		used:        make(map[addrKey]bool),
		storeAddrs:  make(map[string]ManagedAddress),
		acctInfo:    make(map[uint32]*accountInfo),
		privKeyCache: lru.NewCache[DerivationPath, *cachedKey](
			defaultPrivKeyCacheSize,
		),
	}
}

// registerStoreScope adds one durable scoped manager to the root caches. The
// root manager mutex must be held for writes.
func (m *Manager) registerStoreScope(manager *ScopedKeyManager) {
	scope := manager.scope
	addrSchema := manager.addrSchema
	m.scopedManagers[scope] = manager
	m.externalAddrSchemas[addrSchema.ExternalAddrType] = append(
		m.externalAddrSchemas[addrSchema.ExternalAddrType], scope,
	)
	m.internalAddrSchemas[addrSchema.InternalAddrType] = append(
		m.internalAddrSchemas[addrSchema.InternalAddrType], scope,
	)
}

// AttachScopedKeyManagerFromStore reconstructs and registers a scope that is
// already durable, such as after an ambiguous creation commit.
func (m *Manager) AttachScopedKeyManagerFromStore(
	store ManagerReadStore, scope KeyScope) (*ScopedKeyManager, error) {

	m.mtx.RLock()
	if manager := m.scopedManagers[scope]; manager != nil {
		m.mtx.RUnlock()
		return manager, nil
	}

	state, err := store.KeyScope(scope)
	if err != nil {
		m.mtx.RUnlock()
		return nil, err
	}
	manager := m.newStoreScopedKeyManager(scope, state.AddrSchema)
	err = manager.loadStoreState(store)
	m.mtx.RUnlock()
	if err != nil {
		return nil, err
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	if existing := m.scopedManagers[scope]; existing != nil {
		return existing, nil
	}
	m.registerStoreScope(manager)

	return manager, nil
}

// NewScopedKeyManagerFromStore creates and persists a registered key scope.
// The returned manager may be used by later operations in the same transaction,
// but it is registered with the root manager only after commit.
func (m *Manager) NewScopedKeyManagerFromStore(tx ManagerReadWriteTx,
	scope KeyScope, addrSchema ScopeAddrSchema) (*ScopedKeyManager, error) {

	m.mtx.Lock()
	defer m.mtx.Unlock()

	if _, ok := m.scopedManagers[scope]; ok {
		return nil, managerError(
			ErrAlreadyExists, "key scope already exists", nil,
		)
	}
	_, err := tx.KeyScope(scope)
	if err == nil {
		return nil, managerError(
			ErrAlreadyExists, "key scope already exists", nil,
		)
	}
	if !IsError(err, ErrScopeNotFound) {
		return nil, err
	}

	manager := m.newStoreScopedKeyManager(scope, addrSchema)

	if m.WatchOnly() {
		err := tx.PutKeyScope(KeyScopeState{
			Scope:       scope,
			AddrSchema:  addrSchema,
			LastAccount: NoAccount,
		})
		if err != nil {
			return nil, err
		}

		err = tx.PutAccount(AccountState{
			Scope:           scope,
			Account:         ImportedAddrAccount,
			Type:            AccountDefault,
			Name:            ImportedAddrAccountName,
			EncryptedPubKey: []byte{},
		})
		if err != nil {
			return nil, err
		}
	} else {
		if m.IsLocked() {
			return nil, managerError(ErrLocked, errLocked, nil)
		}

		state, err := tx.ManagerState()
		if err != nil {
			return nil, err
		}
		if len(state.EncryptedMasterHDPrivKey) == 0 {
			return nil, managerError(ErrWatchingOnly, errWatchingOnly, nil)
		}

		serializedRoot, err := m.cryptoKeyPriv.Decrypt(
			state.EncryptedMasterHDPrivKey,
		)
		if err != nil {
			return nil, managerError(
				ErrLocked, "failed to decrypt master root key", err,
			)
		}
		defer zero.Bytes(serializedRoot)

		rootKey, err := hdkeychain.NewKeyFromString(string(serializedRoot))
		if err != nil {
			return nil, managerError(
				ErrKeyChain, "failed to decode master root key", err,
			)
		}
		defer rootKey.Zero()

		err = createStoreKeyScope(
			tx, scope, addrSchema, rootKey, m.cryptoKeyPub,
			m.cryptoKeyPriv,
		)
		if err != nil {
			return nil, err
		}
	}

	tx.OnCommit(func() {
		m.mtx.Lock()
		defer m.mtx.Unlock()

		m.registerStoreScope(manager)
	})

	return manager, nil
}

// convertToWatchingOnlyCache removes all private manager material after the
// corresponding durable transaction commits. The root manager mutex must be
// held for writes.
func (m *Manager) convertToWatchingOnlyCache() {
	managers := make([]*ScopedKeyManager, 0, len(m.scopedManagers))
	for _, manager := range m.scopedManagers {
		manager.mtx.Lock()
		managers = append(managers, manager)
	}
	defer func() {
		for i := len(managers) - 1; i >= 0; i-- {
			managers[i].mtx.Unlock()
		}
	}()

	if !m.IsLocked() {
		m.lock()
	}

	for _, manager := range m.scopedManagers {
		for _, info := range manager.acctInfo {
			zero.Bytes(info.acctKeyEncrypted)
			info.acctKeyEncrypted = nil
		}
		for _, managed := range manager.addrs {
			switch addr := managed.(type) {
			case *managedAddress:
				zero.Bytes(addr.privKeyEncrypted)
				addr.privKeyEncrypted = nil

			case *scriptAddress:
				zero.Bytes(addr.scriptEncrypted)
				addr.scriptEncrypted = nil

			case *witnessScriptAddress:
				if addr.isSecretScript {
					zero.Bytes(addr.scriptEncrypted)
					addr.scriptEncrypted = nil
				}

			case *taprootScriptAddress:
				if addr.isSecretScript {
					zero.Bytes(addr.scriptEncrypted)
					addr.scriptEncrypted = nil
				}
			}
		}
	}

	zero.Bytes(m.cryptoKeyScriptEncrypted)
	m.cryptoKeyScriptEncrypted = nil
	m.cryptoKeyScript = nil
	zero.Bytes(m.cryptoKeyPrivEncrypted)
	m.cryptoKeyPrivEncrypted = nil
	m.cryptoKeyPriv = nil
	m.masterKeyPriv = nil
	m.watchingOnly.Store(true)
}

// ConvertToWatchingOnlyFromStore permanently removes private durable material
// and publishes the watch-only state only after commit.
func (m *Manager) ConvertToWatchingOnlyFromStore(
	tx ManagerReadWriteTx) error {

	if m.WatchOnly() {
		return nil
	}

	state, err := tx.ManagerState()
	if err != nil {
		return err
	}
	state.WatchOnly = true
	state.MasterPrivParams = nil
	state.EncryptedCryptoPrivKey = nil
	state.EncryptedCryptoScriptKey = nil
	state.EncryptedMasterHDPrivKey = nil

	if err := tx.DeletePrivateKeys(); err != nil {
		return err
	}
	if err := tx.PutManagerState(state); err != nil {
		return err
	}

	tx.OnCommit(func() {
		m.mtx.Lock()
		defer m.mtx.Unlock()
		m.convertToWatchingOnlyCache()
	})

	return nil
}

// SetBirthdayFromStore persists a birthday and publishes it after commit.
func (m *Manager) SetBirthdayFromStore(tx ManagerReadWriteTx,
	birthday time.Time) error {

	if err := tx.SetBirthday(birthday); err != nil {
		return err
	}
	tx.OnCommit(func() {
		m.mtx.Lock()
		m.birthday = birthday
		m.mtx.Unlock()
	})

	return nil
}

// BirthdayBlockFromStore returns the durable birthday block and verification
// state.
func (m *Manager) BirthdayBlockFromStore(
	store ManagerReadStore) (BlockStamp, bool, error) {

	state, err := store.SyncState()
	if err != nil {
		return BlockStamp{}, false, err
	}
	if state.BirthdayBlock == nil {
		return BlockStamp{}, false, managerError(
			ErrBirthdayBlockNotSet, "birthday block is not set", nil,
		)
	}

	return *state.BirthdayBlock, state.BirthdayBlockVerified, nil
}

// SetBirthdayBlockFromStore persists birthday-block state atomically.
func (m *Manager) SetBirthdayBlockFromStore(tx ManagerReadWriteTx,
	block BlockStamp, verified bool) error {

	if err := tx.SetBirthdayBlock(&block); err != nil {
		return err
	}

	return tx.SetBirthdayBlockVerified(verified)
}

// SetSyncedToFromStore persists a sync position and publishes it after commit.
func (m *Manager) SetSyncedToFromStore(tx ManagerReadWriteTx,
	block *BlockStamp) error {

	if err := tx.SetSyncedTo(block); err != nil {
		return err
	}
	if block == nil {
		state, err := tx.SyncState()
		if err != nil {
			return err
		}
		block = &state.StartBlock
	}
	committedBlock := *block
	tx.OnCommit(func() {
		m.mtx.Lock()
		m.syncState.syncedTo = committedBlock
		m.mtx.Unlock()
	})

	return nil
}

// RefreshStartBlockFromStore replaces the cached import start block with its
// durable value after a transaction with an ambiguous commit outcome.
func (m *Manager) RefreshStartBlockFromStore(store ManagerReadStore) error {
	state, err := store.SyncState()
	if err != nil {
		return err
	}

	m.mtx.Lock()
	m.syncState.startBlock = state.StartBlock
	m.mtx.Unlock()

	return nil
}

// ApplySyncStateFromStore replaces the in-memory chain position with a
// detached durable snapshot after an ambiguous Store commit is reconciled.
func (m *Manager) ApplySyncStateFromStore(state SyncState) {
	m.mtx.Lock()
	m.syncState.startBlock = state.StartBlock
	m.syncState.syncedTo = state.SyncedTo
	m.birthday = state.Birthday
	m.mtx.Unlock()
}

// InvalidateSyncStateCache resets the cached chain position to the durable
// lower bound after a commit outcome cannot be reconciled.
func (m *Manager) InvalidateSyncStateCache() {
	m.mtx.Lock()
	m.syncState.syncedTo = m.syncState.startBlock
	m.mtx.Unlock()
}
