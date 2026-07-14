package waddrmgr

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/walletdb"
)

// kvManagerReadStore binds the bucket used by the legacy read helpers for the
// lifetime of one outer walletdb transaction.
type kvManagerReadStore struct {
	ns walletdb.ReadBucket
}

// kvManagerReadWriteStore binds the bucket used by the legacy write helpers
// for the lifetime of one outer walletdb transaction.
type kvManagerReadWriteStore struct {
	*kvManagerReadStore

	ns walletdb.ReadWriteBucket
}

// managerCreationTimeSize is the size of the legacy Unix timestamp encoding.
const managerCreationTimeSize = 8

// BindManagerReadStore binds the legacy bucket once and returns a bucket-free
// manager persistence view.
func BindManagerReadStore(ns walletdb.ReadBucket) ManagerReadStore {
	return &kvManagerReadStore{ns: ns}
}

// BindManagerReadWriteStore binds the legacy bucket once and returns a
// bucket-free writable manager persistence view.
func BindManagerReadWriteStore(
	ns walletdb.ReadWriteBucket) ManagerReadWriteStore {

	return &kvManagerReadWriteStore{
		kvManagerReadStore: &kvManagerReadStore{ns: ns},
		ns:                 ns,
	}
}

// copyBytes copies a byte slice so durable state does not alias a walletdb
// value after the transaction callback returns.
func copyBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

// ManagerState assembles the durable root manager state from the individual
// values stored by the legacy walletdb implementation.
func (s *kvManagerReadStore) ManagerState() (ManagerState, error) {
	version, err := fetchManagerVersion(s.ns)
	if err != nil {
		return ManagerState{}, err
	}

	mainBucket := s.ns.NestedReadBucket(mainBucketName)

	createdBytes := mainBucket.Get(mgrCreateDateName)
	if len(createdBytes) != managerCreationTimeSize {
		return ManagerState{}, managerError(
			ErrDatabase, "malformed manager creation time", nil,
		)
	}

	masterPub, masterPriv, err := fetchMasterKeyParams(s.ns)
	if err != nil {
		return ManagerState{}, err
	}

	cryptoPub, cryptoPriv, cryptoScript, err := fetchCryptoKeys(s.ns)
	if err != nil {
		return ManagerState{}, err
	}

	masterHDPriv, masterHDPub := fetchMasterHDKeys(s.ns)

	watchOnly, err := fetchWatchingOnly(s.ns)
	if err != nil {
		return ManagerState{}, err
	}

	// The legacy encoding stores signed Unix seconds in an unsigned field.

	createdAt := int64(binary.LittleEndian.Uint64(createdBytes))

	return ManagerState{
		Version:                  version,
		CreatedAt:                time.Unix(createdAt, 0),
		WatchOnly:                watchOnly,
		MasterPubParams:          copyBytes(masterPub),
		MasterPrivParams:         copyBytes(masterPriv),
		EncryptedCryptoPubKey:    copyBytes(cryptoPub),
		EncryptedCryptoPrivKey:   copyBytes(cryptoPriv),
		EncryptedCryptoScriptKey: copyBytes(cryptoScript),
		EncryptedMasterHDPubKey:  copyBytes(masterHDPub),
		EncryptedMasterHDPrivKey: copyBytes(masterHDPriv),
	}, nil
}

// SyncState assembles the complete durable chain position from the legacy sync
// bucket. A missing birthday block is represented by a nil BirthdayBlock while
// preserving its independent verification bit.
func (s *kvManagerReadStore) SyncState() (SyncState, error) {
	start, err := FetchStartBlock(s.ns)
	if err != nil {
		return SyncState{}, err
	}

	synced, err := fetchSyncedTo(s.ns)
	if err != nil {
		return SyncState{}, err
	}

	birthday, err := fetchBirthday(s.ns)
	if err != nil {
		return SyncState{}, err
	}

	state := SyncState{
		StartBlock:            *start,
		SyncedTo:              *synced,
		Birthday:              birthday,
		BirthdayBlockVerified: fetchBirthdayBlockVerification(s.ns),
	}

	birthdayBlock, err := FetchBirthdayBlock(s.ns)
	if err == nil {
		state.BirthdayBlock = &birthdayBlock
	} else if !IsError(err, ErrBirthdayBlockNotSet) {
		return SyncState{}, err
	}

	return state, nil
}

// BlockHash returns the block hash recorded in the legacy sync bucket at the
// given height.
func (s *kvManagerReadStore) BlockHash(height int32) (*chainhash.Hash, error) {
	return fetchBlockHash(s.ns, height)
}

// KeyScope assembles the schema, encrypted coin keys, and last allocated
// account for one legacy key-scope bucket.
func (s *kvManagerReadStore) KeyScope(scope KeyScope) (KeyScopeState, error) {
	schema, err := fetchScopeAddrSchema(s.ns, &scope)
	if err != nil {
		return KeyScopeState{}, err
	}

	bucket, err := fetchReadScopeBucket(s.ns, &scope)
	if err != nil {
		return KeyScopeState{}, err
	}

	lastAccount, err := fetchLastAccount(s.ns, &scope)
	if err != nil {
		return KeyScopeState{}, err
	}

	return KeyScopeState{
		Scope:                scope,
		AddrSchema:           *schema,
		EncryptedCoinPubKey:  copyBytes(bucket.Get(coinTypePubKeyName)),
		EncryptedCoinPrivKey: copyBytes(bucket.Get(coinTypePrivKeyName)),
		LastAccount:          lastAccount,
	}, nil
}

// KeyScopes returns every legacy key scope in the order produced by the
// existing scope iterator.
func (s *kvManagerReadStore) KeyScopes() ([]KeyScopeState, error) {
	var scopes []KeyScopeState

	err := forEachKeyScope(s.ns, func(scope KeyScope) error {
		state, err := s.KeyScope(scope)
		if err != nil {
			return err
		}

		scopes = append(scopes, state)

		return nil
	})

	return scopes, err
}

// accountState converts one legacy account row into backend-neutral durable
// state. The concrete row type determines which optional account fields are
// populated.
func accountState(scope KeyScope, account uint32,
	row any) (AccountState, error) {

	state := AccountState{Scope: scope, Account: account}
	switch row := row.(type) {
	// A default account owns encrypted public and private extended keys.
	case *dbDefaultAccountRow:
		state.Type = AccountDefault
		state.Name = row.name
		state.EncryptedPubKey = copyBytes(row.pubKeyEncrypted)
		state.EncryptedPrivKey = copyBytes(row.privKeyEncrypted)
		state.NextExternalIndex = row.nextExternalIndex
		state.NextInternalIndex = row.nextInternalIndex

	// A watch-only account owns a public key, fingerprint, and optional
	// address schema, but no private key.
	case *dbWatchOnlyAccountRow:
		state.Type = AccountWatchOnly
		state.Name = row.name
		state.EncryptedPubKey = copyBytes(row.pubKeyEncrypted)
		state.MasterKeyFingerprint = row.masterKeyFingerprint
		state.NextExternalIndex = row.nextExternalIndex

		state.NextInternalIndex = row.nextInternalIndex
		if row.addrSchema != nil {
			schema := *row.addrSchema
			state.AddrSchema = &schema
		}

	default:
		return AccountState{}, managerError(
			ErrDatabase, fmt.Sprintf("unsupported account row %T", row), nil,
		)
	}

	return state, nil
}

// Account returns one account after decoding the existing scoped account row.
func (s *kvManagerReadStore) Account(scope KeyScope,
	account uint32) (AccountState, error) {

	row, err := fetchAccountInfo(s.ns, &scope, account)
	if err != nil {
		return AccountState{}, err
	}

	return accountState(scope, account, row)
}

// AccountByName resolves the legacy name index, then returns the corresponding
// scoped account.
func (s *kvManagerReadStore) AccountByName(scope KeyScope,
	name string) (AccountState, error) {

	account, err := fetchAccountByName(s.ns, &scope, name)
	if err != nil {
		return AccountState{}, err
	}

	return s.Account(scope, account)
}

// Accounts returns every account in the order produced by the existing scoped
// account iterator.
func (s *kvManagerReadStore) Accounts(scope KeyScope) ([]AccountState, error) {
	var accounts []AccountState

	err := forEachAccount(s.ns, &scope, func(account uint32) error {
		state, err := s.Account(scope, account)
		if err != nil {
			return err
		}

		accounts = append(accounts, state)

		return nil
	})

	return accounts, err
}

// addressState converts one legacy address row into backend-neutral durable
// state. The concrete row type determines which address-specific fields are
// populated.
func addressState(scope KeyScope, hash []byte, row any,
	used bool) (AddressState, error) {

	state := AddressState{Scope: scope, Hash: copyBytes(hash), Used: used}

	setBase := func(row dbAddressRow) {
		state.Account = row.account
		// The legacy encoding stores signed Unix seconds in an unsigned
		// field.

		state.AddedAt = time.Unix(int64(row.addTime), 0)
		state.SyncStatus = AddressSyncStatus(row.syncStatus)
	}

	switch row := row.(type) {
	// A chain address stores its derivation branch and index.
	case *dbChainAddressRow:
		setBase(row.dbAddressRow)

		state.Type = AddressChain
		branch, index := row.branch, row.index
		state.Branch, state.Index = &branch, &index

	// An imported address stores encrypted public and optional private key
	// material.
	case *dbImportedAddressRow:
		setBase(row.dbAddressRow)

		state.Type = AddressImported
		state.EncryptedPubKey = copyBytes(row.encryptedPubKey)
		state.EncryptedPrivKey = copyBytes(row.encryptedPrivKey)

	// A legacy script address stores its encrypted script hash and script.
	case *dbScriptAddressRow:
		setBase(row.dbAddressRow)

		state.Type = AddressScript
		state.EncryptedHash = copyBytes(row.encryptedHash)
		state.EncryptedScript = copyBytes(row.encryptedScript)

	// Witness and taproot script addresses share the witness-script row
	// encoding and are distinguished by the legacy address type.
	case *dbWitnessScriptAddressRow:
		setBase(row.dbAddressRow)

		state.Type = AddressWitnessScript
		if row.addrType == adtTaprootScript {
			state.Type = AddressTaprootScript
		}

		version, secret := row.witnessVersion, row.isSecretScript
		state.WitnessVersion, state.IsSecretScript = &version, &secret
		state.EncryptedHash = copyBytes(row.encryptedHash)
		state.EncryptedScript = copyBytes(row.encryptedScript)

	default:
		return AddressState{}, managerError(
			ErrDatabase, fmt.Sprintf("unsupported address row %T", row), nil,
		)
	}

	return state, nil
}

// Address returns one managed address by its legacy identifier. The returned
// state includes the SHA256 identifier stored by SQL and the independent used
// bit from the legacy used-address bucket.
func (s *kvManagerReadStore) Address(scope KeyScope,
	addressID []byte) (AddressState, error) {

	row, err := fetchAddress(s.ns, &scope, addressID)
	if err != nil {
		return AddressState{}, err
	}

	used := fetchAddressUsed(s.ns, &scope, addressID)
	hash := sha256.Sum256(addressID)

	return addressState(scope, hash[:], row, used)
}

// collectAddresses loads the addresses indexed by a legacy bucket and
// preserves each address's independent used state.
func (s *kvManagerReadStore) collectAddresses(scope KeyScope,
	bucket walletdb.ReadBucket) ([]AddressState, error) {

	var addresses []AddressState
	if bucket == nil {
		return addresses, nil
	}

	scopedBucket, err := fetchReadScopeBucket(s.ns, &scope)
	if err != nil {
		return nil, err
	}

	usedBucket := scopedBucket.NestedReadBucket(usedAddrBucketName)

	err = bucket.ForEach(func(hash, value []byte) error {
		if value == nil {
			return nil
		}

		row, err := fetchAddressByHash(s.ns, &scope, hash)
		if err != nil {
			return err
		}

		used := usedBucket != nil && usedBucket.Get(hash) != nil

		state, err := addressState(scope, hash, row, used)
		if err != nil {
			return err
		}

		addresses = append(addresses, state)

		return nil
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	return addresses, nil
}

// AccountAddresses returns every address indexed under one legacy scoped
// account.
func (s *kvManagerReadStore) AccountAddresses(scope KeyScope,
	account uint32) ([]AddressState, error) {

	scopedBucket, err := fetchReadScopeBucket(s.ns, &scope)
	if err != nil {
		return nil, err
	}

	bucket := scopedBucket.NestedReadBucket(addrAcctIdxBucketName)
	if bucket != nil {
		bucket = bucket.NestedReadBucket(uint32ToBytes(account))
	}

	return s.collectAddresses(scope, bucket)
}

// ActiveAddresses returns every address in the active-address bucket for one
// key scope.
func (s *kvManagerReadStore) ActiveAddresses(
	scope KeyScope) ([]AddressState, error) {

	scopedBucket, err := fetchReadScopeBucket(s.ns, &scope)
	if err != nil {
		return nil, err
	}

	return s.collectAddresses(
		scope, scopedBucket.NestedReadBucket(addrBucketName),
	)
}

// PutManagerState writes the complete durable manager state with the existing
// walletdb encodings and helper functions.
func (s *kvManagerReadWriteStore) PutManagerState(state ManagerState) error {
	// Store the manager version and creation time before the encrypted key
	// material that depends on this root state.
	err := putManagerVersion(s.ns, state.Version)
	if err != nil {
		return err
	}

	mainBucket := s.ns.NestedReadWriteBucket(mainBucketName)

	var created [managerCreationTimeSize]byte

	binary.LittleEndian.PutUint64(created[:], uint64(state.CreatedAt.Unix()))

	err = mainBucket.Put(mgrCreateDateName, created[:])
	if err != nil {
		return managerError(ErrDatabase, "store manager creation time", err)
	}

	// Reuse the existing key writers so the KV representation remains
	// byte-for-byte compatible with current wallets.
	err = putMasterKeyParams(
		s.ns, state.MasterPubParams, state.MasterPrivParams,
	)
	if err != nil {
		return err
	}

	err = putCryptoKeys(
		s.ns, state.EncryptedCryptoPubKey, state.EncryptedCryptoPrivKey,
		state.EncryptedCryptoScriptKey,
	)
	if err != nil {
		return err
	}

	err = putMasterHDKeys(
		s.ns, state.EncryptedMasterHDPrivKey,
		state.EncryptedMasterHDPubKey,
	)
	if err != nil {
		return err
	}

	// Record the watching-only bit last so a failed key write can't leave the
	// manager marked watch-only with incomplete root state.
	return putWatchingOnly(s.ns, state.WatchOnly)
}

// PutSyncState writes the complete durable chain position. It deliberately
// uses the low-level block writers because bulk restore must not require the
// predecessor checks used by an incremental SetSyncedTo update.
func (s *kvManagerReadWriteStore) PutSyncState(state SyncState) error {
	err := putStartBlock(s.ns, &state.StartBlock)
	if err != nil {
		return err
	}

	err = addBlockHash(s.ns, state.StartBlock.Height,
		state.StartBlock.Hash)
	if err != nil {
		return err
	}

	err = s.SetBirthday(state.Birthday)
	if err != nil {
		return err
	}

	err = s.SetBirthdayBlock(state.BirthdayBlock)
	if err != nil {
		return err
	}

	err = s.SetBirthdayBlockVerified(
		state.BirthdayBlockVerified,
	)
	if err != nil {
		return err
	}

	err = addBlockHash(
		s.ns, state.SyncedTo.Height, state.SyncedTo.Hash,
	)
	if err != nil {
		return err
	}

	return updateSyncedTo(s.ns, &state.SyncedTo)
}

// SetSyncedTo delegates an incremental chain-tip update to the existing
// walletdb implementation, including its predecessor and reorg-depth checks.
func (s *kvManagerReadWriteStore) SetSyncedTo(block *BlockStamp) error {
	return PutSyncedTo(s.ns, block)
}

// SetBirthday writes the birthday timestamp with the existing legacy encoding.
func (s *kvManagerReadWriteStore) SetBirthday(birthday time.Time) error {
	return putBirthday(s.ns, birthday)
}

// SetBirthdayBlock sets or clears the exact birthday block stamp. A non-nil
// block is also added to the legacy height-to-hash index.
func (s *kvManagerReadWriteStore) SetBirthdayBlock(block *BlockStamp) error {
	if block == nil {
		return DeleteBirthdayBlock(s.ns)
	}

	err := addBlockHash(s.ns, block.Height, block.Hash)
	if err != nil {
		return err
	}

	return PutBirthdayBlock(s.ns, *block)
}

// SetBirthdayBlockVerified writes the verification bit independently of the
// optional birthday block.
func (s *kvManagerReadWriteStore) SetBirthdayBlockVerified(
	verified bool) error {

	return putBirthdayBlockVerification(s.ns, verified)
}

// PutKeyScope creates the legacy scoped namespace when needed, then writes its
// schema, encrypted coin keys, and last allocated account.
func (s *kvManagerReadWriteStore) PutKeyScope(state KeyScopeState) error {
	root := s.ns.NestedReadWriteBucket(scopeBucketName)

	scopeKey := scopeToBytes(&state.Scope)
	if root.NestedReadWriteBucket(scopeKey[:]) == nil {
		err := createScopedManagerNS(root, &state.Scope)
		if err != nil {
			return err
		}
	}

	schemas := s.ns.NestedReadWriteBucket(scopeSchemaBucketName)

	err := schemas.Put(
		scopeKey[:], scopeSchemaToBytes(&state.AddrSchema),
	)
	if err != nil {
		return managerError(ErrDatabase, "store scope schema", err)
	}

	err = s.SetCoinTypeKeys(
		state.Scope, state.EncryptedCoinPubKey,
		state.EncryptedCoinPrivKey,
	)
	if err != nil {
		return err
	}

	return s.SetLastAccount(state.Scope, state.LastAccount)
}

// SetCoinTypeKeys replaces the encrypted public and private coin-type keys for
// one legacy key scope.
func (s *kvManagerReadWriteStore) SetCoinTypeKeys(scope KeyScope,
	encryptedPub, encryptedPriv []byte) error {

	return putCoinTypeKeys(s.ns, &scope, encryptedPub, encryptedPriv)
}

// SetLastAccount records the last allocated account for one legacy key scope.
func (s *kvManagerReadWriteStore) SetLastAccount(scope KeyScope,
	account uint32) error {

	return putLastAccount(s.ns, &scope, account)
}

// PutAccount writes one account with the existing row encoding selected by its
// durable account type.
func (s *kvManagerReadWriteStore) PutAccount(state AccountState) error {
	switch state.Type {
	// Default accounts preserve both encrypted extended keys and derivation
	// indexes.
	case AccountDefault:
		return putDefaultAccountInfo(
			s.ns, &state.Scope, state.Account, state.EncryptedPubKey,
			state.EncryptedPrivKey, state.NextExternalIndex,
			state.NextInternalIndex, state.Name,
		)

	// Watch-only accounts preserve the master-key fingerprint and optional
	// address schema instead of a private extended key.
	case AccountWatchOnly:
		return putWatchOnlyAccountInfo(
			s.ns, &state.Scope, state.Account, state.EncryptedPubKey,
			state.MasterKeyFingerprint, state.NextExternalIndex,
			state.NextInternalIndex, state.Name, state.AddrSchema,
		)

	default:
		return managerError(
			ErrDatabase, fmt.Sprintf("unsupported account type %d", state.Type),
			nil,
		)
	}
}

// RenameAccount replaces one account name while keeping both legacy account
// indexes consistent.
func (s *kvManagerReadWriteStore) RenameAccount(scope KeyScope,
	account uint32, name string) error {

	state, err := s.Account(scope, account)
	if err != nil {
		return err
	}

	err = deleteAccountNameIndex(s.ns, &scope, state.Name)
	if err != nil {
		return err
	}

	err = deleteAccountIDIndex(s.ns, &scope, account)
	if err != nil {
		return err
	}

	state.Name = name

	return s.PutAccount(state)
}

// SetAccountIndexes replaces the next external and internal derivation indexes
// while preserving the rest of the legacy account row.
func (s *kvManagerReadWriteStore) SetAccountIndexes(scope KeyScope, account,
	nextExternal, nextInternal uint32) error {

	state, err := s.Account(scope, account)
	if err != nil {
		return err
	}

	state.NextExternalIndex = nextExternal
	state.NextInternalIndex = nextInternal

	return s.PutAccount(state)
}

// addressRow converts backend-neutral address state into the existing legacy
// row encoding. Required optional fields are validated before serialization.
func addressRow(state AddressState) (*dbAddressRow, error) {
	// The legacy encoding stores signed Unix seconds in an unsigned field.

	addedAt := uint64(state.AddedAt.Unix())

	row := &dbAddressRow{
		addrType:   addressType(state.Type),
		account:    state.Account,
		addTime:    addedAt,
		syncStatus: syncStatus(state.SyncStatus),
	}

	switch state.Type {
	// Chain addresses require a complete derivation path.
	case AddressChain:
		if state.Branch == nil || state.Index == nil {
			return nil, errors.New("chain address path is missing")
		}

		row.rawData = serializeChainedAddress(*state.Branch, *state.Index)

	// Imported addresses preserve encrypted public and optional private key
	// material.
	case AddressImported:
		row.rawData = serializeImportedAddress(
			state.EncryptedPubKey, state.EncryptedPrivKey,
		)

	// Legacy script addresses preserve their encrypted hash and script.
	case AddressScript:
		row.rawData = serializeScriptAddress(
			state.EncryptedHash, state.EncryptedScript,
		)

	// Witness and taproot scripts share the legacy witness-script encoding.
	case AddressWitnessScript, AddressTaprootScript:
		if state.WitnessVersion == nil || state.IsSecretScript == nil {
			return nil, errors.New("witness script metadata is missing")
		}

		row.rawData = serializeWitnessScriptAddress(
			*state.WitnessVersion, *state.IsSecretScript,
			state.EncryptedHash, state.EncryptedScript,
		)

	default:
		return nil, fmt.Errorf("unsupported address type %d", state.Type)
	}

	return row, nil
}

// PutAddress writes one address with the existing legacy row codec, then marks
// it used when requested. The used bit remains monotonic in the KV backend.
func (s *kvManagerReadWriteStore) PutAddress(addressID []byte,
	state AddressState) error {

	row, err := addressRow(state)
	if err != nil {
		return err
	}

	err = putAddress(s.ns, &state.Scope, addressID, row)
	if err != nil {
		return err
	}

	if state.Used {
		return markAddressUsed(s.ns, &state.Scope, addressID)
	}

	return nil
}

// MarkAddressUsed records the address identifier in the existing scoped
// used-address bucket.
func (s *kvManagerReadWriteStore) MarkAddressUsed(scope KeyScope,
	addressID []byte) error {

	return markAddressUsed(s.ns, &scope, addressID)
}

// DeletePrivateKeys delegates watching-only conversion to the existing legacy
// helper so every encrypted private key and secret script is handled exactly as
// it is for current wallets.
func (s *kvManagerReadWriteStore) DeletePrivateKeys() error {
	return deletePrivateKeys(s.ns)
}

var (
	_ ManagerReadStore      = (*kvManagerReadStore)(nil)
	_ ManagerReadWriteStore = (*kvManagerReadWriteStore)(nil)
)
