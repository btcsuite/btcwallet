// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package votingpool

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/walletdb"
)

// These constants define the serialized length for a given encrypted extended
// public or private key.
const (
	// We can calculate the encrypted extended key length this way:
	// snacl.Overhead == overhead for encrypting (16)
	// actual base58 extended key length = (111)
	// snacl.NonceSize == nonce size used for encryption (24)
	seriesKeyLength = snacl.Overhead + 111 + snacl.NonceSize
	// 4 bytes version + 1 byte active + 4 bytes nKeys + 4 bytes reqSigs
	seriesMinSerial = 4 + 1 + 4 + 4
	// 15 is the max number of keys in a voting pool, 1 each for
	// pubkey and privkey
	seriesMaxSerial = seriesMinSerial + 15*seriesKeyLength*2
	// version of serialized Series that we support
	seriesMaxVersion = 1
)

var (
	usedAddrsBucketName   = []byte("usedaddrs")
	seriesBucketName      = []byte("series")
	withdrawalsBucketName = []byte("withdrawals")
	// string representing a non-existent private key
	seriesNullPrivKey = [seriesKeyLength]byte{}
)

type dbSeriesRow struct {
	version           uint32
	active            bool
	reqSigs           uint32
	pubKeysEncrypted  [][]byte
	privKeysEncrypted [][]byte
}

type dbWithdrawalRow struct {
	Requests      []dbOutputRequest
	StartAddress  dbWithdrawalAddress
	ChangeStart   dbChangeAddress
	LastSeriesID  uint32
	DustThreshold btcutil.Amount
	Status        dbWithdrawalStatus
}

type dbWithdrawalAddress struct {
	SeriesID uint32
	Branch   Branch
	Index    Index
}

type dbChangeAddress struct {
	SeriesID uint32
	Index    Index
}

type dbOutputRequest struct {
	Addr        string
	Amount      btcutil.Amount
	Server      string
	Transaction uint32
}

type dbWithdrawalOutput struct {
	// We store the OutBailmentID here as we need a way to look up the
	// corresponding dbOutputRequest in dbWithdrawalRow when deserializing.
	OutBailmentID OutBailmentID
	Status        outputStatus
	Outpoints     []dbOutBailmentOutpoint
}

type dbOutBailmentOutpoint struct {
	Ntxid  Ntxid
	Index  uint32
	Amount btcutil.Amount
}

type dbChangeAwareTx struct {
	SerializedMsgTx []byte
	ChangeIdx       int32
}

type dbWithdrawalStatus struct {
	NextInputAddr  dbWithdrawalAddress
	NextChangeAddr dbChangeAddress
	Fees           btcutil.Amount
	Outputs        map[OutBailmentID]dbWithdrawalOutput
	Sigs           map[Ntxid]TxSigs
	Transactions   map[Ntxid]dbChangeAwareTx
}

// getUsedAddrBucketID returns the used addresses bucket ID for the given series
// and branch. It has the form seriesID:branch.
func getUsedAddrBucketID(seriesID uint32, branch Branch) []byte {
	var bucketID [9]byte
	binary.LittleEndian.PutUint32(bucketID[0:4], seriesID)
	bucketID[4] = ':'
	binary.LittleEndian.PutUint32(bucketID[5:9], uint32(branch))
	return bucketID[:]
}

// putUsedAddrHash adds an entry (key==index, value==encryptedHash) to the used
// addresses bucket of the given pool, series and branch.
func putUsedAddrHash(ns walletdb.ReadWriteBucket, poolID []byte, seriesID uint32, branch Branch,
	index Index, encryptedHash []byte) error {

	usedAddrs := ns.NestedReadWriteBucket(poolID).NestedReadWriteBucket(usedAddrsBucketName)
	bucket, err := usedAddrs.CreateBucketIfNotExists(getUsedAddrBucketID(seriesID, branch))
	if err != nil {
		return newError(ErrDatabase, "failed to store used address hash", err)
	}
	return bucket.Put(uint32ToBytes(uint32(index)), encryptedHash)
}

// getUsedAddrHash returns the addr hash with the given index from the used
// addresses bucket of the given pool, series and branch.
func getUsedAddrHash(ns walletdb.ReadBucket, poolID []byte, seriesID uint32, branch Branch,
	index Index) []byte {

	usedAddrs := ns.NestedReadBucket(poolID).NestedReadBucket(usedAddrsBucketName)
	bucket := usedAddrs.NestedReadBucket(getUsedAddrBucketID(seriesID, branch))
	if bucket == nil {
		return nil
	}
	return bucket.Get(uint32ToBytes(uint32(index)))
}

// getMaxUsedIdx returns the highest used index from the used addresses bucket
// of the given pool, series and branch.
func getMaxUsedIdx(ns walletdb.ReadBucket, poolID []byte, seriesID uint32, branch Branch) (Index, error) {
	maxIdx := Index(0)
	usedAddrs := ns.NestedReadBucket(poolID).NestedReadBucket(usedAddrsBucketName)
	bucket := usedAddrs.NestedReadBucket(getUsedAddrBucketID(seriesID, branch))
	if bucket == nil {
		return maxIdx, nil
	}
	// FIXME: This is far from optimal and should be optimized either by storing
	// a separate key in the DB with the highest used idx for every
	// series/branch or perhaps by doing a large gap linear forward search +
	// binary backwards search (e.g. check for 1000000, 2000000, ....  until it
	// doesn't exist, and then use a binary search to find the max using the
	// discovered bounds).
	err := bucket.ForEach(
		func(k, v []byte) error {
			idx := Index(bytesToUint32(k))
			if idx > maxIdx {
				maxIdx = idx
			}
			return nil
		})
	if err != nil {
		return Index(0), newError(ErrDatabase, "failed to get highest idx of used addresses", err)
	}
	return maxIdx, nil
}

// putPool stores a voting pool in the database, creating a bucket named
// after the voting pool id and two other buckets inside it to store series and
// used addresses for that pool.
func putPool(ns walletdb.ReadWriteBucket, poolID []byte) error {
	poolBucket, err := ns.CreateBucket(poolID)
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("cannot create pool %v", poolID), err)
	}
	_, err = poolBucket.CreateBucket(seriesBucketName)
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("cannot create series bucket for pool %v",
			poolID), err)
	}
	_, err = poolBucket.CreateBucket(usedAddrsBucketName)
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("cannot create used addrs bucket for pool %v",
			poolID), err)
	}
	_, err = poolBucket.CreateBucket(withdrawalsBucketName)
	if err != nil {
		return newError(
			ErrDatabase, fmt.Sprintf("cannot create withdrawals bucket for pool %v", poolID), err)
	}
	return nil
}

// loadAllSeries returns a map of all the series stored inside a voting pool
// bucket, keyed by id.
func loadAllSeries(ns walletdb.ReadBucket, poolID []byte) (map[uint32]*dbSeriesRow, error) {
	bucket := ns.NestedReadBucket(poolID).NestedReadBucket(seriesBucketName)
	allSeries := make(map[uint32]*dbSeriesRow)
	err := bucket.ForEach(
		func(k, v []byte) error {
			seriesID := bytesToUint32(k)
			series, err := deserializeSeriesRow(v)
			if err != nil {
				return err
			}
			allSeries[seriesID] = series
			return nil
		})
	if err != nil {
		return nil, err
	}
	return allSeries, nil
}

// existsPool checks the existence of a bucket named after the given
// voting pool id.
func existsPool(ns walletdb.ReadBucket, poolID []byte) bool {
	bucket := ns.NestedReadBucket(poolID)
	return bucket != nil
}

// putSeries stores the given series inside a voting pool bucket named after
// poolID. The voting pool bucket does not need to be created beforehand.
func putSeries(ns walletdb.ReadWriteBucket, poolID []byte, version, ID uint32, active bool, reqSigs uint32, pubKeysEncrypted, privKeysEncrypted [][]byte) error {
	row := &dbSeriesRow{
		version:           version,
		active:            active,
		reqSigs:           reqSigs,
		pubKeysEncrypted:  pubKeysEncrypted,
		privKeysEncrypted: privKeysEncrypted,
	}
	return putSeriesRow(ns, poolID, ID, row)
}

// putSeriesRow stores the given series row inside a voting pool bucket named
// after poolID. The voting pool bucket does not need to be created
// beforehand.
func putSeriesRow(ns walletdb.ReadWriteBucket, poolID []byte, ID uint32, row *dbSeriesRow) error {
	bucket, err := ns.CreateBucketIfNotExists(poolID)
	if err != nil {
		str := fmt.Sprintf("cannot create bucket %v", poolID)
		return newError(ErrDatabase, str, err)
	}
	bucket, err = bucket.CreateBucketIfNotExists(seriesBucketName)
	if err != nil {
		return err
	}
	serialized, err := serializeSeriesRow(row)
	if err != nil {
		return err
	}
	err = bucket.Put(uint32ToBytes(ID), serialized)
	if err != nil {
		str := fmt.Sprintf("cannot put series %v into bucket %v", serialized, poolID)
		return newError(ErrDatabase, str, err)
	}
	return nil
}

// deserializeSeriesRow deserializes a series storage into a dbSeriesRow struct.
func deserializeSeriesRow(serializedSeries []byte) (*dbSeriesRow, error) {
	// The serialized series format is:
	// <version><active><reqSigs><nKeys><pubKey1><privKey1>...<pubkeyN><privKeyN>
	//
	// 4 bytes version + 1 byte active + 4 bytes reqSigs + 4 bytes nKeys
	// + seriesKeyLength * 2 * nKeys (1 for priv, 1 for pub)

	// Given the above, the length of the serialized series should be
	// at minimum the length of the constants.
	if len(serializedSeries) < seriesMinSerial {
		str := fmt.Sprintf("serialized series is too short: %v", serializedSeries)
		return nil, newError(ErrSeriesSerialization, str, nil)
	}

	// Maximum number of public keys is 15 and the same for public keys
	// this gives us an upper bound.
	if len(serializedSeries) > seriesMaxSerial {
		str := fmt.Sprintf("serialized series is too long: %v", serializedSeries)
		return nil, newError(ErrSeriesSerialization, str, nil)
	}

	// Keeps track of the position of the next set of bytes to deserialize.
	current := 0
	row := dbSeriesRow{}

	row.version = bytesToUint32(serializedSeries[current : current+4])
	if row.version > seriesMaxVersion {
		str := fmt.Sprintf("deserialization supports up to version %v not %v",
			seriesMaxVersion, row.version)
		return nil, newError(ErrSeriesVersion, str, nil)
	}
	current += 4

	row.active = serializedSeries[current] == 0x01
	current++

	row.reqSigs = bytesToUint32(serializedSeries[current : current+4])
	current += 4

	nKeys := bytesToUint32(serializedSeries[current : current+4])
	current += 4

	// Check to see if we have the right number of bytes to consume.
	if len(serializedSeries) < current+int(nKeys)*seriesKeyLength*2 {
		str := fmt.Sprintf("serialized series has not enough data: %v", serializedSeries)
		return nil, newError(ErrSeriesSerialization, str, nil)
	} else if len(serializedSeries) > current+int(nKeys)*seriesKeyLength*2 {
		str := fmt.Sprintf("serialized series has too much data: %v", serializedSeries)
		return nil, newError(ErrSeriesSerialization, str, nil)
	}

	// Deserialize the pubkey/privkey pairs.
	row.pubKeysEncrypted = make([][]byte, nKeys)
	row.privKeysEncrypted = make([][]byte, nKeys)
	for i := 0; i < int(nKeys); i++ {
		pubKeyStart := current + seriesKeyLength*i*2
		pubKeyEnd := current + seriesKeyLength*i*2 + seriesKeyLength
		privKeyEnd := current + seriesKeyLength*(i+1)*2
		row.pubKeysEncrypted[i] = serializedSeries[pubKeyStart:pubKeyEnd]
		privKeyEncrypted := serializedSeries[pubKeyEnd:privKeyEnd]
		if bytes.Equal(privKeyEncrypted, seriesNullPrivKey[:]) {
			row.privKeysEncrypted[i] = nil
		} else {
			row.privKeysEncrypted[i] = privKeyEncrypted
		}
	}

	return &row, nil
}

// serializeSeriesRow serializes a dbSeriesRow struct into storage format.
func serializeSeriesRow(row *dbSeriesRow) ([]byte, error) {
	// The serialized series format is:
	// <version><active><reqSigs><nKeys><pubKey1><privKey1>...<pubkeyN><privKeyN>
	//
	// 4 bytes version + 1 byte active + 4 bytes reqSigs + 4 bytes nKeys
	// + seriesKeyLength * 2 * nKeys (1 for priv, 1 for pub)
	serializedLen := 4 + 1 + 4 + 4 + (seriesKeyLength * 2 * len(row.pubKeysEncrypted))

	if len(row.privKeysEncrypted) != 0 &&
		len(row.pubKeysEncrypted) != len(row.privKeysEncrypted) {
		str := fmt.Sprintf("different # of pub (%v) and priv (%v) keys",
			len(row.pubKeysEncrypted), len(row.privKeysEncrypted))
		return nil, newError(ErrSeriesSerialization, str, nil)
	}

	if row.version > seriesMaxVersion {
		str := fmt.Sprintf("serialization supports up to version %v, not %v",
			seriesMaxVersion, row.version)
		return nil, newError(ErrSeriesVersion, str, nil)
	}

	serialized := make([]byte, 0, serializedLen)
	serialized = append(serialized, uint32ToBytes(row.version)...)
	if row.active {
		serialized = append(serialized, 0x01)
	} else {
		serialized = append(serialized, 0x00)
	}
	serialized = append(serialized, uint32ToBytes(row.reqSigs)...)
	nKeys := uint32(len(row.pubKeysEncrypted))
	serialized = append(serialized, uint32ToBytes(nKeys)...)

	var privKeyEncrypted []byte
	for i, pubKeyEncrypted := range row.pubKeysEncrypted {
		// check that the encrypted length is correct
		if len(pubKeyEncrypted) != seriesKeyLength {
			str := fmt.Sprintf("wrong length of Encrypted Public Key: %v",
				pubKeyEncrypted)
			return nil, newError(ErrSeriesSerialization, str, nil)
		}
		serialized = append(serialized, pubKeyEncrypted...)

		if len(row.privKeysEncrypted) == 0 {
			privKeyEncrypted = seriesNullPrivKey[:]
		} else {
			privKeyEncrypted = row.privKeysEncrypted[i]
		}

		if privKeyEncrypted == nil {
			serialized = append(serialized, seriesNullPrivKey[:]...)
		} else if len(privKeyEncrypted) != seriesKeyLength {
			str := fmt.Sprintf("wrong length of Encrypted Private Key: %v",
				len(privKeyEncrypted))
			return nil, newError(ErrSeriesSerialization, str, nil)
		} else {
			serialized = append(serialized, privKeyEncrypted...)
		}
	}
	return serialized, nil
}

// serializeWithdrawal constructs a dbWithdrawalRow and serializes it (using
// encoding/gob) so that it can be stored in the DB.
func serializeWithdrawal(requests []OutputRequest, startAddress WithdrawalAddress,
	lastSeriesID uint32, changeStart ChangeAddress, dustThreshold btcutil.Amount,
	status WithdrawalStatus) ([]byte, error) {

	dbStartAddr := dbWithdrawalAddress{
		SeriesID: startAddress.SeriesID(),
		Branch:   startAddress.Branch(),
		Index:    startAddress.Index(),
	}
	dbChangeStart := dbChangeAddress{
		SeriesID: startAddress.SeriesID(),
		Index:    startAddress.Index(),
	}
	dbRequests := make([]dbOutputRequest, len(requests))
	for i, request := range requests {
		dbRequests[i] = dbOutputRequest{
			Addr:        request.Address.EncodeAddress(),
			Amount:      request.Amount,
			Server:      request.Server,
			Transaction: request.Transaction,
		}
	}
	dbOutputs := make(map[OutBailmentID]dbWithdrawalOutput, len(status.outputs))
	for oid, output := range status.outputs {
		dbOutpoints := make([]dbOutBailmentOutpoint, len(output.outpoints))
		for i, outpoint := range output.outpoints {
			dbOutpoints[i] = dbOutBailmentOutpoint{
				Ntxid:  outpoint.ntxid,
				Index:  outpoint.index,
				Amount: outpoint.amount,
			}
		}
		dbOutputs[oid] = dbWithdrawalOutput{
			OutBailmentID: output.request.outBailmentID(),
			Status:        output.status,
			Outpoints:     dbOutpoints,
		}
	}
	dbTransactions := make(map[Ntxid]dbChangeAwareTx, len(status.transactions))
	for ntxid, tx := range status.transactions {
		var buf bytes.Buffer
		buf.Grow(tx.SerializeSize())
		if err := tx.Serialize(&buf); err != nil {
			return nil, err
		}
		dbTransactions[ntxid] = dbChangeAwareTx{
			SerializedMsgTx: buf.Bytes(),
			ChangeIdx:       tx.changeIdx,
		}
	}
	nextChange := status.nextChangeAddr
	dbStatus := dbWithdrawalStatus{
		NextChangeAddr: dbChangeAddress{
			SeriesID: nextChange.seriesID,
			Index:    nextChange.index,
		},
		Fees:         status.fees,
		Outputs:      dbOutputs,
		Sigs:         status.sigs,
		Transactions: dbTransactions,
	}
	row := dbWithdrawalRow{
		Requests:      dbRequests,
		StartAddress:  dbStartAddr,
		LastSeriesID:  lastSeriesID,
		ChangeStart:   dbChangeStart,
		DustThreshold: dustThreshold,
		Status:        dbStatus,
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(row); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// deserializeWithdrawal deserializes the given byte slice into a dbWithdrawalRow,
// converts it into an withdrawalInfo and returns it. This function must run
// with the address manager unlocked.
func deserializeWithdrawal(p *Pool, ns, addrmgrNs walletdb.ReadBucket, serialized []byte) (*withdrawalInfo, error) {
	var row dbWithdrawalRow
	if err := gob.NewDecoder(bytes.NewReader(serialized)).Decode(&row); err != nil {
		return nil, newError(ErrWithdrawalStorage, "cannot deserialize withdrawal information",
			err)
	}
	wInfo := &withdrawalInfo{
		lastSeriesID:  row.LastSeriesID,
		dustThreshold: row.DustThreshold,
	}
	chainParams := p.Manager().ChainParams()
	wInfo.requests = make([]OutputRequest, len(row.Requests))
	// A map of requests indexed by OutBailmentID; needed to populate
	// WithdrawalStatus.Outputs later on.
	requestsByOID := make(map[OutBailmentID]OutputRequest)
	for i, req := range row.Requests {
		addr, err := btcutil.DecodeAddress(req.Addr, chainParams)
		if err != nil {
			return nil, newError(ErrWithdrawalStorage,
				"cannot deserialize addr for requested output", err)
		}
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, newError(ErrWithdrawalStorage, "invalid addr for requested output", err)
		}
		request := OutputRequest{
			Address:     addr,
			Amount:      req.Amount,
			PkScript:    pkScript,
			Server:      req.Server,
			Transaction: req.Transaction,
		}
		wInfo.requests[i] = request
		requestsByOID[request.outBailmentID()] = request
	}
	startAddr := row.StartAddress
	wAddr, err := p.WithdrawalAddress(ns, addrmgrNs, startAddr.SeriesID, startAddr.Branch, startAddr.Index)
	if err != nil {
		return nil, newError(ErrWithdrawalStorage, "cannot deserialize startAddress", err)
	}
	wInfo.startAddress = *wAddr

	cAddr, err := p.ChangeAddress(row.ChangeStart.SeriesID, row.ChangeStart.Index)
	if err != nil {
		return nil, newError(ErrWithdrawalStorage, "cannot deserialize changeStart", err)
	}
	wInfo.changeStart = *cAddr

	// TODO: Copy over row.Status.nextInputAddr. Not done because StartWithdrawal
	// does not update that yet.
	nextChangeAddr := row.Status.NextChangeAddr
	cAddr, err = p.ChangeAddress(nextChangeAddr.SeriesID, nextChangeAddr.Index)
	if err != nil {
		return nil, newError(ErrWithdrawalStorage,
			"cannot deserialize nextChangeAddress for withdrawal", err)
	}
	wInfo.status = WithdrawalStatus{
		nextChangeAddr: *cAddr,
		fees:           row.Status.Fees,
		outputs:        make(map[OutBailmentID]*WithdrawalOutput, len(row.Status.Outputs)),
		sigs:           row.Status.Sigs,
		transactions:   make(map[Ntxid]changeAwareTx, len(row.Status.Transactions)),
	}
	for oid, output := range row.Status.Outputs {
		outpoints := make([]OutBailmentOutpoint, len(output.Outpoints))
		for i, outpoint := range output.Outpoints {
			outpoints[i] = OutBailmentOutpoint{
				ntxid:  outpoint.Ntxid,
				index:  outpoint.Index,
				amount: outpoint.Amount,
			}
		}
		wInfo.status.outputs[oid] = &WithdrawalOutput{
			request:   requestsByOID[output.OutBailmentID],
			status:    output.Status,
			outpoints: outpoints,
		}
	}
	for ntxid, tx := range row.Status.Transactions {
		var msgtx wire.MsgTx
		if err := msgtx.Deserialize(bytes.NewBuffer(tx.SerializedMsgTx)); err != nil {
			return nil, newError(ErrWithdrawalStorage, "cannot deserialize transaction", err)
		}
		wInfo.status.transactions[ntxid] = changeAwareTx{
			MsgTx:     &msgtx,
			changeIdx: tx.ChangeIdx,
		}
	}
	return wInfo, nil
}

func putWithdrawal(ns walletdb.ReadWriteBucket, poolID []byte, roundID uint32, serialized []byte) error {
	bucket := ns.NestedReadWriteBucket(poolID)
	return bucket.Put(uint32ToBytes(roundID), serialized)
}

func getWithdrawal(ns walletdb.ReadBucket, poolID []byte, roundID uint32) []byte {
	bucket := ns.NestedReadBucket(poolID)
	return bucket.Get(uint32ToBytes(roundID))
}

// uint32ToBytes converts a 32 bit unsigned integer into a 4-byte slice in
// little-endian order: 1 -> [1 0 0 0].
func uint32ToBytes(number uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, number)
	return buf
}

// bytesToUint32 converts a 4-byte slice in little-endian order into a 32 bit
// unsigned integer: [1 0 0 0] -> 1.
func bytesToUint32(encoded []byte) uint32 {
	return binary.LittleEndian.Uint32(encoded)
}
