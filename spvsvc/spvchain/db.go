// NOTE: THIS API IS UNSTABLE RIGHT NOW.

package spvchain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcutil/gcs/builder"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

const (
	// LatestDBVersion is the most recent database version.
	LatestDBVersion = 1
)

var (
	// latestDBVersion is the most recent database version as a variable so
	// the tests can change it to force errors.
	latestDBVersion uint32 = LatestDBVersion
)

// Key names for various database fields.
var (
	// Bucket names.
	spvBucketName         = []byte("spvchain")
	blockHeaderBucketName = []byte("bh")
	basicHeaderBucketName = []byte("bfh")
	basicFilterBucketName = []byte("bf")
	extHeaderBucketName   = []byte("efh")
	extFilterBucketName   = []byte("ef")

	// Db related key names (main bucket).
	dbVersionName      = []byte("dbver")
	dbCreateDateName   = []byte("dbcreated")
	maxBlockHeightName = []byte("maxblockheight")
)

// uint32ToBytes converts a 32 bit unsigned integer into a 4-byte slice in
// little-endian order: 1 -> [1 0 0 0].
func uint32ToBytes(number uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, number)
	return buf
}

// uint64ToBytes converts a 64 bit unsigned integer into a 8-byte slice in
// little-endian order: 1 -> [1 0 0 0 0 0 0 0].
func uint64ToBytes(number uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, number)
	return buf
}

// dbUpdateOption is a function type for the kind of DB update to be done.
// These can call each other and dbViewOption functions; however, they cannot
// be called by dbViewOption functions.
type dbUpdateOption func(bucket walletdb.ReadWriteBucket) error

// dbViewOption is a funciton type for the kind of data to be fetched from DB.
// These can call each other and can be called by dbUpdateOption functions;
// however, they cannot call dbUpdateOption functions.
type dbViewOption func(bucket walletdb.ReadBucket) error

// fetchDBVersion fetches the current manager version from the database.
func (s *ChainService) fetchDBVersion() (uint32, error) {
	var version uint32
	err := s.dbView(fetchDBVersion(&version))
	return version, err
}

func fetchDBVersion(version *uint32) dbViewOption {
	return func(bucket walletdb.ReadBucket) error {
		verBytes := bucket.Get(dbVersionName)
		if verBytes == nil {
			return fmt.Errorf("required version number not " +
				"stored in database")
		}
		*version = binary.LittleEndian.Uint32(verBytes)
		return nil
	}
}

// putDBVersion stores the provided version to the database.
func (s *ChainService) putDBVersion(version uint32) error {
	return s.dbUpdate(putDBVersion(version))
}

func putDBVersion(version uint32) dbUpdateOption {
	return func(bucket walletdb.ReadWriteBucket) error {
		verBytes := uint32ToBytes(version)
		return bucket.Put(dbVersionName, verBytes)
	}
}

// putMaxBlockHeight stores the max block height to the database.
func (s *ChainService) putMaxBlockHeight(maxBlockHeight uint32) error {
	return s.dbUpdate(putMaxBlockHeight(maxBlockHeight))
}

func putMaxBlockHeight(maxBlockHeight uint32) dbUpdateOption {
	return func(bucket walletdb.ReadWriteBucket) error {
		maxBlockHeightBytes := uint32ToBytes(maxBlockHeight)
		err := bucket.Put(maxBlockHeightName, maxBlockHeightBytes)
		if err != nil {
			return fmt.Errorf("failed to store max block height: %s", err)
		}
		return nil
	}
}

// putBlock stores the provided block header and height, keyed to the block
// hash, in the database.
func (s *ChainService) putBlock(header wire.BlockHeader, height uint32) error {
	return s.dbUpdate(putBlock(header, height))
}

func putBlock(header wire.BlockHeader, height uint32) dbUpdateOption {
	return func(bucket walletdb.ReadWriteBucket) error {
		var buf bytes.Buffer
		err := header.Serialize(&buf)
		if err != nil {
			return err
		}
		_, err = buf.Write(uint32ToBytes(height))
		if err != nil {
			return err
		}
		blockHash := header.BlockHash()
		bhBucket := bucket.NestedReadWriteBucket(blockHeaderBucketName)
		err = bhBucket.Put(blockHash[:], buf.Bytes())
		if err != nil {
			return fmt.Errorf("failed to store SPV block info: %s",
				err)
		}
		err = bhBucket.Put(uint32ToBytes(height), blockHash[:])
		if err != nil {
			return fmt.Errorf("failed to store block height info:"+
				" %s", err)
		}
		return nil
	}
}

// putFilter stores the provided filter, keyed to the block hash, in the
// appropriate filter bucket in the database.
func (s *ChainService) putFilter(blockHash chainhash.Hash, bucketName []byte,
	filter *gcs.Filter) error {
	return s.dbUpdate(putFilter(blockHash, bucketName, filter))
}

func putFilter(blockHash chainhash.Hash, bucketName []byte,
	filter *gcs.Filter) dbUpdateOption {
	return func(bucket walletdb.ReadWriteBucket) error {
		var buf bytes.Buffer
		_, err := buf.Write(filter.NBytes())
		if err != nil {
			return err
		}
		filterBucket := bucket.NestedReadWriteBucket(bucketName)
		err = filterBucket.Put(blockHash[:], buf.Bytes())
		if err != nil {
			return fmt.Errorf("failed to store filter: %s", err)
		}
		return nil
	}
}

// putBasicFilter stores the provided filter, keyed to the block hash, in the
// basic filter bucket in the database.
func (s *ChainService) putBasicFilter(blockHash chainhash.Hash,
	filter *gcs.Filter) error {
	return s.dbUpdate(putBasicFilter(blockHash, filter))
}

func putBasicFilter(blockHash chainhash.Hash,
	filter *gcs.Filter) dbUpdateOption {
	return putFilter(blockHash, basicFilterBucketName, filter)
}

// putExtFilter stores the provided filter, keyed to the block hash, in the
// extended filter bucket in the database.
func (s *ChainService) putExtFilter(blockHash chainhash.Hash,
	filter *gcs.Filter) error {
	return s.dbUpdate(putExtFilter(blockHash, filter))
}

func putExtFilter(blockHash chainhash.Hash,
	filter *gcs.Filter) dbUpdateOption {
	return putFilter(blockHash, extFilterBucketName, filter)
}

// putHeader stores the provided header, keyed to the block hash, in the
// appropriate filter header bucket in the database.
func (s *ChainService) putHeader(blockHash chainhash.Hash, bucketName []byte,
	filterTip chainhash.Hash) error {
	return s.dbUpdate(putHeader(blockHash, bucketName, filterTip))
}

func putHeader(blockHash chainhash.Hash, bucketName []byte,
	filterTip chainhash.Hash) dbUpdateOption {
	return func(bucket walletdb.ReadWriteBucket) error {
		headerBucket := bucket.NestedReadWriteBucket(bucketName)
		err := headerBucket.Put(blockHash[:], filterTip[:])
		if err != nil {
			return fmt.Errorf("failed to store filter header: %s", err)
		}
		return nil
	}
}

// putBasicHeader stores the provided header, keyed to the block hash, in the
// basic filter header bucket in the database.
func (s *ChainService) putBasicHeader(blockHash chainhash.Hash,
	filterTip chainhash.Hash) error {
	return s.dbUpdate(putBasicHeader(blockHash, filterTip))
}

func putBasicHeader(blockHash chainhash.Hash,
	filterTip chainhash.Hash) dbUpdateOption {
	return putHeader(blockHash, basicHeaderBucketName, filterTip)
}

// putExtHeader stores the provided header, keyed to the block hash, in the
// extended filter header bucket in the database.
func (s *ChainService) putExtHeader(blockHash chainhash.Hash,
	filterTip chainhash.Hash) error {
	return s.dbUpdate(putExtHeader(blockHash, filterTip))
}

func putExtHeader(blockHash chainhash.Hash,
	filterTip chainhash.Hash) dbUpdateOption {
	return putHeader(blockHash, extHeaderBucketName, filterTip)
}

// getFilter retreives the filter, keyed to the provided block hash, from the
// appropriate filter bucket in the database.
func (s *ChainService) getFilter(blockHash chainhash.Hash,
	bucketName []byte) (*gcs.Filter, error) {
	var filter gcs.Filter
	err := s.dbView(getFilter(blockHash, bucketName, &filter))
	return &filter, err
}

func getFilter(blockHash chainhash.Hash, bucketName []byte,
	filter *gcs.Filter) dbViewOption {
	return func(bucket walletdb.ReadBucket) error {
		filterBucket := bucket.NestedReadBucket(bucketName)
		filterBytes := filterBucket.Get(blockHash[:])
		if len(filterBytes) == 0 {
			return fmt.Errorf("failed to get filter")
		}
		calcFilter, err := gcs.FromNBytes(builder.DefaultP, filterBytes)
		if calcFilter != nil {
			*filter = *calcFilter
		}
		return err
	}
}

// GetBasicFilter retrieves the filter, keyed to the provided block hash, from
// the basic filter bucket in the database.
func (s *ChainService) GetBasicFilter(blockHash chainhash.Hash) (*gcs.Filter,
	error) {
	var filter gcs.Filter
	err := s.dbView(getBasicFilter(blockHash, &filter))
	return &filter, err
}

func getBasicFilter(blockHash chainhash.Hash, filter *gcs.Filter) dbViewOption {
	return getFilter(blockHash, basicFilterBucketName, filter)
}

// GetExtFilter retrieves the filter, keyed to the provided block hash, from
// the extended filter bucket in the database.
func (s *ChainService) GetExtFilter(blockHash chainhash.Hash) (*gcs.Filter,
	error) {
	var filter gcs.Filter
	err := s.dbView(getExtFilter(blockHash, &filter))
	return &filter, err
}

func getExtFilter(blockHash chainhash.Hash, filter *gcs.Filter) dbViewOption {
	return getFilter(blockHash, extFilterBucketName, filter)
}

// getHeader retrieves the header, keyed to the provided block hash, from the
// appropriate filter header bucket in the database.
func (s *ChainService) getHeader(blockHash chainhash.Hash,
	bucketName []byte) (*chainhash.Hash, error) {
	var filterTip chainhash.Hash
	err := s.dbView(getHeader(blockHash, bucketName, &filterTip))
	return &filterTip, err
}

func getHeader(blockHash chainhash.Hash, bucketName []byte,
	filterTip *chainhash.Hash) dbViewOption {
	return func(bucket walletdb.ReadBucket) error {
		headerBucket := bucket.NestedReadBucket(bucketName)
		headerBytes := headerBucket.Get(blockHash[:])
		if len(filterTip) == 0 {
			return fmt.Errorf("failed to get filter header")
		}
		calcFilterTip, err := chainhash.NewHash(headerBytes)
		if calcFilterTip != nil {
			*filterTip = *calcFilterTip
		}
		return err
	}
}

// GetBasicHeader retrieves the header, keyed to the provided block hash, from
// the basic filter header bucket in the database.
func (s *ChainService) GetBasicHeader(blockHash chainhash.Hash) (
	*chainhash.Hash, error) {
	var filterTip chainhash.Hash
	err := s.dbView(getBasicHeader(blockHash, &filterTip))
	return &filterTip, err
}

func getBasicHeader(blockHash chainhash.Hash,
	filterTip *chainhash.Hash) dbViewOption {
	return getHeader(blockHash, basicHeaderBucketName, filterTip)
}

// GetExtHeader retrieves the header, keyed to the provided block hash, from the
// extended filter header bucket in the database.
func (s *ChainService) GetExtHeader(blockHash chainhash.Hash) (*chainhash.Hash,
	error) {
	var filterTip chainhash.Hash
	err := s.dbView(getExtHeader(blockHash, &filterTip))
	return &filterTip, err
}

func getExtHeader(blockHash chainhash.Hash,
	filterTip *chainhash.Hash) dbViewOption {
	return getHeader(blockHash, extHeaderBucketName, filterTip)
}

// rollBackLastBlock rolls back the last known block and returns the BlockStamp
// representing the new last known block.
func (s *ChainService) rollBackLastBlock() (*waddrmgr.BlockStamp, error) {
	var bs waddrmgr.BlockStamp
	err := s.dbUpdate(rollBackLastBlock(&bs))
	return &bs, err
}

func rollBackLastBlock(bs *waddrmgr.BlockStamp) dbUpdateOption {
	return func(bucket walletdb.ReadWriteBucket) error {
		headerBucket := bucket.NestedReadWriteBucket(
			blockHeaderBucketName)
		var sync waddrmgr.BlockStamp
		err := syncedTo(&sync)(bucket)
		if err != nil {
			return err
		}
		err = headerBucket.Delete(sync.Hash[:])
		if err != nil {
			return err
		}
		err = headerBucket.Delete(uint32ToBytes(uint32(sync.Height)))
		if err != nil {
			return err
		}
		err = putMaxBlockHeight(uint32(sync.Height - 1))(bucket)
		if err != nil {
			return err
		}
		sync = waddrmgr.BlockStamp{}
		err = syncedTo(&sync)(bucket)
		if sync != (waddrmgr.BlockStamp{}) {
			*bs = sync
		}
		return err
	}
}

// GetBlockByHash retrieves the block header, filter, and filter tip, based on
// the provided block hash, from the database.
func (s *ChainService) GetBlockByHash(blockHash chainhash.Hash) (
	wire.BlockHeader, uint32, error) {
	var header wire.BlockHeader
	var height uint32
	err := s.dbView(getBlockByHash(blockHash, &header, &height))
	return header, height, err
}

func getBlockByHash(blockHash chainhash.Hash, header *wire.BlockHeader,
	height *uint32) dbViewOption {
	return func(bucket walletdb.ReadBucket) error {
		headerBucket := bucket.NestedReadBucket(blockHeaderBucketName)
		blockBytes := headerBucket.Get(blockHash[:])
		if len(blockBytes) < wire.MaxBlockHeaderPayload+4 {
			return fmt.Errorf("failed to retrieve block info for"+
				" hash %s: want %d bytes, got %d.", blockHash,
				wire.MaxBlockHeaderPayload+4, len(blockBytes))
		}
		buf := bytes.NewReader(blockBytes[:wire.MaxBlockHeaderPayload])
		err := header.Deserialize(buf)
		if err != nil {
			return fmt.Errorf("failed to deserialize block header "+
				"for hash: %s", blockHash)
		}
		*height = binary.LittleEndian.Uint32(
			blockBytes[wire.MaxBlockHeaderPayload : wire.MaxBlockHeaderPayload+4])
		return nil
	}
}

// GetBlockHashByHeight retrieves the hash of a block by its height.
func (s *ChainService) GetBlockHashByHeight(height uint32) (chainhash.Hash,
	error) {
	var blockHash chainhash.Hash
	err := s.dbView(getBlockHashByHeight(height, &blockHash))
	return blockHash, err
}

func getBlockHashByHeight(height uint32,
	blockHash *chainhash.Hash) dbViewOption {
	return func(bucket walletdb.ReadBucket) error {
		headerBucket := bucket.NestedReadBucket(blockHeaderBucketName)
		hashBytes := headerBucket.Get(uint32ToBytes(height))
		if hashBytes == nil {
			return fmt.Errorf("no block hash for height %d", height)
		}
		blockHash.SetBytes(hashBytes)
		return nil
	}
}

// GetBlockByHeight retrieves a block's information by its height.
func (s *ChainService) GetBlockByHeight(height uint32) (wire.BlockHeader,
	error) {
	var header wire.BlockHeader
	err := s.dbView(getBlockByHeight(height, &header))
	return header, err
}

func getBlockByHeight(height uint32, header *wire.BlockHeader) dbViewOption {
	return func(bucket walletdb.ReadBucket) error {
		var blockHash chainhash.Hash
		err := getBlockHashByHeight(height, &blockHash)(bucket)
		if err != nil {
			return err
		}
		var gotHeight uint32
		err = getBlockByHash(blockHash, header, &gotHeight)(bucket)
		if err != nil {
			return err
		}
		if gotHeight != height {
			return fmt.Errorf("Got height %d for block at "+
				"requested height %d", gotHeight, height)
		}
		return nil
	}
}

// BestSnapshot is a synonym for SyncedTo
func (s *ChainService) BestSnapshot() (*waddrmgr.BlockStamp, error) {
	return s.SyncedTo()
}

// SyncedTo retrieves the most recent block's height and hash.
func (s *ChainService) SyncedTo() (*waddrmgr.BlockStamp, error) {
	var bs waddrmgr.BlockStamp
	err := s.dbView(syncedTo(&bs))
	return &bs, err
}

func syncedTo(bs *waddrmgr.BlockStamp) dbViewOption {
	return func(bucket walletdb.ReadBucket) error {
		var header wire.BlockHeader
		var height uint32
		err := latestBlock(&header, &height)(bucket)
		if err != nil {
			return err
		}
		bs.Hash = header.BlockHash()
		bs.Height = int32(height)
		return nil
	}
}

// LatestBlock retrieves latest stored block's header and height.
func (s *ChainService) LatestBlock() (wire.BlockHeader, uint32, error) {
	var bh wire.BlockHeader
	var h uint32
	err := s.dbView(latestBlock(&bh, &h))
	return bh, h, err
}

func latestBlock(header *wire.BlockHeader, height *uint32) dbViewOption {
	return func(bucket walletdb.ReadBucket) error {
		maxBlockHeightBytes := bucket.Get(maxBlockHeightName)
		if maxBlockHeightBytes == nil {
			return fmt.Errorf("no max block height stored")
		}
		*height = binary.LittleEndian.Uint32(maxBlockHeightBytes)
		return getBlockByHeight(*height, header)(bucket)
	}
}

// BlockLocatorFromHash returns a block locator based on the provided hash.
func (s *ChainService) BlockLocatorFromHash(hash chainhash.Hash) (
	blockchain.BlockLocator, error) {
	var locator blockchain.BlockLocator
	err := s.dbView(blockLocatorFromHash(hash, &locator))
	return locator, err
}

func blockLocatorFromHash(hash chainhash.Hash,
	locator *blockchain.BlockLocator) dbViewOption {
	return func(bucket walletdb.ReadBucket) error {
		// Append the initial hash
		*locator = append(*locator, &hash)
		// If hash isn't found in DB or this is the genesis block, return
		// the locator as is
		var header wire.BlockHeader
		var height uint32
		err := getBlockByHash(hash, &header, &height)(bucket)
		if (err != nil) || (height == 0) {
			return nil
		}

		decrement := uint32(1)
		for (height > 0) && (len(*locator) < wire.MaxBlockLocatorsPerMsg) {
			// Decrement by 1 for the first 10 blocks, then double the
			// jump until we get to the genesis hash
			if len(*locator) > 10 {
				decrement *= 2
			}
			if decrement > height {
				height = 0
			} else {
				height -= decrement
			}
			var blockHash chainhash.Hash
			err := getBlockHashByHeight(height, &blockHash)(bucket)
			if err != nil {
				return nil
			}
			*locator = append(*locator, &blockHash)
		}
		return nil
	}
}

// LatestBlockLocator returns the block locator for the latest known block
// stored in the database.
func (s *ChainService) LatestBlockLocator() (blockchain.BlockLocator, error) {
	var locator blockchain.BlockLocator
	err := s.dbView(latestBlockLocator(&locator))
	return locator, err
}

func latestBlockLocator(locator *blockchain.BlockLocator) dbViewOption {
	return func(bucket walletdb.ReadBucket) error {
		var best waddrmgr.BlockStamp
		err := syncedTo(&best)(bucket)
		if err != nil {
			return err
		}
		return blockLocatorFromHash(best.Hash, locator)(bucket)
	}
}

// CheckConnectivity cycles through all of the block headers, from last to
// first, and makes sure they all connect to each other.
func (s *ChainService) CheckConnectivity() error {
	return s.dbView(checkConnectivity())
}

func checkConnectivity() dbViewOption {
	return func(bucket walletdb.ReadBucket) error {
		var header wire.BlockHeader
		var height uint32
		err := latestBlock(&header, &height)(bucket)
		if err != nil {
			return fmt.Errorf("Couldn't retrieve latest block: %s",
				err)
		}
		for height > 0 {
			var newHeader wire.BlockHeader
			var newHeight uint32
			err := getBlockByHash(header.PrevBlock, &newHeader,
				&newHeight)(bucket)
			if err != nil {
				return fmt.Errorf("Couldn't retrieve block %s:"+
					" %s", header.PrevBlock, err)
			}
			if newHeader.BlockHash() != header.PrevBlock {
				return fmt.Errorf("Block %s doesn't match "+
					"block %s's PrevBlock (%s)",
					newHeader.BlockHash(),
					header.BlockHash(), header.PrevBlock)
			}
			if newHeight != height-1 {
				return fmt.Errorf("Block %s doesn't have "+
					"correct height: want %d, got %d",
					newHeader.BlockHash(), height-1,
					newHeight)
			}
			header = newHeader
			height = newHeight
		}
		return nil
	}
}

// createSPVNS creates the initial namespace structure needed for all of the
// SPV-related data.  This includes things such as all of the buckets as well as
// the version and creation date.
func (s *ChainService) createSPVNS() error {
	tx, err := s.db.BeginReadWriteTx()
	if err != nil {
		return err
	}

	spvBucket, err := tx.CreateTopLevelBucket(spvBucketName)
	if err != nil {
		return fmt.Errorf("failed to create main bucket: %s", err)
	}

	_, err = spvBucket.CreateBucketIfNotExists(blockHeaderBucketName)
	if err != nil {
		return fmt.Errorf("failed to create block header bucket: %s",
			err)
	}

	_, err = spvBucket.CreateBucketIfNotExists(basicFilterBucketName)
	if err != nil {
		return fmt.Errorf("failed to create basic filter "+
			"bucket: %s", err)
	}

	_, err = spvBucket.CreateBucketIfNotExists(basicHeaderBucketName)
	if err != nil {
		return fmt.Errorf("failed to create basic header "+
			"bucket: %s", err)
	}

	_, err = spvBucket.CreateBucketIfNotExists(extFilterBucketName)
	if err != nil {
		return fmt.Errorf("failed to create extended filter "+
			"bucket: %s", err)
	}

	_, err = spvBucket.CreateBucketIfNotExists(extHeaderBucketName)
	if err != nil {
		return fmt.Errorf("failed to create extended header "+
			"bucket: %s", err)
	}

	createDate := spvBucket.Get(dbCreateDateName)
	if createDate != nil {
		log.Info("Wallet SPV namespace already created.")
		return nil
	}

	log.Info("Creating wallet SPV namespace.")

	basicFilter, err := builder.BuildBasicFilter(
		s.chainParams.GenesisBlock)
	if err != nil {
		return err
	}

	basicFilterTip := builder.MakeHeaderForFilter(basicFilter,
		s.chainParams.GenesisBlock.Header.PrevBlock)

	extFilter, err := builder.BuildExtFilter(
		s.chainParams.GenesisBlock)
	if err != nil {
		return err
	}

	extFilterTip := builder.MakeHeaderForFilter(extFilter,
		s.chainParams.GenesisBlock.Header.PrevBlock)

	err = putBlock(s.chainParams.GenesisBlock.Header, 0)(spvBucket)
	if err != nil {
		return err
	}

	err = putBasicFilter(*s.chainParams.GenesisHash, basicFilter)(spvBucket)
	if err != nil {
		return err
	}

	err = putBasicHeader(*s.chainParams.GenesisHash, basicFilterTip)(
		spvBucket)
	if err != nil {
		return err
	}

	err = putExtFilter(*s.chainParams.GenesisHash, extFilter)(spvBucket)
	if err != nil {
		return err
	}

	err = putExtHeader(*s.chainParams.GenesisHash, extFilterTip)(spvBucket)
	if err != nil {
		return err
	}

	err = putDBVersion(latestDBVersion)(spvBucket)
	if err != nil {
		return err
	}

	err = putMaxBlockHeight(0)(spvBucket)
	if err != nil {
		return err
	}

	err = spvBucket.Put(dbCreateDateName,
		uint64ToBytes(uint64(time.Now().Unix())))
	if err != nil {
		return fmt.Errorf("failed to store database creation "+
			"time: %s", err)
	}

	return tx.Commit()
}

// dbUpdate allows the passed function to update the ChainService DB bucket.
func (s *ChainService) dbUpdate(updateFunc dbUpdateOption) error {
	tx, err := s.db.BeginReadWriteTx()
	if err != nil {
		tx.Rollback()
		return err
	}
	bucket := tx.ReadWriteBucket(spvBucketName)
	err = updateFunc(bucket)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// dbView allows the passed function to read the ChainService DB bucket.
func (s *ChainService) dbView(viewFunc dbViewOption) error {
	tx, err := s.db.BeginReadTx()
	defer tx.Rollback()
	if err != nil {
		return err
	}
	bucket := tx.ReadBucket(spvBucketName)
	return viewFunc(bucket)

}
