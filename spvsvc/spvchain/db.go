package spvchain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/gcs"
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
	spvBucketName         = []byte("spv")
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

// fetchDBVersion fetches the current manager version from the database.
func fetchDBVersion(tx walletdb.Tx) (uint32, error) {
	bucket := tx.RootBucket().Bucket(spvBucketName)
	verBytes := bucket.Get(dbVersionName)
	if verBytes == nil {
		return 0, fmt.Errorf("required version number not stored in " +
			"database")
	}
	version := binary.LittleEndian.Uint32(verBytes)
	return version, nil
}

// putDBVersion stores the provided version to the database.
func putDBVersion(tx walletdb.Tx, version uint32) error {
	bucket := tx.RootBucket().Bucket(spvBucketName)

	verBytes := uint32ToBytes(version)
	return bucket.Put(dbVersionName, verBytes)
}

// putMaxBlockHeight stores the max block height to the database.
func putMaxBlockHeight(tx walletdb.Tx, maxBlockHeight uint32) error {
	bucket := tx.RootBucket().Bucket(spvBucketName)

	maxBlockHeightBytes := uint32ToBytes(maxBlockHeight)
	err := bucket.Put(maxBlockHeightName, maxBlockHeightBytes)
	if err != nil {
		return fmt.Errorf("failed to store max block height: %s", err)
	}
	return nil
}

// putBlock stores the provided block header and height, keyed to the block
// hash, in the database.
func putBlock(tx walletdb.Tx, header wire.BlockHeader, height uint32) error {
	var buf bytes.Buffer
	err := header.Serialize(&buf)
	if err != nil {
		return err
	}
	_, err = buf.Write(uint32ToBytes(height))
	if err != nil {
		return err
	}

	bucket := tx.RootBucket().Bucket(spvBucketName).Bucket(blockHeaderBucketName)
	blockHash := header.BlockHash()

	err = bucket.Put(blockHash[:], buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to store SPV block info: %s", err)
	}

	err = bucket.Put(uint32ToBytes(height), blockHash[:])
	if err != nil {
		return fmt.Errorf("failed to store block height info: %s", err)
	}

	return nil
}

// putFilter stores the provided filter, keyed to the block hash, in the
// appropriate filter bucket in the database.
func putFilter(tx walletdb.Tx, blockHash chainhash.Hash, bucketName []byte,
	filter *gcs.Filter) error {
	var buf bytes.Buffer
	_, err := buf.Write(filter.NBytes())
	if err != nil {
		return err
	}

	bucket := tx.RootBucket().Bucket(spvBucketName).Bucket(bucketName)

	err = bucket.Put(blockHash[:], buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to store filter: %s", err)
	}

	return nil
}

// putBasicFilter stores the provided filter, keyed to the block hash, in the
// basic filter bucket in the database.
func putBasicFilter(tx walletdb.Tx, blockHash chainhash.Hash,
	filter *gcs.Filter) error {
	return putFilter(tx, blockHash, basicFilterBucketName, filter)
}

// putExtFilter stores the provided filter, keyed to the block hash, in the
// extended filter bucket in the database.
func putExtFilter(tx walletdb.Tx, blockHash chainhash.Hash,
	filter *gcs.Filter) error {
	return putFilter(tx, blockHash, extFilterBucketName, filter)
}

// putHeader stores the provided filter, keyed to the block hash, in the
// appropriate filter bucket in the database.
func putHeader(tx walletdb.Tx, blockHash chainhash.Hash, bucketName []byte,
	filterTip chainhash.Hash) error {

	bucket := tx.RootBucket().Bucket(spvBucketName).Bucket(bucketName)

	err := bucket.Put(blockHash[:], filterTip[:])
	if err != nil {
		return fmt.Errorf("failed to store filter header: %s", err)
	}

	return nil
}

// putBasicHeader stores the provided filter, keyed to the block hash, in the
// basic filter bucket in the database.
func putBasicHeader(tx walletdb.Tx, blockHash chainhash.Hash,
	filterTip chainhash.Hash) error {
	return putHeader(tx, blockHash, basicHeaderBucketName, filterTip)
}

// putExtHeader stores the provided filter, keyed to the block hash, in the
// extended filter bucket in the database.
func putExtHeader(tx walletdb.Tx, blockHash chainhash.Hash,
	filterTip chainhash.Hash) error {
	return putHeader(tx, blockHash, extHeaderBucketName, filterTip)
}

// rollbackLastBlock rolls back the last known block and returns the BlockStamp
// representing the new last known block.
func rollbackLastBlock(tx walletdb.Tx) (*waddrmgr.BlockStamp, error) {
	bs, err := SyncedTo(tx)
	if err != nil {
		return nil, err
	}
	bucket := tx.RootBucket().Bucket(spvBucketName).Bucket(blockHeaderBucketName)
	err = bucket.Delete(bs.Hash[:])
	if err != nil {
		return nil, err
	}
	err = bucket.Delete(uint32ToBytes(uint32(bs.Height)))
	if err != nil {
		return nil, err
	}
	err = putMaxBlockHeight(tx, uint32(bs.Height-1))
	if err != nil {
		return nil, err
	}
	return SyncedTo(tx)
}

// GetBlockByHash retrieves the block header, filter, and filter tip, based on
// the provided block hash, from the database.
func GetBlockByHash(tx walletdb.Tx, blockHash chainhash.Hash) (wire.BlockHeader,
	uint32, error) {
	//chainhash.Hash, chainhash.Hash,
	bucket := tx.RootBucket().Bucket(spvBucketName).Bucket(blockHeaderBucketName)
	blockBytes := bucket.Get(blockHash[:])
	if len(blockBytes) == 0 {
		return wire.BlockHeader{}, 0,
			fmt.Errorf("failed to retrieve block info for hash: %s",
				blockHash)
	}

	buf := bytes.NewReader(blockBytes[:wire.MaxBlockHeaderPayload])
	var header wire.BlockHeader
	err := header.Deserialize(buf)
	if err != nil {
		return wire.BlockHeader{}, 0,
			fmt.Errorf("failed to deserialize block header for "+
				"hash: %s", blockHash)
	}

	height := binary.LittleEndian.Uint32(
		blockBytes[wire.MaxBlockHeaderPayload : wire.MaxBlockHeaderPayload+4])

	return header, height, nil
}

// GetBlockHashByHeight retrieves the hash of a block by its height.
func GetBlockHashByHeight(tx walletdb.Tx, height uint32) (chainhash.Hash,
	error) {
	bucket := tx.RootBucket().Bucket(spvBucketName).Bucket(blockHeaderBucketName)
	var hash chainhash.Hash
	hashBytes := bucket.Get(uint32ToBytes(height))
	if hashBytes == nil {
		return hash, fmt.Errorf("no block hash for height %d", height)
	}
	hash.SetBytes(hashBytes)
	return hash, nil
}

// GetBlockByHeight retrieves a block's information by its height.
func GetBlockByHeight(tx walletdb.Tx, height uint32) (wire.BlockHeader, uint32,
	error) {
	// chainhash.Hash, chainhash.Hash
	blockHash, err := GetBlockHashByHeight(tx, height)
	if err != nil {
		return wire.BlockHeader{}, 0, err
	}

	return GetBlockByHash(tx, blockHash)
}

// SyncedTo retrieves the most recent block's height and hash.
func SyncedTo(tx walletdb.Tx) (*waddrmgr.BlockStamp, error) {
	header, height, err := LatestBlock(tx)
	if err != nil {
		return nil, err
	}
	var blockStamp waddrmgr.BlockStamp
	blockStamp.Hash = header.BlockHash()
	blockStamp.Height = int32(height)
	return &blockStamp, nil
}

// LatestBlock retrieves all the info about the latest stored block.
func LatestBlock(tx walletdb.Tx) (wire.BlockHeader, uint32, error) {
	bucket := tx.RootBucket().Bucket(spvBucketName)

	maxBlockHeightBytes := bucket.Get(maxBlockHeightName)
	if maxBlockHeightBytes == nil {
		return wire.BlockHeader{}, 0,
			fmt.Errorf("no max block height stored")
	}

	maxBlockHeight := binary.LittleEndian.Uint32(maxBlockHeightBytes)
	header, height, err := GetBlockByHeight(tx, maxBlockHeight)
	if err != nil {
		return wire.BlockHeader{}, 0, err
	}
	if height != maxBlockHeight {
		return wire.BlockHeader{}, 0,
			fmt.Errorf("max block height inconsistent")
	}
	return header, height, nil
}

// BlockLocatorFromHash returns a block locator based on the provided hash.
func BlockLocatorFromHash(tx walletdb.Tx, hash chainhash.Hash) blockchain.BlockLocator {
	locator := make(blockchain.BlockLocator, 0, wire.MaxBlockLocatorsPerMsg)
	locator = append(locator, &hash)

	// If hash isn't found in DB or this is the genesis block, return
	// the locator as is
	_, height, err := GetBlockByHash(tx, hash)
	if (err != nil) || (height == 0) {
		return locator
	}

	decrement := uint32(1)
	for (height > 0) && (len(locator) < wire.MaxBlockLocatorsPerMsg) {
		// Decrement by 1 for the first 10 blocks, then double the
		// jump until we get to the genesis hash
		if len(locator) > 10 {
			decrement *= 2
		}
		if decrement > height {
			height = 0
		} else {
			height -= decrement
		}
		blockHash, err := GetBlockHashByHeight(tx, height)
		if err != nil {
			return locator
		}
		locator = append(locator, &blockHash)
	}

	return locator
}

// createSPVNS creates the initial namespace structure needed for all of the
// SPV-related data.  This includes things such as all of the buckets as well as
// the version and creation date.
func createSPVNS(namespace walletdb.Namespace, params *chaincfg.Params) error {
	err := namespace.Update(func(tx walletdb.Tx) error {
		rootBucket := tx.RootBucket()
		spvBucket, err := rootBucket.CreateBucketIfNotExists(spvBucketName)
		if err != nil {
			return fmt.Errorf("failed to create main bucket: %s",
				err)
		}

		_, err = spvBucket.CreateBucketIfNotExists(blockHeaderBucketName)
		if err != nil {
			return fmt.Errorf("failed to create block header "+
				"bucket: %s", err)
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

		basicFilter, err := buildBasicFilter(params.GenesisBlock)
		if err != nil {
			return err
		}

		basicFilterTip := makeHeaderForFilter(basicFilter,
			params.GenesisBlock.Header.PrevBlock)

		extFilter, err := buildExtFilter(params.GenesisBlock)
		if err != nil {
			return err
		}

		extFilterTip := makeHeaderForFilter(extFilter,
			params.GenesisBlock.Header.PrevBlock)

		err = putBlock(tx, params.GenesisBlock.Header, 0)
		if err != nil {
			return err
		}

		err = putBasicFilter(tx, *params.GenesisHash, basicFilter)
		if err != nil {
			return err
		}

		err = putBasicHeader(tx, *params.GenesisHash, basicFilterTip)
		if err != nil {
			return err
		}

		err = putExtFilter(tx, *params.GenesisHash, extFilter)
		if err != nil {
			return err
		}

		err = putExtHeader(tx, *params.GenesisHash, extFilterTip)
		if err != nil {
			return err
		}

		err = putDBVersion(tx, latestDBVersion)
		if err != nil {
			return err
		}

		err = putMaxBlockHeight(tx, 0)
		if err != nil {
			return err
		}

		err = spvBucket.Put(dbCreateDateName,
			uint64ToBytes(uint64(time.Now().Unix())))
		if err != nil {
			return fmt.Errorf("failed to store database creation "+
				"time: %s", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update database: %s", err)
	}

	return nil
}
