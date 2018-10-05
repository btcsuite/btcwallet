package wtxmgr

import "github.com/btcsuite/btcwallet/walletdb"

// dbVersion encapsulates a version along with a migration closure that, once
// complete, will reflect the current version of the store.
type dbVersion struct {
	version   uint32
	migration func(walletdb.ReadWriteBucket) error
}

// dbVersions represents the different versions of the store, along with the
// migrations allowing them to proceed to said versions.
var dbVersions = []dbVersion{
	{
		version:   1,
		migration: nil,
	},
	{
		version:   2,
		migration: migrationBucketMinedInputs,
	},
}

// getLatestDBVersion retrieves the most recent recent of the store.
func getLatestDBVersion() uint32 {
	return dbVersions[len(dbVersions)-1].version
}

// getMigrationsToApply determines the migrations that need to be applied in
// order for the given version to catch up to the latest version.
func getMigrationsToApply(version uint32) []dbVersion {
	// Assuming the migration versions are in increasing order, we'll apply
	// any migrations that have a version
	var migrations []dbVersion
	for _, dbVersion := range dbVersions {
		if dbVersion.version > version {
			migrations = append(migrations, dbVersion)
		}
	}
	return migrations
}

// migrationBucketMinedInputs is the migration responsible for creating a new
// bucket which will store a mapping of a spent output to its spending
// transaction.
func migrationBucketMinedInputs(ns walletdb.ReadWriteBucket) error {
	log.Infof("Populating index of outputs to spending transactions")

	// We'll start by creating the bucket that will represent the index.
	if _, err := ns.CreateBucket(bucketMinedInputs); err != nil {
		str := "failed to create mined inputs bucket"
		return storeError(ErrDatabase, str, err)
	}

	// We'll define a helper struct to coalesce all outputs and their
	// confirmed spending transactions. The members will need to be
	// serialized in the expected format of the new bucket.
	type bucketEntry struct {
		outpointSpent []byte
		spendTx       []byte
	}

	var bucketEntries []bucketEntry

	// Then, we'll iterate over the debits bucket. This bucket includes all
	// the inputs that have spent outputs controlled by the wallet. Each
	// entry then maps to the output it spends, which will allow us to
	// populate the new bucket.
	c := ns.NestedReadBucket(bucketDebits).ReadCursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		// Each value of the debits bucket includes the block at which
		// the spent output confirmed at. We're not interested in all of
		// the information, so we'll omit it and only grab what we need
		// (transaction hash and output index).
		outpointSpent := make([]byte, 32+4)
		copy(outpointSpent[:32], v[8:40])
		copy(outpointSpent[32:], v[76:80])

		bucketEntries = append(bucketEntries, bucketEntry{
			outpointSpent: outpointSpent,
			spendTx:       k,
		})
	}

	// Now that we've gathered all of our results, we'll insert them into
	// our new bucket. Once they've all been inserted, we can consider the
	// migration complete.
	for _, bucketEntry := range bucketEntries {
		err := putRawMinedInput(
			ns, bucketEntry.outpointSpent, bucketEntry.spendTx,
		)
		if err != nil {
			return err
		}
	}

	log.Info("Migration to populate index of outputs to spending " +
		"transaction complete!")

	return nil
}
