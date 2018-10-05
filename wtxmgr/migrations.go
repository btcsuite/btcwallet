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
