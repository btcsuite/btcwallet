// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bdb

import (
	"fmt"

	"github.com/btcsuite/btcwallet/walletdb"
	"go.etcd.io/bbolt"
)

const (
	dbType = "bdb"
)

// parseArgs parses the arguments from the walletdb Open/Create methods.
func parseArgs(funcName string, args ...interface{}) (string, *bbolt.Options, error) {
	if len(args) != 2 {
		return "", nil, fmt.Errorf("invalid arguments to %s.%s -- "+
			"expected database path and *bbolt.Option option",
			dbType, funcName)
	}

	dbPath, ok := args[0].(string)
	if !ok {
		return "", nil, fmt.Errorf("first argument to %s.%s is "+
			"invalid -- expected database path string", dbType,
			funcName)
	}

	options, ok := args[1].(*bbolt.Options)
	if !ok {
		return "", nil, fmt.Errorf("second argument to %s.%s is "+
			"invalid -- expected *bbolt.Option", dbType,
			funcName)
	}

	return dbPath, options, nil
}

// openDBDriver is the callback provided during driver registration that opens
// an existing database for use.
func openDBDriver(args ...interface{}) (walletdb.DB, error) {
	dbPath, options, err := parseArgs("Open", args...)
	if err != nil {
		return nil, err
	}

	return openDB(dbPath, false, options)
}

// createDBDriver is the callback provided during driver registration that
// creates, initializes, and opens a database for use.
func createDBDriver(args ...interface{}) (walletdb.DB, error) {
	dbPath, options, err := parseArgs("Create", args...)
	if err != nil {
		return nil, err
	}

	return openDB(dbPath, true, options)
}

func init() {
	// Register the driver.
	driver := walletdb.Driver{
		DbType: dbType,
		Create: createDBDriver,
		Open:   openDBDriver,
	}
	if err := walletdb.RegisterDriver(driver); err != nil {
		panic(fmt.Sprintf("Failed to regiser database driver '%s': %v",
			dbType, err))
	}
}
