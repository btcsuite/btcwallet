// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bdb

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
)

const (
	dbType = "bdb"
)

// dbArgs holds the parsed arguments of the walletdb Open/Create methods.
type dbArgs struct {
	// dbPath is the path of the database file.
	dbPath string

	// noFreelistSync prevents the database from syncing its freelist to
	// disk.
	noFreelistSync bool

	// timeout is the amount of time to wait to obtain the file lock.
	timeout time.Duration

	// readOnly opens the database in read-only mode.
	readOnly bool

	// mmapFlags are additional flags to set when memory mapping the
	// database file, such as syscall.MAP_POPULATE on Linux.
	mmapFlags int
}

// parseArgs parses the arguments from the walletdb Open/Create methods.
func parseArgs(funcName string, args ...interface{}) (*dbArgs, error) {
	if len(args) < 4 || len(args) > 5 {
		return nil, fmt.Errorf("invalid arguments to %s.%s "+
			"-- expected database path, no-freelist-sync, "+
			"timeout option, read-only flag and optional mmap "+
			"flags", dbType, funcName)
	}

	dbPath, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("first argument to %s.%s is "+
			"invalid -- expected database path string", dbType,
			funcName)
	}

	noFreelistSync, ok := args[1].(bool)
	if !ok {
		return nil, fmt.Errorf("second argument to %s.%s is "+
			"invalid -- expected no-freelist-sync bool", dbType,
			funcName)
	}

	timeout, ok := args[2].(time.Duration)
	if !ok {
		return nil, fmt.Errorf("third argument to %s.%s is "+
			"invalid -- expected timeout time.Duration", dbType,
			funcName)
	}

	readOnly, ok := args[3].(bool)
	if !ok {
		return nil, fmt.Errorf("fourth argument to %s.%s is "+
			"invalid -- expected read-only bool", dbType,
			funcName)
	}

	// The mmap flags are optional to remain compatible with callers that
	// only pass the four arguments above.
	var mmapFlags int
	if len(args) == 5 {
		mmapFlags, ok = args[4].(int)
		if !ok {
			return nil, fmt.Errorf("fifth argument to %s.%s is "+
				"invalid -- expected mmap flags int", dbType,
				funcName)
		}
	}

	return &dbArgs{
		dbPath:         dbPath,
		noFreelistSync: noFreelistSync,
		timeout:        timeout,
		readOnly:       readOnly,
		mmapFlags:      mmapFlags,
	}, nil
}

// openDBDriver is the callback provided during driver registration that opens
// an existing database for use.
func openDBDriver(args ...interface{}) (walletdb.DB, error) {
	dbArgs, err := parseArgs("Open", args...)
	if err != nil {
		return nil, err
	}

	return openDB(dbArgs, false)
}

// createDBDriver is the callback provided during driver registration that
// creates, initializes, and opens a database for use.
func createDBDriver(args ...interface{}) (walletdb.DB, error) {
	dbArgs, err := parseArgs("Create", args...)
	if err != nil {
		return nil, err
	}

	return openDB(dbArgs, true)
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
