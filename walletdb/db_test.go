// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package walletdb_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
)

var (
	// ignoreDbTypes are types which should be ignored when running tests
	// that iterate all supported DB types.  This allows some tests to add
	// bogus drivers for testing purposes while still allowing other tests
	// to easily iterate all supported drivers.
	ignoreDbTypes = map[string]bool{"createopenfail": true}

	// defaultDBTimeout specifies the timeout value when opening the wallet
	// database.
	defaultDBTimeout = 10 * time.Second
)

// TestAddDuplicateDriver ensures that adding a duplicate driver does not
// overwrite an existing one.
func TestAddDuplicateDriver(t *testing.T) {
	supportedDrivers := walletdb.SupportedDrivers()
	if len(supportedDrivers) == 0 {
		t.Errorf("no backends to test")
		return
	}
	dbType := supportedDrivers[0]

	// bogusCreateDB is a function which acts as a bogus create and open
	// driver function and intentionally returns a failure that can be
	// detected if the interface allows a duplicate driver to overwrite an
	// existing one.
	bogusCreateDB := func(args ...interface{}) (walletdb.DB, error) {
		return nil, fmt.Errorf("duplicate driver allowed for database "+
			"type [%v]", dbType)
	}

	// Create a driver that tries to replace an existing one.  Set its
	// create and open functions to a function that causes a test failure if
	// they are invoked.
	driver := walletdb.Driver{
		DbType: dbType,
		Create: bogusCreateDB,
		Open:   bogusCreateDB,
	}
	err := walletdb.RegisterDriver(driver)
	if err != walletdb.ErrDbTypeRegistered {
		t.Errorf("unexpected duplicate driver registration error - "+
			"got %v, want %v", err, walletdb.ErrDbTypeRegistered)
	}

	tempDir, err := os.MkdirTemp("", "dupdrivertest")
	if err != nil {
		t.Errorf("unable to create temp dir: %v", err)
		return
	}
	defer os.Remove(tempDir)

	dbPath := filepath.Join(tempDir, "db")
	db, err := walletdb.Create(dbType, dbPath, true, defaultDBTimeout)
	if err != nil {
		t.Errorf("failed to create database: %v", err)
		return
	}
	db.Close()

}

// TestCreateOpenFail ensures that errors which occur while opening or closing
// a database are handled properly.
func TestCreateOpenFail(t *testing.T) {
	// bogusCreateDB is a function which acts as a bogus create and open
	// driver function that intentionally returns a failure which can be
	// detected.
	dbType := "createopenfail"
	openError := fmt.Errorf("failed to create or open database for "+
		"database type [%v]", dbType)
	bogusCreateDB := func(args ...interface{}) (walletdb.DB, error) {
		return nil, openError
	}

	// Create and add driver that intentionally fails when created or opened
	// to ensure errors on database open and create are handled properly.
	driver := walletdb.Driver{
		DbType: dbType,
		Create: bogusCreateDB,
		Open:   bogusCreateDB,
	}
	walletdb.RegisterDriver(driver)

	// Ensure creating a database with the new type fails with the expected
	// error.
	_, err := walletdb.Create(dbType)
	if err != openError {
		t.Errorf("expected error not received - got: %v, want %v", err,
			openError)
		return
	}

	// Ensure opening a database with the new type fails with the expected
	// error.
	_, err = walletdb.Open(dbType)
	if err != openError {
		t.Errorf("expected error not received - got: %v, want %v", err,
			openError)
		return
	}
}

// TestCreateOpenUnsupported ensures that attempting to create or open an
// unsupported database type is handled properly.
func TestCreateOpenUnsupported(t *testing.T) {
	// Ensure creating a database with an unsupported type fails with the
	// expected error.
	dbType := "unsupported"
	_, err := walletdb.Create(dbType)
	if err != walletdb.ErrDbUnknownType {
		t.Errorf("expected error not received - got: %v, want %v", err,
			walletdb.ErrDbUnknownType)
		return
	}

	// Ensure opening a database with the an unsupported type fails with the
	// expected error.
	_, err = walletdb.Open(dbType)
	if err != walletdb.ErrDbUnknownType {
		t.Errorf("expected error not received - got: %v, want %v", err,
			walletdb.ErrDbUnknownType)
		return
	}
}
