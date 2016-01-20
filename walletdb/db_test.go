/*
 * Copyright (c) 2014 The btcsuite developers
 * Copyright (c) 2015 The Decred developers
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package walletdb_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/decred/dcrwallet/walletdb"
	_ "github.com/decred/dcrwallet/walletdb/bdb"
)

var (
	// ignoreDbTypes are types which should be ignored when running tests
	// that iterate all supported DB types.  This allows some tests to add
	// bogus drivers for testing purposes while still allowing other tests
	// to easily iterate all supported drivers.
	ignoreDbTypes = map[string]bool{"createopenfail": true}
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

	dbPath := "dupdrivertest.db"
	db, err := walletdb.Create(dbType, dbPath)
	if err != nil {
		t.Errorf("failed to create database: %v", err)
		return
	}
	db.Close()
	_ = os.Remove(dbPath)

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
