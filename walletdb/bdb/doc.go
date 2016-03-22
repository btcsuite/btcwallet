// Copyright (c) 2014 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package bdb implements an instance of walletdb that uses boltdb for the backing
datastore.

Usage

This package is only a driver to the walletdb package and provides the database
type of "bdb".  The only parameter the Open and Create functions take is the
database path as a string:

	db, err := walletdb.Open("bdb", "path/to/database.db")
	if err != nil {
		// Handle error
	}

	db, err := walletdb.Create("bdb", "path/to/database.db")
	if err != nil {
		// Handle error
	}
*/
package bdb
