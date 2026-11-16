package bdb_test

import (
	"bytes"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
)

// TestMmapFlags ensures that a database can be created, written to and
// re-opened when additional mmap flags are passed to the driver.
func TestMmapFlags(t *testing.T) {
	var (
		dbPath = filepath.Join(t.TempDir(), "db")
		bucket = []byte("bucket")
		key    = []byte("key")
		value  = []byte("value")
	)

	db, err := walletdb.Create(
		dbType, dbPath, true, defaultDBTimeout, false,
		syscall.MAP_POPULATE,
	)
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		b, err := tx.CreateTopLevelBucket(bucket)
		if err != nil {
			return err
		}

		return b.Put(key, value)
	})
	if err != nil {
		t.Fatalf("Update: unexpected error: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: unexpected error: %v", err)
	}

	db, err = walletdb.Open(
		dbType, dbPath, true, defaultDBTimeout, false,
		syscall.MAP_POPULATE,
	)
	if err != nil {
		t.Fatalf("Open: unexpected error: %v", err)
	}
	defer db.Close()

	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		got := tx.ReadBucket(bucket).Get(key)
		if !bytes.Equal(got, value) {
			t.Fatalf("Get: got %q, want %q", got, value)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("View: unexpected error: %v", err)
	}
}
