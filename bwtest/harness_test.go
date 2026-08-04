package bwtest

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBackendArtifactValidatesExpectedBackend verifies that backend artifact
// validation reports positive, mismatched, and malformed headers without
// depending on testing.T failure state.
func TestBackendArtifactValidatesExpectedBackend(t *testing.T) {
	t.Parallel()

	sqliteHeader := make([]byte, bboltMagicOffset+bboltMagicLen)
	copy(sqliteHeader, sqliteHeaderMagic)

	kvdbHeader := make([]byte, bboltMagicOffset+bboltMagicLen)
	binary.LittleEndian.PutUint32(
		kvdbHeader[bboltMagicOffset:], bboltMagic,
	)

	testCases := []struct {
		name    string
		dbType  string
		header  []byte
		wantErr string
	}{
		{name: "sqlite matches", dbType: dbNameSQLite,
			header: sqliteHeader},
		{name: "kvdb matches", dbType: dbNameKvdb,
			header: kvdbHeader},
		{
			name:    "sqlite mismatches kvdb",
			dbType:  dbNameKvdb,
			header:  sqliteHeader,
			wantErr: "is a sqlite database",
		},
		{
			name:    "kvdb mismatches sqlite",
			dbType:  dbNameSQLite,
			header:  kvdbHeader,
			wantErr: "is a kvdb database",
		},
		{
			name:    "unknown header",
			dbType:  dbNameSQLite,
			header:  make([]byte, bboltMagicOffset+bboltMagicLen),
			wantErr: "unrecognized wallet database artifact",
		},
		{
			name:    "truncated header",
			dbType:  dbNameKvdb,
			header:  []byte("short"),
			wantErr: "read wallet database header",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			dbPath := filepath.Join(t.TempDir(), "wallet.db")
			err := os.WriteFile(dbPath, testCase.header, 0o600)
			require.NoError(t, err)

			err = validateBackendArtifact(testCase.dbType, dbPath)
			if testCase.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.ErrorContains(t, err, testCase.wantErr)
		})
	}
}
