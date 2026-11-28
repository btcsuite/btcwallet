package bwtest

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// TestPostgresDatabaseNameSafe verifies that arbitrary subtest names become
// short identifiers containing only a fixed prefix and lowercase hex.
func TestPostgresDatabaseNameSafe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "punctuation",
			input: `TestManager/reopen; DROP DATABASE postgres`,
		},
		{
			name: "long name",
			input: "TestManager/this name is deliberately much longer " +
				"than a PostgreSQL identifier",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			name := postgresDatabaseName(test.input)

			require.Regexp(t, `^bwtest_[0-9a-f]{24}$`, name)
			require.Equal(t, name, postgresDatabaseName(test.input))
		})
	}
}

// TestPostgresDatabaseNameDistinct verifies that different subtests do not
// select the same isolated database.
func TestPostgresDatabaseNameDistinct(t *testing.T) {
	t.Parallel()

	require.NotEqual(
		t, postgresDatabaseName("TestManager/create"),
		postgresDatabaseName("TestManager/load"),
	)
}

// TestPostgresDatabaseDSNSelectsDatabase verifies that rewriting retains the
// administrative endpoint and selects only the isolated database.
func TestPostgresDatabaseDSNSelectsDatabase(t *testing.T) {
	t.Parallel()

	const adminDSN = "postgres://user:pass@localhost:5432/postgres?" +
		"sslmode=disable"

	dsn, err := postgresDatabaseDSN(adminDSN, "bwtest_deadbeef")
	require.NoError(t, err)

	cfg, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	require.Equal(t, "bwtest_deadbeef", cfg.Database)
	require.Equal(t, "localhost", cfg.Host)
	require.Equal(t, uint16(5432), cfg.Port)
	require.Equal(t, "user", cfg.User)
}

// TestPostgresDatabaseDSNRejectsInvalid verifies that malformed administrative
// configuration is reported before a database can be selected.
func TestPostgresDatabaseDSNRejectsInvalid(t *testing.T) {
	t.Parallel()

	dsn, err := postgresDatabaseDSN("://invalid", "bwtest_deadbeef")
	require.ErrorContains(t, err, "parse postgres admin DSN")
	require.Empty(t, dsn)
}
