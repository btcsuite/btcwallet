package pg

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestConnectionConfigRequireSSL verifies that SSL enforcement works for both
// DSN formats accepted by pgx without weakening stricter verification modes.
func TestConnectionConfigRequireSSL(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name               string
		dsn                string
		wantSkipVerify     bool
		wantServerName     string
		wantFallbacks      int
		wantFallbackVerify bool
	}{
		{
			name: "url disable",
			dsn: "postgres://user:pass@localhost/wallet?" +
				"sslmode=disable",
			wantSkipVerify: true,
			wantServerName: "localhost",
		},
		{
			name: "keyword value prefer",
			dsn: "host=localhost user=user password=pass " +
				"dbname=wallet sslmode=prefer",
			wantSkipVerify:     true,
			wantServerName:     "localhost",
			wantFallbacks:      1,
			wantFallbackVerify: true,
		},
		{
			name: "url verify full",
			dsn: "postgres://user:pass@localhost/wallet?" +
				"sslmode=verify-full",
			wantServerName: "localhost",
		},
		{
			name: "keyword value verify ca",
			dsn: "host=localhost user=user dbname=wallet " +
				"sslmode=verify-ca",
			wantSkipVerify: true,
			wantServerName: "localhost",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			config, err := (Config{
				DSN:        testCase.dsn,
				RequireSSL: true,
			}).connectionConfig()
			require.NoError(t, err)
			require.NotNil(t, config.TLSConfig)
			require.Equal(
				t, testCase.wantSkipVerify,
				config.TLSConfig.InsecureSkipVerify,
			)
			require.Equal(
				t, testCase.wantServerName,
				config.TLSConfig.ServerName,
			)
			require.Len(t, config.Fallbacks, testCase.wantFallbacks)

			for _, fallback := range config.Fallbacks {
				require.NotNil(t, fallback.TLSConfig)
				require.Equal(
					t, testCase.wantFallbackVerify,
					fallback.TLSConfig.InsecureSkipVerify,
				)
			}
		})
	}
}

// TestConnectionConfigAllowsExplicitNonSSL verifies that RequireSSL is
// opt-in.
func TestConnectionConfigAllowsExplicitNonSSL(t *testing.T) {
	t.Parallel()

	config, err := (Config{
		DSN: "host=localhost dbname=wallet sslmode=disable",
	}).connectionConfig()
	require.NoError(t, err)
	require.Nil(t, config.TLSConfig)
}
