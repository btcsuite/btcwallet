//go:build itest && test_db_postgres

package itest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSanitizedPgDBNameShort verifies that short names remain unchanged.
func TestSanitizedPgDBNameShort(t *testing.T) {
	t.Parallel()

	shortName := "TestShort"
	expected := "testshort"

	result := sanitizePgDBNameString(shortName)
	require.Equal(t, expected, result)
}

// TestSanitizedPgDBNameSanitization verifies special characters are replaced.
func TestSanitizedPgDBNameSanitization(t *testing.T) {
	t.Parallel()

	nameWithSpecial := "Test/With-Special.Chars"
	expected := "test_with_special_chars"

	result := sanitizePgDBNameString(nameWithSpecial)
	require.Equal(t, expected, result)
}

// TestSanitizedPgDBNameMaxLength verifies names at the limit are unchanged.
func TestSanitizedPgDBNameMaxLength(t *testing.T) {
	t.Parallel()

	nameAtLimit := "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0"
	require.Equal(t, 63, len(nameAtLimit))

	result := sanitizePgDBNameString(nameAtLimit)
	require.Equal(t, nameAtLimit, result)
	require.Equal(t, 63, len(result))
}

// TestSanitizedPgDBNameTruncationWithHash verifies truncation adds hash
// suffix.
func TestSanitizedPgDBNameTruncationWithHash(t *testing.T) {
	t.Parallel()

	longName := "TestVeryLongNameThatExceedsPostgreSQLIdentifierLimitOfSixtyThreeBytes"
	require.Greater(t, len(longName), 63)

	result := sanitizePgDBNameString(longName)

	require.Equal(t, 63, len(result))
	require.True(t, strings.Contains(result, "_"))

	suffix := result[len(result)-9:]
	require.Equal(t, 9, len(suffix))
	require.Equal(t, byte('_'), suffix[0])

	for _, ch := range suffix[1:] {
		require.True(
			t, (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'),
			"suffix contains non-hex character: %q", string(ch),
		)
	}
}

// TestSanitizedPgDBNameCollisionAvoidance verifies different long names
// with identical prefixes produce different database names.
func TestSanitizedPgDBNameCollisionAvoidance(t *testing.T) {
	t.Parallel()

	prefix := "testverylongnamethatsharesfirstfiftyfourcharacterswithother"
	name1 := prefix + "suffix1"
	name2 := prefix + "suffix2"

	require.Greater(t, len(name1), 63)
	require.Greater(t, len(name2), 63)

	result1 := sanitizePgDBNameString(name1)
	result2 := sanitizePgDBNameString(name2)

	require.NotEqual(t, result1, result2)
	require.Equal(t, 63, len(result1))
	require.Equal(t, 63, len(result2))
}
