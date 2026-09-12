package sqlite

import _ "embed"

var (
	// DatabaseIdentitySchema lets startup claim an empty file atomically.
	//go:embed bootstrap/database_identity.sql
	DatabaseIdentitySchema string
	// DatabaseIdentityCatalog reports whether startup may adopt the file.
	//go:embed assets/database_identity_catalog.sql
	DatabaseIdentityCatalog string
	// DatabaseIdentityJournal enables WAL after identity and reports its mode.
	//go:embed assets/database_identity_journal.sql
	DatabaseIdentityJournal string
)
