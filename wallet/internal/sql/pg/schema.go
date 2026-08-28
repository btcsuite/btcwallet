package pg

import _ "embed"

// DatabaseIdentitySchema runs only when startup claims an absent fixed schema.
//
//go:embed bootstrap/database_identity.sql
var DatabaseIdentitySchema string
