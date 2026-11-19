package pg

import _ "embed"

// WalletSchemaName is the fixed PostgreSQL namespace for wallet state.
const WalletSchemaName = "btcwallet"

// DatabaseIdentitySchema runs only when startup claims an absent fixed schema.
//
//go:embed bootstrap/database_identity.sql
var DatabaseIdentitySchema string
