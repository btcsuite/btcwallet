# `db/err`

This package provides the shared SQL error taxonomy and normalization layer
used by the wallet database backends.

It defines the common backend, class, and reason enums, the `SQLError`
wrapper used to preserve classification data in error chains, normalization
helpers for mapping backend failures into the shared model, and stats types for
recording classified SQL errors.

Backend-specific mapping remains in the backend packages, including [`pg`](../pg/errors.go)
and [`sqlite`](../sqlite/errors.go).

Higher-level runtime behavior such as retry handling, unhealthy-store
transitions, and transaction execution policy is implemented by callers outside
this package.
