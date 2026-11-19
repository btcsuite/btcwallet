package db

import "errors"

// ErrAccountSecretUnavailable is returned when a backend does not expose
// store-side account secret material through AccountStore.
var ErrAccountSecretUnavailable = errors.New("account secret unavailable")
