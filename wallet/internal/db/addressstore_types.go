package db

import (
	"errors"
	"fmt"
)

// errInvalidAddressType is returned when an address type ID from the database
// does not fit in AddressType (uint8). In practice, this should never happen,
// but it's possible if the database is modified incorrectly or the query is
// incorrect.
var errInvalidAddressType = errors.New("invalid address type")

// IDToAddressType safely converts an integer to AddressType. It returns an
// error if the value does not correspond to a known AddressType value.
func IDToAddressType[T ~int16 | ~int64](v T) (AddressType, error) {
	if v < 0 || v > T(Anchor) {
		return 0, fmt.Errorf("%w: %d", errInvalidAddressType, v)
	}

	return AddressType(v), nil
}
