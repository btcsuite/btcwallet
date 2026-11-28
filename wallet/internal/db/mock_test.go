package db

import (
	"errors"
	"fmt"
)

var errMockType = errors.New("mock arg type")

// mockTypeError wraps the shared mock type sentinel with call-site context.
func mockTypeError(detail string) error {
	return fmt.Errorf("%w: %s", errMockType, detail)
}
