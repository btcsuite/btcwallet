//go:build !(darwin || linux)

package bwtest

// raiseNoFileLimit attempts to increase the current process file descriptor
// limit.
//
// On platforms where this isn't supported, this is a no-op.
func raiseNoFileLimit() error {
	return nil
}
