package db

// NilIfEmptyBytes returns nil for nil or empty byte slices and returns
// non-empty byte slices unchanged.
func NilIfEmptyBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}

	return b
}
