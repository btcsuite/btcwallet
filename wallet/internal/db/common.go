package db

// NilIfEmptyBytes returns nil for nil or empty byte slices and returns
// non-empty byte slices unchanged.
//
// Call this at the SQL boundary on nullable byte columns where "absent"
// is encoded as SQL NULL. Go's []byte{} is non-nil but length-zero, and
// database/sql sends it as an empty bytea/BLOB (not NULL), which
// disagrees with two things:
//
//   - DB-side triggers and CHECK constraints that test `IS NULL` /
//     `IS NOT NULL` (e.g. the watch-only secret triggers), and
//   - Go-side "no value" checks that use `len(...) == 0` (e.g.
//     HasPrivateKey).
//
// Normalizing empty to nil here picks one canonical storage shape —
// empty means SQL NULL — so the two layers stay in agreement, and callers
// can pass either nil or []byte{} without changing behavior.
func NilIfEmptyBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}

	return b
}
