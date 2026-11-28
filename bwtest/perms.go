package bwtest

// logDirPerm is the default permission for harness-managed log directories.
//
// 0o750 keeps logs accessible to the current user/group while avoiding
// world-readable test artifacts that may contain sensitive runtime details.
const logDirPerm = 0o750
