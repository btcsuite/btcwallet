// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chain

type semver struct {
	major, minor, patch uint32
}

func semverCompatible(required, actual semver) bool {
	switch {
	case required.major != required.major:
		return false
	case required.minor > actual.minor:
		return false
	case required.minor == actual.minor && required.patch > actual.patch:
		return false
	default:
		return true
	}
}
