// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package build

import (
	"bytes"
	"runtime/debug"
	"strings"
)

// semanticAlphabet
const semanticAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

// appVersion is defined as a variable so it can be overridden during the build
// process if needed. It MUST only contain characters from semanticAlphabet per
// the semantic versioning spec.
//
// Example:
// go build -ldflags "-X github.com/btcsuite/btcwallet/build.appVersion=v1.0.0" ./...
var appVersion string

// Version returns the application version as a properly formed string per the
// semantic versioning 2.0.0 spec (http://semver.org/).
//
// May panic if the version is poorly configured on build.
func Version() string {
	// If set the module version must overridden.
	if appVersion != "" {
		return normalizeVerString(appVersion)
	}

	info, ok := debug.ReadBuildInfo()
	if ok {
		return info.Main.Version
	}

	panic("Application version is not set")
}

// normalizeVerString returns the passed string stripped of all characters which
// are not valid according to the semantic versioning guidelines for pre-release
// version and build metadata strings.  In particular they MUST only contain
// characters in semanticAlphabet.
func normalizeVerString(str string) string {
	result := bytes.Buffer{}
	for _, r := range str {
		if strings.ContainsRune(semanticAlphabet, r) {
			_, err := result.WriteRune(r)
			// Writing to a bytes.Buffer panics on OOM, and all
			// errors are unexpected.
			if err != nil {
				panic(err)
			}
		}
	}
	return result.String()
}
