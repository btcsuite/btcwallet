// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package build

import "testing"

// TestNormalizeVerString ensures semantic version separators are preserved
// while characters outside the alphabet are still stripped.
func TestNormalizeVerString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "dotted pre-release identifier",
			in:   "beta.rc1",
			want: "beta.rc1",
		},
		{
			// appBuild may be set to a dotted value via -ldflags at
			// build time.
			name: "dotted build metadata",
			in:   "exp.sha.5114f85",
			want: "exp.sha.5114f85",
		},
		{
			// Guards against the filter being dropped entirely: an
			// identity function satisfies the cases above.
			name: "character outside the alphabet",
			in:   "beta!rc1",
			want: "betarc1",
		},
	}

	for _, test := range tests {
		if got := normalizeVerString(test.in); got != test.want {
			t.Fatalf("%s: normalizeVerString(%q) = %q, want %q",
				test.name, test.in, got, test.want)
		}
	}
}
