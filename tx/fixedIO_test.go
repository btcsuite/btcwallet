// copied from btcwire

// Copyright (c) 2013-2014 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tx_test

import (
	"io"
)

// fixedWriter implements the io.Writer interface and intentially allows
// testing of error paths by forcing short writes.
type fixedWriter struct {
	b   []byte
	pos int
}

// Write ...
func (w *fixedWriter) Write(p []byte) (n int, err error) {
	lenp := len(p)
	if w.pos+lenp > cap(w.b) {
		return 0, io.ErrShortWrite
	}
	n = lenp
	w.pos += copy(w.b[w.pos:], p)
	return
}

// Bytes ...
func (w *fixedWriter) Bytes() []byte {
	return w.b
}

// newFixedWriter...
func newFixedWriter(max int64) *fixedWriter {
	b := make([]byte, max, max)
	fw := fixedWriter{b, 0}
	return &fw
}
