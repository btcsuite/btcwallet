// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacyrpc

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestThrottle(t *testing.T) {
	const threshold = 1
	busy := make(chan struct{})

	srv := httptest.NewServer(throttledFn(threshold,
		func(w http.ResponseWriter, r *http.Request) {
			<-busy
		}),
	)

	codes := make(chan int, 2)
	for i := 0; i < cap(codes); i++ {
		go func() {
			res, err := http.Get(srv.URL)
			if err != nil {
				t.Log(err)
				return
			}
			codes <- res.StatusCode
			_ = res.Body.Close()
		}()
	}

	got := make(map[int]int, cap(codes))
	for i := 0; i < cap(codes); i++ {
		got[<-codes]++

		if i == 0 {
			close(busy)
		}
	}

	want := map[int]int{200: 1, 429: 1}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("status codes: want: %v, got: %v", want, got)
	}
}
