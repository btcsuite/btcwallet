// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacyrpc

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestThrottle(t *testing.T) {
	const threshold = 1

	srv := httptest.NewServer(throttledFn(threshold,
		func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(20 * time.Millisecond)
		}),
	)

	codes := make(chan int, 2)
	for i := 0; i < cap(codes); i++ {
		go func() {
			res, err := http.Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			codes <- res.StatusCode
		}()
	}

	got := make(map[int]int, cap(codes))
	for i := 0; i < cap(codes); i++ {
		got[<-codes]++
	}

	want := map[int]int{200: 1, 429: 1}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("status codes: want: %v, got: %v", want, got)
	}
}
