// Copyright (c) 2015 The btcsuite developers
// Copyright (c) 2015 The Decred developers
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrwallet/internal/rpchelp"
)

func serverMethods() map[string]struct{} {
	m := make(map[string]struct{})
	for method, handlerData := range rpcHandlers {
		if !handlerData.noHelp {
			m[method] = struct{}{}
		}
	}
	return m
}

// TestRPCMethodHelpGeneration ensures that help text can be generated for every
// method of the RPC server for every supported locale.
func TestRPCMethodHelpGeneration(t *testing.T) {
	needsGenerate := false

	defer func() {
		if needsGenerate && !t.Failed() {
			t.Error("Generated help texts are out of date: run 'go generate'")
			return
		}
		if t.Failed() {
			t.Log("Regenerate help texts with 'go generate' after fixing")
		}
	}()

	for i := range rpchelp.HelpDescs {
		svrMethods := serverMethods()
		locale := rpchelp.HelpDescs[i].Locale
		generatedDescs := localeHelpDescs[locale]()
		for _, m := range rpchelp.Methods {
			delete(svrMethods, m.Method)

			helpText, err := dcrjson.GenerateHelp(m.Method, rpchelp.HelpDescs[i].Descs, m.ResultTypes...)
			if err != nil {
				t.Errorf("Cannot generate '%s' help for method '%s': missing description for '%s'",
					locale, m.Method, err)
				continue
			}
			if !needsGenerate && helpText != generatedDescs[m.Method] {
				needsGenerate = true
			}
		}

		for m := range svrMethods {
			t.Errorf("Missing '%s' help for method '%s'", locale, m)
		}
	}
}

// TestRPCMethodUsageGeneration ensures that single line usage text can be
// generated for every supported request of the RPC server.
func TestRPCMethodUsageGeneration(t *testing.T) {
	needsGenerate := false

	defer func() {
		if needsGenerate && !t.Failed() {
			t.Error("Generated help usages are out of date: run 'go generate'")
			return
		}
		if t.Failed() {
			t.Log("Regenerate help usage with 'go generate' after fixing")
		}
	}()

	svrMethods := serverMethods()
	usageStrs := make([]string, 0, len(rpchelp.Methods))
	for _, m := range rpchelp.Methods {
		delete(svrMethods, m.Method)

		usage, err := dcrjson.MethodUsageText(m.Method)
		if err != nil {
			t.Errorf("Cannot generate single line usage for method '%s': %v",
				m.Method, err)
		}

		if !t.Failed() {
			usageStrs = append(usageStrs, usage)
		}
	}

	if !t.Failed() {
		usages := strings.Join(usageStrs, "\n")
		needsGenerate = usages != requestUsages
	}
}
