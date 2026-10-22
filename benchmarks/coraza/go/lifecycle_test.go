// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package bench_test

import (
	"testing"

	bench "github.com/corazawaf/coraza-rs/benchmarks/coraza/go"
)

const smokeDirectives = `
SecRuleEngine On
SecRule REQUEST_URI "@contains /smoke-deny" "id:900001,phase:1,deny,status:403,log"
`

func smokeRequest(uri string) bench.Request {
	return bench.Request{
		ClientIP:         "127.0.0.1",
		ClientPort:       12345,
		ServerIP:         "127.0.0.1",
		ServerPort:       8080,
		Method:           "GET",
		URI:              uri,
		HTTPVersion:      "HTTP/1.1",
		RequestHeaders:   [][2]string{{"Host", "example.test"}},
		ResponseCode:     200,
		ResponseProtocol: "HTTP/1.1",
		ResponseHeaders:  [][2]string{{"Content-Type", "text/html"}},
	}
}

func TestLifecycleSmoke(t *testing.T) {
	engine, err := bench.New(smokeDirectives)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if got := engine.RulesCount(); got != 1 {
		t.Fatalf("rules compiled = %d, want 1", got)
	}

	allowed, err := engine.Run(smokeRequest("/smoke-allow"))
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Interrupted {
		t.Fatalf("benign request was interrupted: %+v", allowed)
	}

	denied, err := engine.Run(smokeRequest("/smoke-deny"))
	if err != nil {
		t.Fatal(err)
	}
	if !denied.Interrupted || denied.Status != 403 || denied.Action != "deny" {
		t.Fatalf("denied request result = %+v, want interruption 403 deny", denied)
	}
	if len(denied.MatchedRuleIDs) != 1 || denied.MatchedRuleIDs[0] != 900001 {
		t.Fatalf("matched rule ids = %v, want [900001]", denied.MatchedRuleIDs)
	}

	// Reusing the compiled policy proves compilation is outside the unit of work.
	again, err := engine.Run(smokeRequest("/smoke-allow"))
	if err != nil {
		t.Fatal(err)
	}
	if again.Interrupted {
		t.Fatalf("second benign request was interrupted: %+v", again)
	}
}
