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

const serverNameDirectives = `
SecRuleEngine On
SecRule SERVER_NAME "@streq example.test" "id:900002,phase:1,deny,status:403"
`

func TestServerNameFromHost(t *testing.T) {
	engine, err := bench.New(serverNameDirectives)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	withHost, err := engine.Run(smokeRequest("/anything"))
	if err != nil {
		t.Fatal(err)
	}
	if !withHost.Interrupted || withHost.Status != 403 {
		t.Fatalf("request with Host was not denied: %+v", withHost)
	}

	withoutHost := smokeRequest("/anything")
	withoutHost.RequestHeaders = nil
	allowed, err := engine.Run(withoutHost)
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Interrupted {
		t.Fatalf("request without Host was interrupted: %+v", allowed)
	}
}

const loggingDirectives = `
SecRuleEngine On
SecRule REQUEST_URI "@contains /deny" "id:900001,phase:1,deny,status:403,log"
SecRule REQUEST_METHOD "@streq GET" "id:900003,phase:5,pass,nolog"
`

func TestLoggingPhaseMatchesAreIncluded(t *testing.T) {
	engine, err := bench.New(loggingDirectives)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	allowed, err := engine.Run(smokeRequest("/allow"))
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Interrupted {
		t.Fatalf("benign request was interrupted: %+v", allowed)
	}
	if !containsRule(allowed.MatchedRuleIDs, 900003) {
		t.Fatalf("allowed matched rule ids = %v, want phase-5 rule 900003", allowed.MatchedRuleIDs)
	}

	denied, err := engine.Run(smokeRequest("/deny"))
	if err != nil {
		t.Fatal(err)
	}
	if !denied.Interrupted {
		t.Fatalf("denied request was not interrupted: %+v", denied)
	}
	for _, id := range []int{900001, 900003} {
		if !containsRule(denied.MatchedRuleIDs, id) {
			t.Fatalf("denied matched rule ids = %v, want %d", denied.MatchedRuleIDs, id)
		}
	}
}

func containsRule(ids []int, want int) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
