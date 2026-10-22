// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package bench

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// stringPointer returns a pointer to value.
func stringPointer(value string) *string {
	return &value
}

// base64Text encodes a UTF-8 string the same way the drivers do.
func base64Text(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

// syntheticOutcome returns a complete synthetic case outcome.
func syntheticOutcome(caseID string) Outcome {
	return Outcome{
		CaseID: caseID,
		Interruption: &OutcomeInterruption{
			RuleID: 1001,
			Action: "deny",
			Status: 403,
			Data:   "",
		},
		Matches: []OutcomeMatch{{
			RuleID:   1001,
			Variable: "ARGS_GET",
			Key:      stringPointer("q"),
			Value:    base64Text("attack"),
		}},
		Captures: []OutcomeCapture{{Index: 0, Value: base64Text("attack")}},
		Scores:   map[string]int64{"inbound_anomaly_score": 5},
		Flags:    map[string]string{"REQBODY_ERROR": "0"},
		Collections: []OutcomeCollection{{
			Variable: "REQBODY_PROCESSOR",
			Key:      nil,
			Value:    stringPointer(base64Text("URLENCODED")),
		}},
	}
}

// TestCompareOutcomesAcceptsIdenticalDocuments proves equal documents pass.
func TestCompareOutcomesAcceptsIdenticalDocuments(t *testing.T) {
	rust := []Outcome{syntheticOutcome("case-a"), syntheticOutcome("case-b")}
	goOutcomes := []Outcome{syntheticOutcome("case-a"), syntheticOutcome("case-b")}
	if divergences := CompareOutcomes(rust, goOutcomes); len(divergences) != 0 {
		t.Fatalf("divergences = %v, want none", divergences)
	}
}

// TestCompareOutcomesReportsFieldDivergence proves the comparator fails on
// synthetic documents that differ in one field.
func TestCompareOutcomesReportsFieldDivergence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Outcome)
		field  string
	}{
		{
			name: "match value",
			mutate: func(outcome *Outcome) {
				outcome.Matches[0].Value = base64Text("safe")
			},
			field: "matches[0].value",
		},
		{
			name: "match key",
			mutate: func(outcome *Outcome) {
				outcome.Matches[0].Key = nil
			},
			field: "matches[0].key",
		},
		{
			name: "interruption action",
			mutate: func(outcome *Outcome) {
				outcome.Interruption.Action = "block"
			},
			field: "interruption.action",
		},
		{
			name: "capture value",
			mutate: func(outcome *Outcome) {
				outcome.Captures[0].Value = base64Text("safe")
			},
			field: "captures[0].value",
		},
		{
			name: "score",
			mutate: func(outcome *Outcome) {
				outcome.Scores["inbound_anomaly_score"] = 0
			},
			field: "scores.inbound_anomaly_score",
		},
		{
			name: "flag",
			mutate: func(outcome *Outcome) {
				outcome.Flags["REQBODY_ERROR"] = "1"
			},
			field: "flags.REQBODY_ERROR",
		},
		{
			name: "collection value",
			mutate: func(outcome *Outcome) {
				outcome.Collections[0].Value = stringPointer(base64Text("JSON"))
			},
			field: "collections[0].value",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rust := syntheticOutcome("case-a")
			goOutcome := syntheticOutcome("case-a")
			test.mutate(&goOutcome)
			divergences := CompareOutcomes([]Outcome{rust}, []Outcome{goOutcome})
			if len(divergences) != 1 {
				t.Fatalf("divergences = %v, want exactly one", divergences)
			}
			if !strings.Contains(divergences[0], "case case-a: "+test.field) {
				t.Fatalf("divergence %q does not name case and field %s", divergences[0], test.field)
			}
		})
	}
}

// TestCompareOutcomesReportsMissingAndExtraCases proves the comparator fails
// closed on a case set mismatch.
func TestCompareOutcomesReportsMissingAndExtraCases(t *testing.T) {
	divergences := CompareOutcomes(
		[]Outcome{syntheticOutcome("only-rust")},
		[]Outcome{syntheticOutcome("only-go")},
	)
	if len(divergences) != 2 {
		t.Fatalf("divergences = %v, want two", divergences)
	}
	if !strings.Contains(divergences[0], "case only-rust: missing from the Go document") {
		t.Fatalf("first divergence = %q", divergences[0])
	}
	if !strings.Contains(divergences[1], "case only-go: missing from the Rust document") {
		t.Fatalf("second divergence = %q", divergences[1])
	}
}

// TestOutcomeDocumentRoundTrip parses the documents the Go driver emits.
func TestOutcomeDocumentRoundTrip(t *testing.T) {
	cases, err := LoadWorkload(shippedWorkloadRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer closePrepared(t, cases)
	outcomes := make([]Outcome, 0, len(cases))
	for _, prepared := range cases {
		outcome, err := RunCase(prepared)
		if err != nil {
			t.Fatalf("case %s: %v", prepared.ID, err)
		}
		outcomes = append(outcomes, outcome)
	}
	var document bytes.Buffer
	if err := WriteOutcomes(&document, outcomes); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseOutcomes(&document)
	if err != nil {
		t.Fatal(err)
	}
	if divergences := CompareOutcomes(outcomes, parsed); len(divergences) != 0 {
		t.Fatalf("round trip divergences = %v", divergences)
	}
}

// TestParseOutcomesRejectsInvalidInput proves incomplete or malformed documents
// fail closed.
func TestParseOutcomesRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     string
	}{
		{name: "invalid JSON", document: "{not json}\n", want: "not valid NDJSON"},
		{name: "incomplete case", document: `{"case_id":"case-a"}` + "\n", want: "missing"},
		{name: "empty document", document: "", want: "empty"},
		{
			name:     "duplicate case",
			document: `{"case_id":"a","interruption":null,"matches":[],"captures":[],"scores":{},"flags":{},"collections":[]}` + "\n" + `{"case_id":"a","interruption":null,"matches":[],"captures":[],"scores":{},"flags":{},"collections":[]}` + "\n",
			want:     "repeats case",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseOutcomes(strings.NewReader(test.document))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
