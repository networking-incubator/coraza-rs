// Copyright Coraza Kubernetes Operator contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command exporter serializes Go Coraza's registered engine test profiles into one
// JSON document for the Rust replay harness in coraza/tests/go_profiles_replay.rs.
//
// Upstream has no profile exporter: the profiles are Go literals registered from init
// functions, so this program links the engine package for its side effects and walks
// profile.Profiles directly.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"sort"

	_ "github.com/corazawaf/coraza/v3/testing/engine"
	"github.com/corazawaf/coraza/v3/testing/profile"
)

// sourceCommit is the commit of tag v3.8.1 in github.com/corazawaf/coraza, as recorded
// by the Go module cache's .info file and `git ls-remote`.
const sourceCommit = "9f8521398d1ff023b958fad0b944cac265763866"

type document struct {
	Source   source       `json:"source"`
	Profiles []profileOut `json:"profiles"`
}

type source struct {
	Module    string `json:"module"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTags string `json:"build_tags"`
	Exporter  string `json:"exporter"`
}

type profileOut struct {
	Name        string    `json:"name"`
	Author      string    `json:"author,omitempty"`
	Description string    `json:"description,omitempty"`
	Rules       string    `json:"rules"`
	Tests       []testOut `json:"tests"`
}

type testOut struct {
	Title       string  `json:"title,omitempty"`
	Description string  `json:"description,omitempty"`
	Stages      []stage `json:"stages"`
}

type stage struct {
	Input  input  `json:"input"`
	Output output `json:"output"`
}

type input struct {
	URI      string            `json:"uri,omitempty"`
	Method   string            `json:"method,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Data     string            `json:"data,omitempty"`
	DestAddr string            `json:"dest_addr,omitempty"`
}

type output struct {
	Headers           map[string]string `json:"headers,omitempty"`
	Data              string            `json:"data,omitempty"`
	TriggeredRules    []int             `json:"triggered_rules,omitempty"`
	NonTriggeredRules []int             `json:"non_triggered_rules,omitempty"`
	LogContains       string            `json:"log_contains,omitempty"`
	NoLogContains     string            `json:"no_log_contains,omitempty"`
	Interruption      *interruption     `json:"interruption,omitempty"`
}

type interruption struct {
	RuleID int    `json:"rule_id,omitempty"`
	Action string `json:"action,omitempty"`
	Status int    `json:"status,omitempty"`
	Data   string `json:"data,omitempty"`
}

func main() {
	out := flag.String("o", "profiles.json", "output file, - for stdout")
	flag.Parse()

	doc := document{
		Source: source{
			Module:    "github.com/corazawaf/coraza/v3",
			Version:   moduleVersion(),
			Commit:    sourceCommit,
			BuildTags: buildTags(),
			Exporter:  "coraza/tests/go_profiles/exporter",
		},
	}

	names := make([]string, 0, len(profile.Profiles))
	for name := range profile.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		doc.Profiles = append(doc.Profiles, exportProfile(profile.Profiles[name]))
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fail(err)
	}
	data = append(data, '\n')
	if *out == "-" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(*out, data, 0o644)
	}
	if err != nil {
		fail(err)
	}
}

func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/corazawaf/coraza/v3" {
			return dep.Version
		}
	}
	return "unknown"
}

// buildTags reports the build constraints the exporter was compiled with, which select
// the upstream profile files: the multiphase profiles live behind a build tag.
func buildTags() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, setting := range info.Settings {
		if setting.Key == "-tags" {
			return setting.Value
		}
	}
	return "default"
}

func exportProfile(p profile.Profile) profileOut {
	out := profileOut{
		Name:        p.Meta.Name,
		Author:      p.Meta.Author,
		Description: p.Meta.Description,
		Rules:       p.Rules,
	}
	for _, test := range p.Tests {
		t := testOut{Title: test.Title, Description: test.Description}
		for _, s := range test.Stages {
			in := s.Stage.Input
			exp := s.Stage.Output
			refuseUnsupported(in, exp)
			t.Stages = append(t.Stages, stage{
				Input: input{
					URI:      in.URI,
					Method:   in.Method,
					Headers:  in.Headers,
					Data:     bodyToString(in.Data),
					DestAddr: in.DestAddr,
				},
				Output: output{
					Headers:           exp.Headers,
					Data:              bodyToString(exp.Data),
					TriggeredRules:    exp.TriggeredRules,
					NonTriggeredRules: exp.NonTriggeredRules,
					LogContains:       exp.LogContains,
					NoLogContains:     exp.NoLogContains,
					Interruption:      exportInterruption(exp.Interruption),
				},
			})
		}
		out.Tests = append(out.Tests, t)
	}
	return out
}

func exportInterruption(i *profile.ExpectedInterruption) *interruption {
	if i == nil {
		return nil
	}
	return &interruption{RuleID: i.RuleID, Action: i.Action, Status: i.Status, Data: i.Data}
}

// refuseUnsupported aborts on a stage field the Rust replay harness does not implement.
// Exporting it would silently drop a Go expectation, so a new field must either gain
// replay support here or fail the export.
func refuseUnsupported(in profile.StageInput, exp profile.ExpectedOutput) {
	fields := []struct {
		name string
		set  bool
	}{
		{"input.version", in.Version != ""},
		{"input.port", in.Port != 0},
		{"input.stop_magic", in.StopMagic},
		{"input.raw_request", len(in.RawRequest) != 0},
		{"input.encoded_request", in.EncodedRequest != ""},
	}
	for _, field := range fields {
		if field.set {
			panic(fmt.Sprintf("unsupported stage field %s: add replay support before exporting", field.name))
		}
	}
}

// bodyToString mirrors the runner's own body conversion (testing/engine.go).
func bodyToString(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case []string:
		data := ""
		for _, line := range value {
			data += line + "\r\n"
		}
		return data + "\r\n"
	default:
		panic(fmt.Sprintf("bodyToString: unsupported %T", v))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
