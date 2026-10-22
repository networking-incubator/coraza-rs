// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// validUpstreamResolution returns a valid upstream identity.
func validUpstreamResolution() goResolution {
	return goResolution{
		Profile:     "upstream",
		GoBinary:    "/usr/bin/go",
		GoVersion:   "go version test",
		GOWork:      "off",
		GOToolchain: "local",
		Engine:      goModule{Path: engineModulePath, Version: "v3.8.1"},
	}
}

// validLocalResolution returns a valid clean local identity.
func validLocalResolution() goResolution {
	return goResolution{
		Profile:        "local",
		GoBinary:       "/usr/bin/go",
		GoVersion:      "go version test",
		GOWork:         "off",
		GOToolchain:    "local",
		Engine:         goModule{Path: engineModulePath, Version: "v3.8.1", Replace: &goModule{Path: "/engines/coraza", Dir: "/engines/coraza"}},
		EngineDir:      "/engines/coraza",
		EngineRevision: strings.Repeat("a", 40),
	}
}

// TestValidateResolution covers profile expectations and clean-engine gates.
func TestValidateResolution(t *testing.T) {
	tests := []struct {
		name       string
		profile    string
		resolution goResolution
		mutate     func(*goResolution)
		wantError  bool
	}{
		{name: "upstream", profile: "auto", resolution: validUpstreamResolution()},
		{name: "local", profile: "auto", resolution: validLocalResolution()},
		{name: "expected local", profile: "local", resolution: validLocalResolution()},
		{
			name:       "profile mismatch",
			profile:    "local",
			resolution: validUpstreamResolution(),
			wantError:  true,
		},
		{
			name:       "unknown profile",
			profile:    "auto",
			resolution: validUpstreamResolution(),
			mutate:     func(value *goResolution) { value.Profile = "vendor" },
			wantError:  true,
		},
		{
			name:       "wrong module path",
			profile:    "auto",
			resolution: validUpstreamResolution(),
			mutate:     func(value *goResolution) { value.Engine.Path = "example.test/other" },
			wantError:  true,
		},
		{
			name:       "empty version",
			profile:    "auto",
			resolution: validUpstreamResolution(),
			mutate:     func(value *goResolution) { value.Engine.Version = "" },
			wantError:  true,
		},
		{
			name:       "dirty local engine",
			profile:    "auto",
			resolution: validLocalResolution(),
			mutate:     func(value *goResolution) { value.EngineDirty = true },
			wantError:  true,
		},
		{
			name:       "dirty upstream engine",
			profile:    "auto",
			resolution: validUpstreamResolution(),
			mutate:     func(value *goResolution) { value.EngineDirty = true },
			wantError:  true,
		},
		{
			name:       "local without replacement",
			profile:    "auto",
			resolution: validLocalResolution(),
			mutate:     func(value *goResolution) { value.Engine.Replace = nil },
			wantError:  true,
		},
		{
			name:       "local without resolved directory",
			profile:    "auto",
			resolution: validLocalResolution(),
			mutate:     func(value *goResolution) { value.EngineDir = "" },
			wantError:  true,
		},
		{
			name:       "local without revision",
			profile:    "auto",
			resolution: validLocalResolution(),
			mutate:     func(value *goResolution) { value.EngineRevision = "" },
			wantError:  true,
		},
		{
			name:       "upstream with replacement",
			profile:    "auto",
			resolution: validUpstreamResolution(),
			mutate: func(value *goResolution) {
				value.Engine.Replace = &goModule{Path: "/engines/coraza", Dir: "/engines/coraza"}
			},
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolution := test.resolution
			if test.mutate != nil {
				test.mutate(&resolution)
			}
			cfg := &config{goProfile: test.profile}
			err := validateResolution(cfg, resolution)
			if test.wantError {
				requireError(t, err)
			} else {
				requireNoError(t, err)
			}
		})
	}
}

// TestCheckResolutionRequiresCleanExit stops the run when checkresolve fails.
func TestCheckResolutionRequiresCleanExit(t *testing.T) {
	clearCoordinatorEnv(t)
	work := t.TempDir()
	runDir := t.TempDir()
	cfg := &config{
		goModule:        makeGoModule(t),
		checkresolveCmd: writeShellScript(t, work, "checkresolve.sh", "echo mismatch >&2\nexit 4\n"),
	}
	_, err := checkResolution(t.Context(), cfg, runDir)
	requireError(t, err)
	if !strings.Contains(err.Error(), "exit status 4") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestCheckResolutionRejectsMalformedJSON rejects non-JSON output.
func TestCheckResolutionRejectsMalformedJSON(t *testing.T) {
	clearCoordinatorEnv(t)
	work := t.TempDir()
	runDir := t.TempDir()
	badJSON := writeTestFile(t, work, "bad.json", "{")
	cfg := &config{
		goModule:        makeGoModule(t),
		checkresolveCmd: "cat " + shellQuote(badJSON),
	}
	_, err := checkResolution(t.Context(), cfg, runDir)
	requireError(t, err)
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestCheckResolutionRequiresGoModule refuses to run outside an isolated
// module with a manifest file.
func TestCheckResolutionRequiresGoModule(t *testing.T) {
	clearCoordinatorEnv(t)
	cfg := &config{
		goModule:        t.TempDir(),
		checkresolveCmd: "true",
	}
	_, err := checkResolution(t.Context(), cfg, t.TempDir())
	requireError(t, err)
}

// TestCollectRepositoryIdentity records a real revision and ignores untracked
// files. The test runs inside the repository that owns this module.
func TestCollectRepositoryIdentity(t *testing.T) {
	root := defaultRepoRoot()
	identity, err := collectRepositoryIdentity(root)
	requireNoError(t, err)
	if !isHexCommit(identity.Revision) {
		t.Fatalf("repository revision %q is not a 40-character hex commit", identity.Revision)
	}
	requireEqual(t, identity.Root, root)
}
