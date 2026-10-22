// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package bench

import (
	"context"
	"runtime/debug"
	"testing"
)

func TestResolutionReportsEngineIdentity(t *testing.T) {
	res, err := CheckResolution(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("profile=%s go=%s version=%s dir=%s revision=%s gowork=%s gotoolchain=%s",
		res.Profile, res.GoVersion, res.Engine.Version, res.EngineDir,
		res.EngineRevision, res.GOWORK, res.GOToolchain)

	switch res.Profile {
	case ProfileUpstream:
		if res.Engine.Replace != nil {
			t.Fatalf("upstream profile resolved through replace %+v", res.Engine.Replace)
		}
		if res.Engine.Version != ExpectedEngineVersion {
			t.Fatalf("engine version = %q, want %q", res.Engine.Version, ExpectedEngineVersion)
		}
	case ProfileLocal:
		if res.Engine.Replace == nil || res.Engine.Replace.Dir == "" {
			t.Fatalf("local profile has no directory replace: %+v", res.Engine)
		}
		if res.EngineRevision != PinnedEngineRevision {
			t.Fatalf("engine revision = %q, want %q", res.EngineRevision, PinnedEngineRevision)
		}
		if res.EngineDirty {
			t.Fatal("engine checkout has local modifications")
		}
	default:
		t.Fatalf("unknown profile %q", res.Profile)
	}
}

func TestClassifyModule(t *testing.T) {
	tests := []struct {
		name    string
		engine  Module
		want    Profile
		wantErr bool
	}{
		{
			name:   "upstream expected version",
			engine: Module{Path: EngineModulePath, Version: ExpectedEngineVersion},
			want:   ProfileUpstream,
		},
		{
			name:    "upstream other version",
			engine:  Module{Path: EngineModulePath, Version: "v3.7.0"},
			wantErr: true,
		},
		{
			name: "local directory replace",
			engine: Module{
				Path:    EngineModulePath,
				Version: ExpectedEngineVersion,
				Replace: &Module{Path: "../coraza", Dir: "/tmp/coraza"},
			},
			want: ProfileLocal,
		},
		{
			name: "local replace without directory",
			engine: Module{
				Path:    EngineModulePath,
				Version: ExpectedEngineVersion,
				Replace: &Module{Path: "../coraza"},
			},
			wantErr: true,
		},
		{
			name: "replace by module version",
			engine: Module{
				Path:    EngineModulePath,
				Version: ExpectedEngineVersion,
				Replace: &Module{Path: EngineModulePath, Version: "v3.7.0", Dir: "/tmp/cache"},
			},
			wantErr: true,
		},
		{
			name:    "different module",
			engine:  Module{Path: "example.com/other", Version: ExpectedEngineVersion},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyModule(tt.engine)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("classifyModule(%+v) = %q, want error", tt.engine, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("classifyModule(%+v) = %q, want %q", tt.engine, got, tt.want)
			}
		})
	}
}

// TestBuildInfoMatchesResolution checks what was linked into this test binary,
// not just what go.mod declares. An ambient workspace that selected another
// engine would fail here.
func TestBuildInfoMatchesResolution(t *testing.T) {
	res, err := CheckResolution(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("build info is unavailable")
	}
	var dep *debug.Module
	for _, candidate := range info.Deps {
		if candidate.Path == EngineModulePath {
			dep = candidate
			break
		}
	}
	if dep == nil {
		t.Fatalf("engine %s is missing from build info", EngineModulePath)
	}

	switch res.Profile {
	case ProfileUpstream:
		if dep.Replace != nil {
			t.Fatalf("engine was linked through replace %q", dep.Replace.Path)
		}
		if dep.Version != res.Engine.Version {
			t.Fatalf("linked engine version = %q, resolved version = %q", dep.Version, res.Engine.Version)
		}
	case ProfileLocal:
		if dep.Replace == nil {
			t.Fatalf("engine %s %s was linked, not the local replacement", dep.Path, dep.Version)
		}
		if dep.Replace.Path != res.Engine.Replace.Path {
			t.Fatalf("linked replace path = %q, resolved replace path = %q",
				dep.Replace.Path, res.Engine.Replace.Path)
		}
	default:
		t.Fatalf("unknown profile %q", res.Profile)
	}
}
