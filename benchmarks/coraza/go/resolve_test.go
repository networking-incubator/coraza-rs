// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package bench

import (
	"context"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func TestResolutionReportsEngineIdentity(t *testing.T) {
	res, err := checkResolution(context.Background(), false)
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

func TestVerifyLinkedEngine(t *testing.T) {
	upstream := Module{Path: EngineModulePath, Version: ExpectedEngineVersion}
	local := Module{
		Path:    EngineModulePath,
		Version: ExpectedEngineVersion,
		Replace: &Module{Path: "../coraza", Dir: "/tmp/coraza"},
	}
	tests := []struct {
		name     string
		profile  Profile
		resolved Module
		linked   debug.Module
		wantErr  bool
	}{
		{
			name:     "upstream match",
			profile:  ProfileUpstream,
			resolved: upstream,
			linked:   debug.Module{Path: EngineModulePath, Version: ExpectedEngineVersion},
		},
		{
			name:     "upstream version mismatch",
			profile:  ProfileUpstream,
			resolved: upstream,
			linked:   debug.Module{Path: EngineModulePath, Version: "v3.7.0"},
			wantErr:  true,
		},
		{
			name:     "upstream linked replacement",
			profile:  ProfileUpstream,
			resolved: upstream,
			linked: debug.Module{
				Path:    EngineModulePath,
				Version: ExpectedEngineVersion,
				Replace: &debug.Module{Path: "../coraza"},
			},
			wantErr: true,
		},
		{
			name:     "local match",
			profile:  ProfileLocal,
			resolved: local,
			linked: debug.Module{
				Path:    EngineModulePath,
				Version: ExpectedEngineVersion,
				Replace: &debug.Module{Path: "../coraza"},
			},
		},
		{
			name:     "local linked without replacement",
			profile:  ProfileLocal,
			resolved: local,
			linked:   debug.Module{Path: EngineModulePath, Version: ExpectedEngineVersion},
			wantErr:  true,
		},
		{
			name:     "local replacement mismatch",
			profile:  ProfileLocal,
			resolved: local,
			linked: debug.Module{
				Path:    EngineModulePath,
				Version: ExpectedEngineVersion,
				Replace: &debug.Module{Path: "../other"},
			},
			wantErr: true,
		},
		{
			name:     "local version mismatch",
			profile:  ProfileLocal,
			resolved: local,
			linked: debug.Module{
				Path:    EngineModulePath,
				Version: "v3.7.0",
				Replace: &debug.Module{Path: "../coraza"},
			},
			wantErr: true,
		},
		{
			name:     "local replacement by version",
			profile:  ProfileLocal,
			resolved: local,
			linked: debug.Module{
				Path:    EngineModulePath,
				Version: ExpectedEngineVersion,
				Replace: &debug.Module{Path: EngineModulePath, Version: "v3.7.0"},
			},
			wantErr: true,
		},
		{
			name:     "unknown profile",
			profile:  Profile("other"),
			resolved: upstream,
			linked:   debug.Module{Path: EngineModulePath, Version: ExpectedEngineVersion},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyLinkedEngine(tt.profile, tt.resolved, tt.linked)
			if tt.wantErr && err == nil {
				t.Fatal("verifyLinkedEngine() = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifyBuildStamp(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const revision = "d9cc9befc2721fd217ce1660a0e91aca1157221d"

	tests := []struct {
		name    string
		stamp   buildStamp
		wantErr bool
	}{
		{
			name:  "matching stamp",
			stamp: buildStamp{Dir: dir, Revision: revision, Clean: "1"},
		},
		{
			name:    "missing dir",
			stamp:   buildStamp{Revision: revision, Clean: "1"},
			wantErr: true,
		},
		{
			name:    "missing revision",
			stamp:   buildStamp{Dir: dir, Clean: "1"},
			wantErr: true,
		},
		{
			name:    "missing clean stamp",
			stamp:   buildStamp{Dir: dir, Revision: revision},
			wantErr: true,
		},
		{
			name:    "dirty clean stamp",
			stamp:   buildStamp{Dir: dir, Revision: revision, Clean: "0"},
			wantErr: true,
		},
		{
			name:    "different dir",
			stamp:   buildStamp{Dir: other, Revision: revision, Clean: "1"},
			wantErr: true,
		},
		{
			name:    "different revision",
			stamp:   buildStamp{Dir: dir, Revision: "abc", Clean: "1"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyBuildStamp(tt.stamp, dir, revision)
			if tt.wantErr && err == nil {
				t.Fatal("verifyBuildStamp() = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestModuleRootContainsGoMod(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %q has no go.mod: %v", root, err)
	}
}

// TestBuildInfoMatchesResolution checks what was linked into this test binary,
// not just what go.mod declares. An ambient workspace that selected another
// engine would fail here. Go 1.26 test binaries omit dependency build info, so
// on that toolchain the test skips and cmd/checkresolve, a command binary,
// covers the linked-engine check.
func TestBuildInfoMatchesResolution(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("build info is unavailable")
	}
	if len(info.Deps) == 0 {
		t.Skip("Go 1.26 test binaries omit dependency build info; cmd/checkresolve covers the linked-engine check for this toolchain")
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

	res, err := checkResolution(context.Background(), false)
	if err != nil {
		t.Fatal(err)
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
