// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
)

const (
	// EngineModulePath is the Go module under comparison.
	EngineModulePath = "github.com/corazawaf/coraza/v3"
	// ExpectedEngineVersion is the upstream release the harness requires when
	// no replace directive is present.
	ExpectedEngineVersion = "v3.8.1"
	// PinnedEngineRevision is the local checkout revision the local profile
	// requires. Update it when the assessed checkout moves.
	PinnedEngineRevision = "d9cc9befc2721fd217ce1660a0e91aca1157221d"
)

// Profile names the module identity a benchmark run uses.
type Profile string

const (
	// ProfileUpstream resolves the published module at ExpectedEngineVersion.
	ProfileUpstream Profile = "upstream"
	// ProfileLocal resolves an explicit directory replace.
	ProfileLocal Profile = "local"
)

// Module is the subset of `go list -m -json` used by the resolution report.
type Module struct {
	Path    string  `json:"Path"`
	Version string  `json:"Version"`
	Dir     string  `json:"Dir"`
	GoMod   string  `json:"GoMod"`
	Replace *Module `json:"Replace"`
}

// Resolution records what the build actually selects. It is intentionally
// small so a coordinator can consume it as JSON.
type Resolution struct {
	Profile        Profile `json:"profile"`
	GoBinary       string  `json:"go_binary"`
	GoVersion      string  `json:"go_version"`
	GOWORK         string  `json:"gowork"`
	GOToolchain    string  `json:"gotoolchain"`
	Engine         Module  `json:"engine"`
	EngineDir      string  `json:"engine_dir"`
	EngineRevision string  `json:"engine_revision"`
	EngineDirty    bool    `json:"engine_dirty"`
}

// classifyModule derives the profile from structured `go list -m -json` output
// so neither path nor version text has to be parsed. The upstream profile is
// the expected version without a replace; the local profile is a replace
// through a directory, which carries no replacement version.
func classifyModule(engine Module) (Profile, error) {
	if engine.Path != EngineModulePath {
		return "", fmt.Errorf("resolved module %q, want %q", engine.Path, EngineModulePath)
	}
	if engine.Replace == nil {
		if engine.Version != ExpectedEngineVersion {
			return "", fmt.Errorf("engine version is %q, want %q", engine.Version, ExpectedEngineVersion)
		}
		return ProfileUpstream, nil
	}
	if engine.Replace.Version != "" {
		return "", fmt.Errorf(
			"engine is replaced by module version %q; the local profile needs a directory replace",
			engine.Replace.Version,
		)
	}
	if engine.Replace.Dir == "" {
		return "", fmt.Errorf("engine replace %q did not resolve to a directory", engine.Replace.Path)
	}
	return ProfileLocal, nil
}

// CheckResolution reports the profile and engine identity the build selects.
// Every go command runs with GOWORK=off so an ambient workspace cannot
// substitute another engine, and GOTOOLCHAIN=local so nothing is downloaded
// implicitly. The upstream profile stops after `go list`; the local profile
// additionally pins the checkout revision and requires it to be clean. The
// returned error is meant to stop a benchmark run.
func CheckResolution(ctx context.Context) (Resolution, error) {
	root, err := moduleRoot()
	if err != nil {
		return Resolution{}, err
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		return Resolution{}, fmt.Errorf("find go binary: %w", err)
	}

	out, err := runGo(ctx, root, "version")
	if err != nil {
		return Resolution{}, err
	}
	res := Resolution{
		GoBinary:    goBinary,
		GoVersion:   strings.TrimSpace(string(out)),
		GOWORK:      "off",
		GOToolchain: "local",
	}

	out, err = runGo(ctx, root, "list", "-m", "-json", EngineModulePath)
	if err != nil {
		return Resolution{}, err
	}
	if err := json.Unmarshal(out, &res.Engine); err != nil {
		return Resolution{}, fmt.Errorf("decode go list output: %w", err)
	}
	profile, err := classifyModule(res.Engine)
	if err != nil {
		return Resolution{}, err
	}
	res.Profile = profile
	res.EngineDir = res.Engine.Dir

	linked, err := linkedEngine()
	if err != nil {
		return Resolution{}, err
	}
	if err := verifyLinkedEngine(profile, res.Engine, linked); err != nil {
		return Resolution{}, err
	}

	if profile == ProfileUpstream {
		return res, nil
	}

	dir, err := filepath.EvalSymlinks(res.Engine.Replace.Dir)
	if err != nil {
		return Resolution{}, fmt.Errorf("resolve replacement directory %q: %w", res.Engine.Replace.Dir, err)
	}
	res.EngineDir = dir

	head, err := git(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return Resolution{}, err
	}
	res.EngineRevision = strings.TrimSpace(head)
	if res.EngineRevision != PinnedEngineRevision {
		return Resolution{}, fmt.Errorf(
			"engine revision mismatch: %s resolves to %s, pinned revision is %s",
			dir, res.EngineRevision, PinnedEngineRevision,
		)
	}

	status, err := git(ctx, dir, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return Resolution{}, err
	}
	res.EngineDirty = strings.TrimSpace(status) != ""
	if res.EngineDirty {
		return Resolution{}, fmt.Errorf(
			"engine checkout %s has local modifications; a benchmark must use the pinned revision: %s",
			dir, strings.TrimSpace(status),
		)
	}

	return res, nil
}

// linkedEngine returns the engine module recorded in this binary's build info.
func linkedEngine() (debug.Module, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return debug.Module{}, fmt.Errorf("build info is unavailable")
	}
	for _, dep := range info.Deps {
		if dep.Path == EngineModulePath {
			return *dep, nil
		}
	}
	return debug.Module{}, fmt.Errorf("%s is not linked into this binary", EngineModulePath)
}

// verifyLinkedEngine checks the engine actually linked into this binary matches
// the resolved profile, so a different GOFLAGS at run time cannot make the
// report describe an engine the binary did not use.
func verifyLinkedEngine(profile Profile, resolved Module, linked debug.Module) error {
	switch profile {
	case ProfileUpstream:
		if linked.Replace != nil {
			return fmt.Errorf(
				"linked engine uses replace %q, but the resolved profile is upstream",
				linked.Replace.Path,
			)
		}
		if linked.Version != resolved.Version {
			return fmt.Errorf("linked engine version is %q, resolved version is %q", linked.Version, resolved.Version)
		}
	case ProfileLocal:
		if resolved.Replace == nil {
			return fmt.Errorf("local profile has no resolved replace")
		}
		if linked.Replace == nil {
			return fmt.Errorf("linked engine %s %s is not the local replacement", linked.Path, linked.Version)
		}
		if linked.Replace.Path != resolved.Replace.Path {
			return fmt.Errorf(
				"linked replace path is %q, resolved replace path is %q",
				linked.Replace.Path, resolved.Replace.Path,
			)
		}
		if linked.Replace.Version != "" {
			return fmt.Errorf("linked replace uses module version %q, want a directory replace", linked.Replace.Version)
		}
	default:
		return fmt.Errorf("unknown profile %q", profile)
	}
	return nil
}

// moduleRoot returns the module directory from the runtime working directory.
// The caller must run from the module directory: runtime.Caller source paths are
// not filesystem paths under -trimpath.
func moduleRoot() (string, error) {
	root, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("run from the module directory, %s has no go.mod: %w", root, err)
	}
	return root, nil
}

func runGo(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	env := withEnv(os.Environ(), "GOWORK", "off")
	cmd.Env = withEnv(env, "GOTOOLCHAIN", "local")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git -C %s %s: %w: %s", dir, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// withEnv replaces key in env so no duplicate entry can override it on any
// platform.
func withEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			out = append(out, entry)
		}
	}
	return append(out, prefix+value)
}
