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
	"runtime"
	"strings"
)

const (
	// EngineModulePath is the Go module under comparison.
	EngineModulePath = "github.com/corazawaf/coraza/v3"
	// PinnedEngineRevision is the inspected Coraza checkout this harness builds
	// against. Update it together with the local replace and the README.
	PinnedEngineRevision = "d9cc9befc2721fd217ce1660a0e91aca1157221d"
	// DeclaredEngineReplace must match the replace directive in go.mod. Build
	// info records this literal path, so checking it also detects a workspace
	// replace that was active at compile time.
	DeclaredEngineReplace = "../../../../coraza"
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
// small so a future coordinator can consume it as JSON.
type Resolution struct {
	GoBinary       string `json:"go_binary"`
	GoVersion      string `json:"go_version"`
	GOWORK         string `json:"gowork"`
	GOToolchain    string `json:"gotoolchain"`
	Engine         Module `json:"engine"`
	EngineDir      string `json:"engine_dir"`
	EngineRevision string `json:"engine_revision"`
	EngineDirty    bool   `json:"engine_dirty"`
}

// CheckResolution verifies that the engine resolves to the declared local
// replacement and that the checkout is exactly the pinned revision. Every go
// command here runs with GOWORK=off so an ambient workspace cannot substitute
// another engine. The returned error is meant to stop a benchmark run.
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
	if res.Engine.Path != EngineModulePath {
		return Resolution{}, fmt.Errorf("resolved module %q, want %q", res.Engine.Path, EngineModulePath)
	}
	if res.Engine.Replace == nil || res.Engine.Replace.Dir == "" {
		return Resolution{}, fmt.Errorf(
			"engine %s is not resolved through a local directory replace; refusing to benchmark a downloaded module",
			EngineModulePath,
		)
	}
	if res.Engine.Replace.Path != DeclaredEngineReplace {
		return Resolution{}, fmt.Errorf(
			"engine replace path is %q, expected the declared %q",
			res.Engine.Replace.Path, DeclaredEngineReplace,
		)
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

func moduleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate module root: runtime.Caller failed")
	}
	return filepath.Dir(file), nil
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
