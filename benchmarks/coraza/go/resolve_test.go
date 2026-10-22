// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package bench_test

import (
	"context"
	"runtime/debug"
	"testing"

	bench "github.com/corazawaf/coraza-rs/benchmarks/coraza/go"
)

func TestResolutionIsPinnedLocalCheckout(t *testing.T) {
	res, err := bench.CheckResolution(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("go=%s engine=%s revision=%s gowork=%s",
		res.GoVersion, res.EngineDir, res.EngineRevision, res.GOWORK)
}

// TestBuildInfoUsesLocalReplacement checks what was linked into this test
// binary, not just what go.mod declares. An ambient go.work that selected a
// downloaded engine would fail here.
func TestBuildInfoUsesLocalReplacement(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("build info is unavailable")
	}
	for _, dep := range info.Deps {
		if dep.Path != bench.EngineModulePath {
			continue
		}
		if dep.Replace == nil {
			t.Fatalf("engine %s was linked from %s %s, not from the local replacement",
				dep.Path, dep.Path, dep.Version)
		}
		if dep.Replace.Path != bench.DeclaredEngineReplace {
			t.Fatalf("engine was linked through replace %q, declared replace is %q",
				dep.Replace.Path, bench.DeclaredEngineReplace)
		}
		return
	}
	t.Fatalf("engine %s is missing from build info", bench.EngineModulePath)
}
