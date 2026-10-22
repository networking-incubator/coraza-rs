// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

// Command checkresolve prints the resolved engine source as JSON and exits
// non-zero when the resolution is not the pinned local checkout.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	bench "github.com/corazawaf/coraza-rs/benchmarks/coraza/go"
)

func main() {
	res, err := bench.CheckResolution(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolution check failed: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "encode resolution: %v\n", err)
		os.Exit(1)
	}
}
