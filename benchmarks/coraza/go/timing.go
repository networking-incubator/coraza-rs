// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

package bench

// Timing support. The driver loads and compiles once, then times one fresh
// transaction per iteration through the same public lifecycle RunCase uses.

import (
	"fmt"
	"time"
)

// RunTimed drives one fresh transaction through the same lifecycle as RunCase
// and returns its elapsed wall-clock duration. The timed section starts before
// WAF.NewTransaction and ends after Transaction.Close, so it includes
// transaction initialization, connection, URI, headers, request body, response
// headers and body, logging and close. Workload loading, validation, policy
// compilation and outcome observation are outside it.
func RunTimed(prepared *PreparedCase) (time.Duration, error) {
	start := time.Now()
	tx := prepared.engine.waf.NewTransaction()
	driveErr := drive(tx, prepared.request)
	tx.ProcessLogging()
	closeErr := tx.Close()
	elapsed := time.Since(start)
	if driveErr != nil {
		return 0, fmt.Errorf("case %s: %w", prepared.ID, driveErr)
	}
	if closeErr != nil {
		return 0, fmt.Errorf("case %s: close transaction: %w", prepared.ID, closeErr)
	}
	return elapsed, nil
}
