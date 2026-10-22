// Copyright 2026 Coraza Rust Contributors
// SPDX-License-Identifier: Apache-2.0

// Package bench provides the Go side of the local Go-versus-Rust Coraza
// harness. It owns the lifecycle only: one policy is compiled when Engine is
// created, and each Run creates, drives and releases exactly one transaction.
// Timing and result collection are intentionally out of scope here.
package bench

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

// Request is one unit of work. Bodies are read, not retained, by Run.
type Request struct {
	ClientIP         string
	ClientPort       int
	ServerIP         string
	ServerPort       int
	Method           string
	URI              string
	HTTPVersion      string
	RequestHeaders   [][2]string
	RequestBody      []byte
	ResponseCode     int
	ResponseProtocol string
	ResponseHeaders  [][2]string
	ResponseBody     []byte
}

// Result is the observable outcome needed by validation. It is not a timing
// structure and is deliberately independent of Coraza's types.
type Result struct {
	Interrupted    bool
	Status         int
	Action         string
	MatchedRuleIDs []int
}

// Engine owns one compiled policy. It is safe for concurrent Run calls because
// each Run uses a fresh transaction.
type Engine struct {
	waf    coraza.WAF
	closer io.Closer
	rules  int
}

// New compiles directives once. Compilation is never part of a timed unit.
func New(directives string) (*Engine, error) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	e := &Engine{waf: waf}
	if closer, ok := waf.(experimental.WAFCloser); ok {
		e.closer = closer
	}
	if counter, ok := waf.(experimental.WAFWithRules); ok {
		e.rules = counter.RulesCount()
	}
	return e, nil
}

// RulesCount reports the number of rules compiled into the policy.
func (e *Engine) RulesCount() int {
	return e.rules
}

// Run drives one transaction through phases 1 to 5 and releases it. The
// sequence mirrors Coraza's HTTP middleware so validation and measurement use
// the same path. An interruption ends the transaction immediately, as a server
// would stop processing that request. Logging always runs, and the result is
// built after it so phase-5 matches are visible.
func (e *Engine) Run(req Request) (Result, error) {
	tx := e.waf.NewTransaction()
	defer func() {
		_ = tx.Close()
	}()

	err := drive(tx, req)
	tx.ProcessLogging()
	res := result(tx)
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

// drive runs the phases in Coraza HTTP middleware order. An interruption stops
// further processing but is not an error; logging still runs in Run.
func drive(tx types.Transaction, req Request) error {
	tx.ProcessConnection(req.ClientIP, req.ClientPort, req.ServerIP, req.ServerPort)
	tx.ProcessURI(req.URI, req.Method, req.HTTPVersion)

	host := ""
	for _, h := range req.RequestHeaders {
		if host == "" && strings.EqualFold(h[0], "Host") {
			host = h[1]
		}
		tx.AddRequestHeader(h[0], h[1])
	}
	// The HTTP middleware promotes Host to the request field and uses it for
	// SERVER_NAME. Structured input keeps it among the headers, and the value
	// must be set before ProcessRequestHeaders.
	if host != "" {
		tx.SetServerName(host)
	}

	if tx.ProcessRequestHeaders() != nil {
		return nil
	}

	if tx.IsRequestBodyAccessible() && len(req.RequestBody) > 0 {
		it, _, err := tx.ReadRequestBodyFrom(bytes.NewReader(req.RequestBody))
		if err != nil {
			return fmt.Errorf("read request body: %w", err)
		}
		if it != nil {
			return nil
		}
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		return fmt.Errorf("process request body: %w", err)
	} else if it != nil {
		return nil
	}

	for _, h := range req.ResponseHeaders {
		tx.AddResponseHeader(h[0], h[1])
	}
	if tx.ProcessResponseHeaders(req.ResponseCode, req.ResponseProtocol) != nil {
		return nil
	}

	if tx.IsResponseBodyProcessable() && len(req.ResponseBody) > 0 {
		it, _, err := tx.ReadResponseBodyFrom(bytes.NewReader(req.ResponseBody))
		if err != nil {
			return fmt.Errorf("read response body: %w", err)
		}
		if it != nil {
			return nil
		}
	}
	if it, err := tx.ProcessResponseBody(); err != nil {
		return fmt.Errorf("process response body: %w", err)
	} else if it != nil {
		return nil
	}

	return nil
}

// Close releases resources cached by the WAF, including compiled patterns.
func (e *Engine) Close() error {
	if e.closer != nil {
		return e.closer.Close()
	}
	return nil
}

func result(tx types.Transaction) Result {
	r := Result{}
	if it := tx.Interruption(); it != nil {
		r.Interrupted = true
		r.Status = it.Status
		r.Action = it.Action
	}
	for _, m := range tx.MatchedRules() {
		r.MatchedRuleIDs = append(r.MatchedRuleIDs, m.Rule().ID())
	}
	return r
}
