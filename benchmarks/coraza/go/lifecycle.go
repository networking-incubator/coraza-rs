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
// would stop processing that request.
func (e *Engine) Run(req Request) (Result, error) {
	tx := e.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	tx.ProcessConnection(req.ClientIP, req.ClientPort, req.ServerIP, req.ServerPort)
	tx.ProcessURI(req.URI, req.Method, req.HTTPVersion)
	for _, h := range req.RequestHeaders {
		tx.AddRequestHeader(h[0], h[1])
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return result(tx), nil
	}

	if tx.IsRequestBodyAccessible() && len(req.RequestBody) > 0 {
		it, _, err := tx.ReadRequestBodyFrom(bytes.NewReader(req.RequestBody))
		if err != nil {
			return Result{}, fmt.Errorf("read request body: %w", err)
		}
		if it != nil {
			return result(tx), nil
		}
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		return Result{}, fmt.Errorf("process request body: %w", err)
	} else if it != nil {
		return result(tx), nil
	}

	for _, h := range req.ResponseHeaders {
		tx.AddResponseHeader(h[0], h[1])
	}
	if it := tx.ProcessResponseHeaders(req.ResponseCode, req.ResponseProtocol); it != nil {
		return result(tx), nil
	}

	if tx.IsResponseBodyProcessable() && len(req.ResponseBody) > 0 {
		it, _, err := tx.ReadResponseBodyFrom(bytes.NewReader(req.ResponseBody))
		if err != nil {
			return Result{}, fmt.Errorf("read response body: %w", err)
		}
		if it != nil {
			return result(tx), nil
		}
	}
	if it, err := tx.ProcessResponseBody(); err != nil {
		return Result{}, fmt.Errorf("process response body: %w", err)
	} else if it != nil {
		return result(tx), nil
	}

	return result(tx), nil
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
