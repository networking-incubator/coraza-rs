// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestWaitUntilReadyAcceptsMatchingReadinessToken(t *testing.T) {
	const token = "run-token"
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/coraza-ftw-health/"+token {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, token)
	}))
	port := server.port
	runner := &Server{port: port, readinessToken: token, done: make(chan struct{})}
	if err := runner.WaitUntilReady(time.Second); err != nil {
		t.Fatalf("WaitUntilReady() error = %v", err)
	}
}

func TestWaitUntilReadyRejectsUnrelatedListener(t *testing.T) {
	const token = "run-token"
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readiness" {
			fmt.Fprint(w, token)
			return
		}
		http.Redirect(w, r, "/readiness", http.StatusFound)
	}))
	port := server.port
	runner := &Server{port: port, readinessToken: token, done: make(chan struct{})}
	if err := runner.WaitUntilReady(50 * time.Millisecond); err == nil {
		t.Fatal("WaitUntilReady() accepted an unrelated listener")
	}
}

func TestWaitUntilReadyReportsExitedProcess(t *testing.T) {
	done := make(chan struct{})
	close(done)
	runner := &Server{done: done}
	if err := runner.WaitUntilReady(time.Second); err == nil || !strings.Contains(err.Error(), "process exited") {
		t.Fatalf("WaitUntilReady() error = %v, want process exit", err)
	}
}

func TestHealthCheckErrorsOnNon200(t *testing.T) {
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	err := testServerHealthAt(server.url, server.client)
	if err == nil || !strings.Contains(err.Error(), "GET /") || !strings.Contains(err.Error(), "503") {
		t.Fatalf("testServerHealthAt() error = %v, want GET / and status 503", err)
	}
}

func TestHealthCheckErrorsOnRedirect(t *testing.T) {
	server := newIPv4TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/redirect-target", http.StatusFound)
	}))

	err := testServerHealthAt(server.url, server.client)
	if err == nil || !strings.Contains(err.Error(), "GET /") || !strings.Contains(err.Error(), "302") {
		t.Fatalf("testServerHealthAt() error = %v, want GET / and status 302", err)
	}
}

func TestHealthCheckPassesOn200(t *testing.T) {
	server := newIPv4TestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err := testServerHealthAt(server.url, server.client); err != nil {
		t.Fatalf("testServerHealthAt() error = %v", err)
	}
}

type localTestServer struct {
	url    string
	port   int
	client *http.Client
}

func newIPv4TestServer(t *testing.T, handler http.Handler) *localTestServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on IPv4 loopback: %v", err)
	}
	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() { _ = server.Close() })
	port := listener.Addr().(*net.TCPAddr).Port
	return &localTestServer{
		url:    fmt.Sprintf("http://127.0.0.1:%d", port),
		port:   port,
		client: &http.Client{},
	}
}
