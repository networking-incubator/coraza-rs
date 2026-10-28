package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

const largeBodySize = 1024*1024 + 1

type backend struct {
	mu     sync.Mutex
	counts map[string]int
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/__stats" {
		b.writeStats(w, r)
		return
	}
	b.mu.Lock()
	b.counts[r.URL.Path]++
	b.mu.Unlock()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read request", http.StatusBadRequest)
		return
	}
	switch {
	case r.URL.Path == "/echo":
		w.Header().Set("Content-Type", "application/octet-stream")
		if trailer := r.Trailer.Get("X-Client-Trailer"); trailer != "" {
			w.Header().Set("X-Client-Trailer-Seen", trailer)
		}
		writeBody(w, body)
	case r.URL.Path == "/response-deny":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream-Secret", "upstream-header-marker")
		w.Header().Set("Set-Cookie", "upstream-secret=secret-cookie")
		writeBody(w, []byte("secret upstream response body"))
	case r.URL.Path == "/response-trailers":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Add("Trailer", "X-Backend-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("trailer response"))
		w.Header().Set("X-Backend-Trailer", "passed")
	case r.URL.Path == "/empty":
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
	case r.URL.Path == "/large-uninspectable":
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Large-Probe", "preserved")
		writeBody(w, bytes.Repeat([]byte{'z'}, largeBodySize))
	case r.URL.Path == "/large-header-deny":
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Deny-Response", "yes")
		body := bytes.Repeat([]byte{'z'}, largeBodySize)
		copy(body[len(body)-len("LEAK-MARKER"):], "LEAK-MARKER")
		writeBody(w, body)
	case strings.HasPrefix(r.URL.Path, "/bytes/"):
		size, parseErr := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/bytes/"))
		if parseErr != nil || size < 0 || size > 1024 {
			http.Error(w, "invalid body size", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		writeBody(w, bytes.Repeat([]byte{'a'}, size))
	default:
		w.Header().Set("Content-Type", "text/plain")
		writeBody(w, []byte("backend received "+r.URL.Path+" "+string(body)))
	}
}

func (b *backend) writeStats(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if path := r.URL.Query().Get("path"); path != "" {
		_, _ = fmt.Fprint(w, b.counts[path])
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b.counts)
}

func writeBody(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

func main() {
	server := &http.Server{
		Addr:    ":3000",
		Handler: &backend{counts: make(map[string]int)},
	}
	log.Fatal(server.ListenAndServe())
}
