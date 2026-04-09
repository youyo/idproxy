package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHealthzHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	healthzHandler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/plain")
	}
	body := w.Body.String()
	if body != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
}

func TestNewReverseProxy(t *testing.T) {
	proxy, err := newReverseProxy("http://localhost:3000")
	if err != nil {
		t.Fatalf("newReverseProxy() error: %v", err)
	}
	if proxy == nil {
		t.Fatal("proxy is nil")
	}
	if proxy.FlushInterval != -1 {
		t.Errorf("FlushInterval = %v, want -1", proxy.FlushInterval)
	}
}

func TestNewReverseProxy_InvalidURL(t *testing.T) {
	_, err := newReverseProxy("://invalid")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestSSEPassthrough(t *testing.T) {
	// Mock upstream server sending SSE events
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		// Send 3 SSE events
		for i := 0; i < 3; i++ {
			_, _ = fmt.Fprintf(w, "data: event-%d\n\n", i)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	// Create reverse proxy with FlushInterval:-1
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1

	// Create proxy server
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	// Send SSE request
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(proxyServer.URL + "/events")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/event-stream")
	}

	// Read SSE events
	scanner := bufio.NewScanner(resp.Body)
	var events []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			events = append(events, line)
		}
	}

	if len(events) != 3 {
		t.Fatalf("received %d events, want 3", len(events))
	}
	for i, ev := range events {
		expected := fmt.Sprintf("data: event-%d", i)
		if ev != expected {
			t.Errorf("events[%d] = %q, want %q", i, ev, expected)
		}
	}
}

func TestSSEPassthrough_StreamingTiming(t *testing.T) {
	// Test that SSE events are flushed immediately
	eventCh := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		// Send first event
		_, _ = fmt.Fprintf(w, "data: first\n\n")
		flusher.Flush()

		// Wait for client to receive first event
		<-eventCh

		// Send second event
		_, _ = fmt.Fprintf(w, "data: second\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	target, _ := url.Parse(upstream.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(proxyServer.URL + "/stream")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	scanner := bufio.NewScanner(resp.Body)

	// Verify first event arrives immediately
	start := time.Now()
	var firstEvent string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			firstEvent = line
			break
		}
	}
	elapsed := time.Since(start)

	if firstEvent != "data: first" {
		t.Errorf("first event = %q, want %q", firstEvent, "data: first")
	}
	// FlushInterval:-1 should flush immediately (< 500ms)
	if elapsed > 500*time.Millisecond {
		t.Errorf("first event took %v, expected < 500ms (FlushInterval should be -1)", elapsed)
	}

	// Allow upstream to continue
	close(eventCh)

	// Verify second event arrives
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			if line != "data: second" {
				t.Errorf("second event = %q, want %q", line, "data: second")
			}
			return
		}
	}
	t.Fatal("second event not received")
}

func TestPrintUsage(t *testing.T) {
	var buf bytes.Buffer
	flag.CommandLine.SetOutput(&buf)
	defer flag.CommandLine.SetOutput(os.Stderr)
	printUsage()
	output := buf.String()
	for _, want := range []string{"UPSTREAM_URL", "EXTERNAL_URL", "COOKIE_SECRET", "OIDC_ISSUER", "OIDC_CLIENT_ID", "Environment Variables"} {
		if !strings.Contains(output, want) {
			t.Errorf("expected %q in usage output", want)
		}
	}
}
