package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestHTTPKubeProbeHealthz(t *testing.T) {
	var sbuf safeBuffer
	l := logger.New(&sbuf)

	srv := NewServer(Config{
		Port:        0,
		PublicPort:  80,
		ServiceName: "portal-test",
		Logger:      l,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	client := &http.Client{}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/healthz", srv.Port()), nil)
	req.Header.Set("User-Agent", "kube-probe/1.28")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
	if s := resp.Header.Get("Server"); s != headerServer {
		t.Errorf("expected Server %q, got %q", headerServer, s)
	}

	// kube-probe should NOT produce attack log
	output := sbuf.String()
	if strings.Contains(output, "honeypot_attack") {
		t.Errorf("kube-probe healthz should not produce attack log, but got:\n%s", output)
	}
}

func TestHTTPExternalHealthzLogged(t *testing.T) {
	var sbuf safeBuffer
	l := logger.New(&sbuf)

	srv := NewServer(Config{
		Port:        0,
		PublicPort:  80,
		ServiceName: "portal-test",
		Logger:      l,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	// External scanner access without kube-probe User-Agent
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", srv.Port()))
	if err != nil {
		t.Fatalf("failed to GET: %v", err)
	}
	defer resp.Body.Close()

	output := sbuf.String()
	if !strings.Contains(output, "honeypot_attack") {
		t.Fatalf("expected attack log for external healthz request, but got:\n%s", output)
	}
}

func TestHTTPXFFSpoofingPrevention(t *testing.T) {
	var sbuf safeBuffer
	l := logger.New(&sbuf)

	srv := NewServer(Config{
		Port:        0,
		PublicPort:  80,
		ServiceName: "portal-test",
		Logger:      l,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	client := &http.Client{}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", srv.Port()), nil)
	// Try to spoof source IP
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 10.0.0.1")
	req.Header.Set("X-Real-IP", "198.51.100.22")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	output := sbuf.String()
	var event logger.AttackEvent
	lines := strings.Split(strings.TrimSpace(output), "\n")
	found := false
	for _, line := range lines {
		if err := json.Unmarshal([]byte(line), &event); err == nil && event.Event == "honeypot_attack" {
			found = true
			if event.SrcIP != "127.0.0.1" {
				t.Errorf("expected real connection IP 127.0.0.1, but got spoofed IP %q", event.SrcIP)
			}
			if event.DstPort != 80 {
				t.Errorf("expected dst_port 80 (public port), got %d", event.DstPort)
			}
			headers := event.Details["headers"].(map[string]interface{})
			if !strings.Contains(headers["X-Forwarded-For"].(string), "203.0.113.195") {
				t.Errorf("expected X-Forwarded-For header to be preserved in details")
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected attack event in logs:\n%s", output)
	}
}

func TestHTTPNoRedirectOnTraversalOrDoubleSlash(t *testing.T) {
	var sbuf safeBuffer
	l := logger.New(&sbuf)

	srv := NewServer(Config{
		Port:        0,
		PublicPort:  80,
		ServiceName: "portal-test",
		Logger:      l,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	// Send raw request over TCP to avoid Go client automatic URL cleaning
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.Port()))
	if err != nil {
		t.Fatalf("tcp dial failed: %v", err)
	}
	defer conn.Close()

	rawReq := "GET //wp-login.php HTTP/1.1\r\nHost: target\r\nUser-Agent: scanner\r\n\r\n"
	if _, err := conn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	resBuf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(resBuf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	response := string(resBuf[:n])
	// Should NOT be 307 / 301 redirect! Must be 404 with decoy header
	if strings.Contains(response, "307 Temporary Redirect") || strings.Contains(response, "301 Moved") {
		t.Fatalf("server returned redirect instead of handling traversal/double-slash:\n%s", response)
	}
	if !strings.Contains(response, "404 Not Found") {
		t.Fatalf("expected 404 Not Found, got:\n%s", response)
	}
	if !strings.Contains(response, "Server: Apache/2.4.41 (Ubuntu)") {
		t.Fatalf("missing decoy server header in response:\n%s", response)
	}

	output := sbuf.String()
	if !strings.Contains(output, "wp-login.php") {
		t.Fatalf("expected attack log for //wp-login.php, got:\n%s", output)
	}
}

func TestHTTPLoginDecoyFailure(t *testing.T) {
	var sbuf safeBuffer
	l := logger.New(&sbuf)

	srv := NewServer(Config{
		Port:        0,
		PublicPort:  80,
		ServiceName: "portal-test",
		Logger:      l,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	reqBody := `username=admin&password=admin123`
	resp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/login", srv.Port()), "application/x-www-form-urlencoded", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for /login, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Invalid username or password") {
		t.Errorf("expected login failed message in body, got:\n%s", string(body))
	}

	output := sbuf.String()
	if !strings.Contains(output, "admin123") {
		t.Fatalf("expected password payload in logs, got:\n%s", output)
	}
}
