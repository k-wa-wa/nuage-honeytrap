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

func TestHTTPCloudflareHeaders(t *testing.T) {
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

	tests := []struct {
		name                string
		headers             map[string]string
		expectedSrcIP       string
		expectedSrcIPSource string
		expectedCountry     string
		expectedRayID       string
		expectedInvalidCFIP string
	}{
		{
			name: "All Cloudflare headers present (IPv4)",
			headers: map[string]string{
				"CF-Connecting-IP": "198.51.100.42",
				"CF-IPCountry":     "JP",
				"CF-Ray":           "8a1b2c3d4e5f6g7h-NRT",
				"X-Forwarded-For":  "203.0.113.1", // Spoofed XFF should be ignored in favor of CF-Connecting-IP
			},
			expectedSrcIP:       "198.51.100.42",
			expectedSrcIPSource: "cf-connecting-ip",
			expectedCountry:     "JP",
			expectedRayID:       "8a1b2c3d4e5f6g7h-NRT",
		},
		{
			name: "CF-Connecting-IP with port",
			headers: map[string]string{
				"CF-Connecting-IP": "198.51.100.99:54321",
				"CF-IPCountry":     "US",
			},
			expectedSrcIP:       "198.51.100.99",
			expectedSrcIPSource: "cf-connecting-ip",
			expectedCountry:     "US",
			expectedRayID:       "",
		},
		{
			name: "CF-Connecting-IP with valid IPv6",
			headers: map[string]string{
				"CF-Connecting-IP": "2001:db8::1",
				"CF-IPCountry":     "DE",
			},
			expectedSrcIP:       "2001:db8::1",
			expectedSrcIPSource: "cf-connecting-ip",
			expectedCountry:     "DE",
			expectedRayID:       "",
		},
		{
			name: "Invalid CF-Connecting-IP falls back to RemoteAddr and logs invalid_cf_connecting_ip",
			headers: map[string]string{
				"CF-Connecting-IP": "invalid-ip-string<script>",
				"CF-IPCountry":     "SG",
			},
			expectedSrcIP:       "127.0.0.1",
			expectedSrcIPSource: "remote_addr",
			expectedCountry:     "SG",
			expectedRayID:       "",
			expectedInvalidCFIP: "invalid-ip-string<script>",
		},
		{
			name: "No Cloudflare headers (fallback to RemoteAddr)",
			headers: map[string]string{
				"User-Agent": "normal-client",
			},
			expectedSrcIP:       "127.0.0.1",
			expectedSrcIPSource: "remote_addr",
			expectedCountry:     "",
			expectedRayID:       "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sbuf.mu.Lock()
			sbuf.buf.Reset()
			sbuf.mu.Unlock()

			req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/test-cf", srv.Port()), nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()

			output := sbuf.String()
			var foundEvent *logger.AttackEvent
			lines := strings.Split(strings.TrimSpace(output), "\n")
			for _, line := range lines {
				var ev logger.AttackEvent
				if err := json.Unmarshal([]byte(line), &ev); err == nil && ev.Event == "honeypot_attack" {
					foundEvent = &ev
					break
				}
			}
			if foundEvent == nil {
				t.Fatalf("expected honeypot_attack event in output:\n%s", output)
			}

			event := *foundEvent
			if event.SrcIP != tc.expectedSrcIP {
				t.Errorf("expected SrcIP %q, got %q", tc.expectedSrcIP, event.SrcIP)
			}

			srcIPSource, hasSource := event.Details["src_ip_source"].(string)
			if !hasSource || srcIPSource != tc.expectedSrcIPSource {
				t.Errorf("expected src_ip_source %q, got %q (present=%v)", tc.expectedSrcIPSource, srcIPSource, hasSource)
			}

			remoteIP, hasRemoteIP := event.Details["remote_ip"].(string)
			if !hasRemoteIP || remoteIP != "127.0.0.1" {
				t.Errorf("expected remote_ip 127.0.0.1, got %q (present=%v)", remoteIP, hasRemoteIP)
			}

			invalidCF, hasInvalidCF := event.Details["invalid_cf_connecting_ip"].(string)
			if tc.expectedInvalidCFIP != "" {
				if !hasInvalidCF || invalidCF != tc.expectedInvalidCFIP {
					t.Errorf("expected invalid_cf_connecting_ip %q, got %q (present=%v)", tc.expectedInvalidCFIP, invalidCF, hasInvalidCF)
				}
			} else {
				if hasInvalidCF {
					t.Errorf("expected no invalid_cf_connecting_ip, got %q", invalidCF)
				}
			}

			country, hasCountry := event.Details["country"].(string)
			if tc.expectedCountry != "" {
				if !hasCountry || country != tc.expectedCountry {
					t.Errorf("expected country %q, got %q (present=%v)", tc.expectedCountry, country, hasCountry)
				}
			} else {
				if hasCountry {
					t.Errorf("expected no country in details, got %q", country)
				}
			}

			rayID, hasRayID := event.Details["ray_id"].(string)
			if tc.expectedRayID != "" {
				if !hasRayID || rayID != tc.expectedRayID {
					t.Errorf("expected ray_id %q, got %q (present=%v)", tc.expectedRayID, rayID, hasRayID)
				}
			} else {
				if hasRayID {
					t.Errorf("expected no ray_id in details, got %q", rayID)
				}
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"dev-portal.example.com", "dev-portal.example.com"},
		{"Dev-Portal.Example.COM", "dev-portal.example.com"},
		{"staging-ext.example.com:443", "staging-ext.example.com"},
		{"staging-ext.example.com.", "staging-ext.example.com"},
		{"127.0.0.1:8080", "127.0.0.1"},
		{"[2001:db8::1]:80", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"", ""},
		{"evil<script>.example.com", ""},
		{"a b.example.com", ""},
		{strings.Repeat("a", 254), ""},
	}

	for _, tc := range tests {
		if got := normalizeDomain(tc.input); got != tc.expected {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestHTTPDomainLogged(t *testing.T) {
	var sbuf safeBuffer
	l := logger.New(&sbuf)

	srv := NewServer(Config{Port: 0, Logger: l})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", srv.Port()), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Host = "Dev-Portal.Example.com"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	for _, line := range strings.Split(strings.TrimSpace(sbuf.String()), "\n") {
		var ev logger.AttackEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil || ev.Event != "honeypot_attack" {
			continue
		}
		if ev.Domain != "dev-portal.example.com" {
			t.Errorf("expected domain dev-portal.example.com, got %q", ev.Domain)
		}
		if ev.Details["host"] != "Dev-Portal.Example.com" {
			t.Errorf("expected raw host preserved in details.host, got %v", ev.Details["host"])
		}
		return
	}
	t.Fatalf("expected honeypot_attack event in output:\n%s", sbuf.String())
}
