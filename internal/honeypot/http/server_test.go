package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

func TestHTTPHealthz(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf)

	srv := NewServer(Config{
		Port:        0,
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

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", srv.Port()))
	if err != nil {
		t.Fatalf("failed to GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	// /healthz should not produce attack log
	output := buf.String()
	if strings.Contains(output, "honeypot_attack") {
		t.Errorf("healthz should not produce attack log, but got:\n%s", output)
	}
}

func TestHTTPRoot(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf)

	srv := NewServer(Config{
		Port:        0,
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

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", srv.Port()))
	if err != nil {
		t.Fatalf("failed to GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	// Verify decoy headers
	if s := resp.Header.Get("Server"); s != headerServer {
		t.Errorf("expected Server %q, got %q", headerServer, s)
	}
	if p := resp.Header.Get("X-Powered-By"); p != headerPoweredBy {
		t.Errorf("expected X-Powered-By %q, got %q", headerPoweredBy, p)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "Nuage Internal Portal v0.8.2-beta") {
		t.Error("body does not contain portal title")
	}
	if !strings.Contains(bodyStr, "Environment: Staging (Internal Access Only)") {
		t.Error("body does not contain environment note")
	}
	if !strings.Contains(bodyStr, "TODO(dev): 本番移行前にデフォルトの管理者PW (admin / admin123) を無効化すること") {
		t.Error("body does not contain TODO comment")
	}

	// Verify attack log
	output := buf.String()
	var event logger.AttackEvent
	lines := strings.Split(strings.TrimSpace(output), "\n")
	found := false
	for _, line := range lines {
		if err := json.Unmarshal([]byte(line), &event); err == nil && event.Event == "honeypot_attack" {
			found = true
			if event.Protocol != "http" {
				t.Errorf("expected protocol http, got %s", event.Protocol)
			}
			if event.Details["path"] != "/" {
				t.Errorf("expected path /, got %v", event.Details["path"])
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected attack event in logs, got:\n%s", output)
	}
}

func TestHTTPRobotsTxt(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf)

	srv := NewServer(Config{
		Port:        0,
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

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/robots.txt", srv.Port()))
	if err != nil {
		t.Fatalf("failed to GET /robots.txt: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "Disallow: /.env") || !strings.Contains(bodyStr, "Disallow: /admin/") {
		t.Errorf("unexpected robots.txt content: %s", bodyStr)
	}
}

func TestHTTPNotFoundAndPostPayload(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf)

	srv := NewServer(Config{
		Port:        0,
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

	reqBody := `username=admin&password=Password123`
	resp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/admin/login.php", srv.Port()), "application/x-www-form-urlencoded", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 Not Found, got %d", resp.StatusCode)
	}

	output := buf.String()
	var event logger.AttackEvent
	lines := strings.Split(strings.TrimSpace(output), "\n")
	found := false
	for _, line := range lines {
		if err := json.Unmarshal([]byte(line), &event); err == nil && event.Event == "honeypot_attack" {
			if event.Details["path"] == "/admin/login.php" && event.Details["body"] == reqBody {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("expected POST attack event with body in logs, got:\n%s", output)
	}
}
