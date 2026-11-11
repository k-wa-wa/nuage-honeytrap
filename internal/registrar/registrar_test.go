package registrar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

func noSleep(context.Context, time.Duration) error { return nil }

func TestParseDomains(t *testing.T) {
	got, err := ParseDomains(" Dev-Portal.example.com, staging-ext.example.com.,,dev-portal.example.com ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"dev-portal.example.com", "staging-ext.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}

	for _, bad := range []string{"", " , ", "https://example.com", "localhost", "-bad.example.com", "a_b.example.com"} {
		if _, err := ParseDomains(bad); err == nil {
			t.Errorf("ParseDomains(%q) expected error", bad)
		}
	}
}

func TestURLScanSubmitSuccess(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/scan/" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("API-Key") != "test-key" {
			t.Errorf("missing API-Key header")
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "nuage-honeytrap-registrar/") {
			t.Errorf("unexpected User-Agent %q", r.Header.Get("User-Agent"))
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = io.WriteString(w, `{"message":"Submission successful","uuid":"abc-123","result":"https://urlscan.io/result/abc-123/","visibility":"public"}`)
	}))
	defer srv.Close()

	u := &URLScan{APIKey: "test-key", BaseURL: srv.URL, HTTPClient: srv.Client(), sleep: noSleep}
	res, err := u.Submit(context.Background(), "https://dev-portal.example.com/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotBody["url"] != "https://dev-portal.example.com/" || gotBody["visibility"] != "public" {
		t.Errorf("unexpected request body %v", gotBody)
	}
	if res.ID != "abc-123" || res.ResultURL != "https://urlscan.io/result/abc-123/" {
		t.Errorf("unexpected result %+v", res)
	}
}

func TestURLScanSubmitRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"message":"DNS Error - Could not resolve domain","description":"The domain could not be resolved.","status":400}`)
	}))
	defer srv.Close()

	u := &URLScan{APIKey: "k", BaseURL: srv.URL, HTTPClient: srv.Client(), sleep: noSleep}
	_, err := u.Submit(context.Background(), "https://nowhere.example.com/")
	if err == nil || !strings.Contains(err.Error(), "DNS Error") {
		t.Fatalf("expected DNS error, got %v", err)
	}
}

func TestURLScanSubmitRetriesOn429(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			w.Header().Set("X-Rate-Limit-Reset-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"message":"Rate limit exceeded"}`)
			return
		}
		_, _ = io.WriteString(w, `{"uuid":"retry-ok","visibility":"public"}`)
	}))
	defer srv.Close()

	var waited []time.Duration
	u := &URLScan{APIKey: "k", BaseURL: srv.URL, HTTPClient: srv.Client(), sleep: func(_ context.Context, d time.Duration) error {
		waited = append(waited, d)
		return nil
	}}
	res, err := u.Submit(context.Background(), "https://dev-portal.example.com/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ID != "retry-ok" || res.ResultURL != srv.URL+"/result/retry-ok/" {
		t.Errorf("unexpected result %+v", res)
	}
	if len(waited) != 1 || waited[0] != 4*time.Second {
		t.Errorf("expected one wait of 4s from X-Rate-Limit-Reset-After, got %v", waited)
	}
}

func TestURLScanSubmitVisibilityDowngraded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"uuid":"x","visibility":"unlisted"}`)
	}))
	defer srv.Close()

	u := &URLScan{APIKey: "k", BaseURL: srv.URL, HTTPClient: srv.Client(), sleep: noSleep}
	if _, err := u.Submit(context.Background(), "https://dev-portal.example.com/"); err == nil {
		t.Fatal("expected error when visibility is not public")
	}
}

func TestURLScanRequiresKey(t *testing.T) {
	u := &URLScan{HTTPClient: http.DefaultClient}
	if _, err := u.Submit(context.Background(), "https://x.example.com/"); err == nil {
		t.Fatal("expected error for empty API key")
	}
}

func TestWaybackSubmitSuccess(t *testing.T) {
	var mu sync.Mutex
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "LOW ak:sk" {
			t.Errorf("unexpected Authorization header %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/save":
			_ = r.ParseForm()
			if r.PostForm.Get("url") != "https://dev-portal.example.com/" {
				t.Errorf("unexpected url form value %q", r.PostForm.Get("url"))
			}
			_, _ = io.WriteString(w, `{"url":"https://dev-portal.example.com/","job_id":"job-1"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/save/status/job-1":
			mu.Lock()
			polls++
			n := polls
			mu.Unlock()
			if n == 1 {
				_, _ = io.WriteString(w, `{"status":"pending","job_id":"job-1"}`)
				return
			}
			_, _ = io.WriteString(w, `{"status":"success","job_id":"job-1","timestamp":"20261112000000","original_url":"https://dev-portal.example.com/"}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	wb := &Wayback{AccessKey: "ak", SecretKey: "sk", BaseURL: srv.URL, HTTPClient: srv.Client(), sleep: noSleep}
	res, err := wb.Submit(context.Background(), "https://dev-portal.example.com/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := srv.URL + "/web/20261112000000/https://dev-portal.example.com/"
	if res.ID != "job-1" || res.ResultURL != want {
		t.Errorf("unexpected result %+v, want ResultURL %s", res, want)
	}
}

func TestWaybackSubmitUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"You need to be logged in to use Save Page Now."}`)
	}))
	defer srv.Close()

	wb := &Wayback{AccessKey: "ak", SecretKey: "sk", BaseURL: srv.URL, HTTPClient: srv.Client(), sleep: noSleep}
	_, err := wb.Submit(context.Background(), "https://dev-portal.example.com/")
	if err == nil || !strings.Contains(err.Error(), "logged in") {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
}

func TestWaybackSubmitJobError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = io.WriteString(w, `{"job_id":"job-2"}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":"error","status_ext":"error:invalid-host-resolution","message":"Couldn't resolve host"}`)
	}))
	defer srv.Close()

	wb := &Wayback{AccessKey: "ak", SecretKey: "sk", BaseURL: srv.URL, HTTPClient: srv.Client(), sleep: noSleep}
	_, err := wb.Submit(context.Background(), "https://dev-portal.example.com/")
	if err == nil || !strings.Contains(err.Error(), "invalid-host-resolution") {
		t.Fatalf("expected job error, got %v", err)
	}
}

func TestWaybackSubmitTimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = io.WriteString(w, `{"job_id":"job-3"}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":"pending"}`)
	}))
	defer srv.Close()

	wb := &Wayback{AccessKey: "ak", SecretKey: "sk", BaseURL: srv.URL, HTTPClient: srv.Client(), PollDeadline: 50 * time.Millisecond,
		sleep: func(ctx context.Context, _ time.Duration) error { return sleepCtx(ctx, 10*time.Millisecond) }}
	_, err := wb.Submit(context.Background(), "https://dev-portal.example.com/")
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

type fakeSubmitter struct {
	name    string
	failFor string
	got     []string
}

func (f *fakeSubmitter) Name() string { return f.name }

func (f *fakeSubmitter) Submit(_ context.Context, targetURL string) (Result, error) {
	f.got = append(f.got, targetURL)
	if strings.Contains(targetURL, f.failFor) && f.failFor != "" {
		return Result{}, errors.New("boom")
	}
	return Result{ID: "id", ResultURL: "https://result.example/" + targetURL}, nil
}

func TestRunnerContinuesAfterFailureAndCounts(t *testing.T) {
	var buf bytes.Buffer
	a := &fakeSubmitter{name: "a", failFor: "bad.example.com"}
	b := &fakeSubmitter{name: "b"}
	r := &Runner{Submitters: []Submitter{a, b}, Logger: logger.New(&buf), Interval: time.Second, sleep: noSleep}

	failures := r.Run(context.Background(), []string{"bad.example.com", "good.example.com"})
	if failures != 1 {
		t.Errorf("expected 1 failure, got %d", failures)
	}
	if len(a.got) != 2 || len(b.got) != 2 {
		t.Errorf("expected every domain submitted to every service, got a=%v b=%v", a.got, b.got)
	}

	var succeeded, failed int
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var l logger.SystemLog
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			t.Fatalf("invalid JSON log line %q: %v", line, err)
		}
		switch l.Message {
		case "registration succeeded":
			succeeded++
			if l.Fields["result_url"] == "" || l.Fields["domain"] == "" {
				t.Errorf("success log lacks fields: %v", l.Fields)
			}
		case "registration failed":
			failed++
			if l.Level != "error" || l.Fields["error"] != "boom" {
				t.Errorf("unexpected failure log: %+v", l)
			}
		}
	}
	if succeeded != 3 || failed != 1 {
		t.Errorf("expected 3 success and 1 failure logs, got %d and %d", succeeded, failed)
	}
}
