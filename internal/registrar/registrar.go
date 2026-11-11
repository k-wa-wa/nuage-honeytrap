// Package registrar submits the honeypot domains to public scanning services (urlscan.io)
// so that crawlers and attackers who mine those feeds find them.
package registrar

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

// userAgent identifies this integration to the services, as urlscan.io asks integrations to do.
const userAgent = "nuage-honeytrap-registrar/1.0"

// Result describes an accepted submission.
type Result struct {
	// ID is the identifier assigned by the service (scan UUID or job ID).
	ID string
	// ResultURL is where the public result (scan report or snapshot) can be viewed.
	ResultURL string
}

// Submitter registers a URL with one external service.
type Submitter interface {
	Name() string
	Submit(ctx context.Context, targetURL string) (Result, error)
}

// Runner submits every domain to every submitter and logs each outcome.
type Runner struct {
	Submitters []Submitter
	Logger     *logger.Logger
	// Interval is the pause between two consecutive submissions to the same service.
	Interval time.Duration
	// sleep is replaceable in tests.
	sleep func(ctx context.Context, d time.Duration) error
}

// Run submits all domains and returns the number of failed submissions.
// It keeps going after a failure so that one bad domain or service does not hide the others.
func (r *Runner) Run(ctx context.Context, domains []string) int {
	sleep := r.sleep
	if sleep == nil {
		sleep = sleepCtx
	}

	failures := 0
	for _, s := range r.Submitters {
		for i, domain := range domains {
			if i > 0 && r.Interval > 0 {
				if err := sleep(ctx, r.Interval); err != nil {
					r.Logger.Error("registration aborted", map[string]interface{}{
						"target": s.Name(),
						"error":  err.Error(),
					})
					return failures + len(domains) - i
				}
			}

			targetURL := "https://" + domain + "/"
			res, err := s.Submit(ctx, targetURL)
			if err != nil {
				failures++
				r.Logger.Error("registration failed", map[string]interface{}{
					"target": s.Name(),
					"domain": domain,
					"url":    targetURL,
					"error":  err.Error(),
				})
				continue
			}
			r.Logger.Info("registration succeeded", map[string]interface{}{
				"target":     s.Name(),
				"domain":     domain,
				"url":        targetURL,
				"id":         res.ID,
				"result_url": res.ResultURL,
			})
		}
	}
	return failures
}

// ParseDomains splits a comma-separated list into normalized domains.
// It fails on an empty list or an invalid entry instead of silently skipping it.
func ParseDomains(raw string) ([]string, error) {
	var domains []string
	seen := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(part)), ".")
		if d == "" {
			continue
		}
		if !isValidDomain(d) {
			return nil, fmt.Errorf("invalid domain %q", part)
		}
		if !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains given")
	}
	return domains, nil
}

func isValidDomain(d string) bool {
	if len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func newRequest(ctx context.Context, method, url string, body *strings.Reader) (*http.Request, error) {
	var req *http.Request
	var err error
	if body == nil {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, body)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// snippet shortens a response body for error messages.
func snippet(b []byte) string {
	const max = 300
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
