package registrar

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	urlscanDefaultBaseURL = "https://urlscan.io"
	urlscanMaxAttempts    = 3
	urlscanMaxWait        = 2 * time.Minute
)

// URLScan submits public scans to urlscan.io.
// API: https://docs.urlscan.io/apis/urlscan-openapi/scanning/submitscan
type URLScan struct {
	APIKey     string
	BaseURL    string
	HTTPClient *http.Client
	sleep      func(ctx context.Context, d time.Duration) error
}

func (u *URLScan) Name() string { return "urlscan" }

type urlscanResponse struct {
	UUID        string `json:"uuid"`
	Result      string `json:"result"`
	Visibility  string `json:"visibility"`
	Message     string `json:"message"`
	Description string `json:"description"`
}

// Submit requests a public scan. It retries on HTTP 429 and 5xx, waiting as the rate limit headers say.
func (u *URLScan) Submit(ctx context.Context, targetURL string) (Result, error) {
	if u.APIKey == "" {
		return Result{}, fmt.Errorf("urlscan API key is empty")
	}
	base := u.BaseURL
	if base == "" {
		base = urlscanDefaultBaseURL
	}
	sleep := u.sleep
	if sleep == nil {
		sleep = sleepCtx
	}

	payload, err := json.Marshal(map[string]string{"url": targetURL, "visibility": "public"})
	if err != nil {
		return Result{}, err
	}

	var lastErr error
	for attempt := 1; attempt <= urlscanMaxAttempts; attempt++ {
		req, err := newRequest(ctx, http.MethodPost, base+"/api/v1/scan/", strings.NewReader(string(payload)))
		if err != nil {
			return Result{}, err
		}
		req.Header.Set("API-Key", u.APIKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := u.HTTPClient.Do(req)
		if err != nil {
			return Result{}, fmt.Errorf("urlscan request failed: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		var parsed urlscanResponse
		_ = json.Unmarshal(body, &parsed)

		if resp.StatusCode == http.StatusOK {
			if parsed.UUID == "" {
				return Result{}, fmt.Errorf("urlscan returned 200 without uuid: %s", snippet(body))
			}
			resultURL := parsed.Result
			if resultURL == "" {
				resultURL = base + "/result/" + parsed.UUID + "/"
			}
			if parsed.Visibility != "" && parsed.Visibility != "public" {
				return Result{ID: parsed.UUID, ResultURL: resultURL},
					fmt.Errorf("urlscan accepted the scan but downgraded visibility to %q", parsed.Visibility)
			}
			return Result{ID: parsed.UUID, ResultURL: resultURL}, nil
		}

		lastErr = fmt.Errorf("urlscan returned HTTP %d: %s", resp.StatusCode, describe(parsed, body))
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		if !retryable || attempt == urlscanMaxAttempts {
			return Result{}, lastErr
		}
		if err := sleep(ctx, retryWait(resp.Header, attempt)); err != nil {
			return Result{}, err
		}
	}
	return Result{}, lastErr
}

func describe(r urlscanResponse, body []byte) string {
	switch {
	case r.Message != "" && r.Description != "":
		return r.Message + " - " + r.Description
	case r.Message != "":
		return r.Message
	default:
		return snippet(body)
	}
}

// retryWait follows X-Rate-Limit-Reset-After when present, otherwise backs off exponentially.
func retryWait(h http.Header, attempt int) time.Duration {
	if v := h.Get("X-Rate-Limit-Reset-After"); v != "" {
		if secs, err := strconv.ParseFloat(v, 64); err == nil && secs >= 0 {
			d := time.Duration(secs*float64(time.Second)) + time.Second
			if d > urlscanMaxWait {
				d = urlscanMaxWait
			}
			return d
		}
	}
	return time.Duration(5<<attempt) * time.Second
}
