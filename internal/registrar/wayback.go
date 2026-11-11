package registrar

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	waybackDefaultBaseURL  = "https://web.archive.org"
	waybackPollInterval    = 5 * time.Second
	waybackDefaultDeadline = 3 * time.Minute
)

// Wayback captures pages with the Internet Archive "Save Page Now 2" API.
// Anonymous use is rejected with 401, so an archive.org S3-style key pair is required.
// Keys: https://archive.org/account/s3.php
type Wayback struct {
	AccessKey  string
	SecretKey  string
	BaseURL    string
	HTTPClient *http.Client
	// PollDeadline bounds how long to wait for the capture job to finish.
	PollDeadline time.Duration
	sleep        func(ctx context.Context, d time.Duration) error
}

func (w *Wayback) Name() string { return "wayback" }

type spnSubmitResponse struct {
	JobID   string `json:"job_id"`
	URL     string `json:"url"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

type spnStatusResponse struct {
	Status      string `json:"status"`
	StatusExt   string `json:"status_ext"`
	Message     string `json:"message"`
	Timestamp   string `json:"timestamp"`
	OriginalURL string `json:"original_url"`
}

// Submit starts a capture job and waits until it succeeds or fails.
func (w *Wayback) Submit(ctx context.Context, targetURL string) (Result, error) {
	if w.AccessKey == "" || w.SecretKey == "" {
		return Result{}, fmt.Errorf("wayback access key or secret key is empty")
	}
	base := w.BaseURL
	if base == "" {
		base = waybackDefaultBaseURL
	}
	sleep := w.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	deadline := w.PollDeadline
	if deadline <= 0 {
		deadline = waybackDefaultDeadline
	}

	form := url.Values{"url": {targetURL}}
	req, err := newRequest(ctx, http.MethodPost, base+"/save", strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w.authorize(req)

	var submitted spnSubmitResponse
	status, body, err := w.doJSON(req, &submitted)
	if err != nil {
		return Result{}, err
	}
	if status != http.StatusOK || submitted.JobID == "" {
		msg := submitted.Message
		if msg == "" {
			msg = snippet(body)
		}
		return Result{}, fmt.Errorf("wayback save rejected (HTTP %d): %s", status, msg)
	}

	pollCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	for {
		if err := sleep(pollCtx, waybackPollInterval); err != nil {
			return Result{ID: submitted.JobID}, fmt.Errorf("wayback job %s did not finish within %s: %w", submitted.JobID, deadline, err)
		}

		statusReq, err := newRequest(pollCtx, http.MethodGet, base+"/save/status/"+url.PathEscape(submitted.JobID), nil)
		if err != nil {
			return Result{}, err
		}
		w.authorize(statusReq)

		var st spnStatusResponse
		code, body, err := w.doJSON(statusReq, &st)
		if err != nil {
			return Result{ID: submitted.JobID}, err
		}
		if code != http.StatusOK {
			return Result{ID: submitted.JobID}, fmt.Errorf("wayback status check returned HTTP %d: %s", code, snippet(body))
		}

		switch st.Status {
		case "success":
			original := st.OriginalURL
			if original == "" {
				original = targetURL
			}
			return Result{
				ID:        submitted.JobID,
				ResultURL: fmt.Sprintf("%s/web/%s/%s", base, st.Timestamp, original),
			}, nil
		case "error":
			return Result{ID: submitted.JobID}, fmt.Errorf("wayback capture failed: %s %s", st.StatusExt, st.Message)
		case "pending":
			continue
		default:
			return Result{ID: submitted.JobID}, fmt.Errorf("wayback returned unknown job status %q: %s", st.Status, snippet(body))
		}
	}
}

func (w *Wayback) authorize(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("LOW %s:%s", w.AccessKey, w.SecretKey))
}

func (w *Wayback) doJSON(req *http.Request, v interface{}) (int, []byte, error) {
	resp, err := w.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("wayback request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = json.Unmarshal(body, v)
	return resp.StatusCode, body, nil
}
