package http

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

const (
	headerServer    = "Apache/2.4.41 (Ubuntu)"
	headerPoweredBy = "PHP/7.4.3"

	robotsTxtContent = `User-agent: *
Disallow: /admin/
Disallow: /.env
Disallow: /backup.sql
Disallow: /api/v1/debug
Disallow: /staging/config
`

	portalHTML = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>Nuage Internal Portal v0.8.2-beta</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 40px 20px; color: #333; }
    .container { max-width: 440px; margin: 0 auto; background: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); padding: 32px; }
    h1 { font-size: 20px; margin-bottom: 8px; color: #1a1a1a; }
    .badge { display: inline-block; padding: 2px 8px; font-size: 11px; font-weight: bold; background: #fff3cd; color: #856404; border-radius: 4px; margin-bottom: 20px; }
    .form-group { margin-bottom: 16px; text-align: left; }
    label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 4px; color: #555; }
    input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; }
    button { width: 100%; padding: 10px; background: #0066cc; color: #fff; border: none; border-radius: 4px; font-size: 14px; font-weight: bold; cursor: pointer; margin-top: 8px; }
    button:hover { background: #0052a3; }
    footer { margin-top: 32px; font-size: 12px; color: #777; text-align: center; border-top: 1px solid #eee; padding-top: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Nuage Internal Portal</h1>
    <div class="badge">v0.8.2-beta</div>
    <form method="POST" action="/login">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" placeholder="admin" required autofocus>
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit">Sign In</button>
    </form>
    <footer>
      Environment: Staging (Internal Access Only)
    </footer>
    <!-- TODO(dev): 本番移行前にデフォルトの管理者PW (admin / admin123) を無効化すること -->
  </div>
</body>
</html>
`

	apache404HTML = `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at nuage.internal Port 80</address>
</body></html>
`
)

// Server is an HTTP honeypot server masquerading as an Apache/PHP internal portal.
type Server struct {
	port        int
	serviceName string
	logger      *logger.Logger
	httpServer  *http.Server
	listener    net.Listener
}

// Config holds options for the HTTP honeypot.
type Config struct {
	Port        int
	ServiceName string
	Logger      *logger.Logger
}

// NewServer creates a new HTTP honeypot server.
func NewServer(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = logger.DefaultLogger
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "portal-staging"
	}

	s := &Server{
		port:        cfg.Port,
		serviceName: cfg.ServiceName,
		logger:      cfg.Logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/", s.handleAll)

	s.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return s
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = ln

	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		s.port = tcpAddr.Port
	}

	s.logger.Info("HTTP honeypot started", map[string]interface{}{
		"port":    s.port,
		"service": s.serviceName,
	})

	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP serve error", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}()

	return nil
}

// Port returns the listening port.
func (s *Server) Port() int {
	return s.port
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleAll(w http.ResponseWriter, r *http.Request) {
	// Set decoy headers
	w.Header().Set("Server", headerServer)
	w.Header().Set("X-Powered-By", headerPoweredBy)

	// Read body up to 4KB for attack logging
	var bodySnippet string
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		bodySnippet = string(bodyBytes)
	}

	// Filter and collect headers
	headers := make(map[string]string)
	for k, v := range r.Header {
		headers[k] = strings.Join(v, ", ")
	}

	clientIP := s.extractClientIP(r)

	s.logger.LogAttack("http", clientIP, s.port, s.serviceName, map[string]interface{}{
		"method":     r.Method,
		"path":       r.URL.Path,
		"query":      r.URL.RawQuery,
		"user_agent": r.UserAgent(),
		"headers":    headers,
		"body":       bodySnippet,
		"host":       r.Host,
	})

	switch r.URL.Path {
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(portalHTML))
	case "/robots.txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(robotsTxtContent))
	default:
		w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(apache404HTML))
	}
}

func (s *Server) extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return logger.ExtractIP(r.RemoteAddr)
}

// Stop gracefully stops the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	err := s.httpServer.Shutdown(ctx)
	s.logger.Info("HTTP honeypot stopped", map[string]interface{}{"port": s.port})
	return err
}
