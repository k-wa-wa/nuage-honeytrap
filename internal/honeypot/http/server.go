package http

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
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

	loginFailedHTML = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>Nuage Internal Portal v0.8.2-beta - Login Failed</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 40px 20px; color: #333; }
    .container { max-width: 440px; margin: 0 auto; background: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); padding: 32px; }
    h1 { font-size: 20px; margin-bottom: 8px; color: #1a1a1a; }
    .alert { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px 12px; border-radius: 4px; font-size: 13px; margin-bottom: 16px; }
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
    <div class="alert">Invalid username or password. Please try again.</div>
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
	port          int
	publicPort    int
	serviceName   string
	logger        *logger.Logger
	httpServer    *http.Server
	listener      net.Listener
	activeConnsMu sync.Mutex
	activeConns   map[net.Conn]struct{}
	connSemaphore chan struct{}
}

// Config holds options for the HTTP honeypot.
type Config struct {
	Port           int
	PublicPort     int
	ServiceName    string
	Logger         *logger.Logger
	MaxConnections int
}

// NewServer creates a new HTTP honeypot server.
func NewServer(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = logger.DefaultLogger
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "portal-staging"
	}
	if cfg.PublicPort <= 0 {
		cfg.PublicPort = 80
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 100
	}

	s := &Server{
		port:          cfg.Port,
		publicPort:    cfg.PublicPort,
		serviceName:   cfg.ServiceName,
		logger:        cfg.Logger,
		activeConns:   make(map[net.Conn]struct{}),
		connSemaphore: make(chan struct{}, cfg.MaxConnections),
	}

	// Do NOT use http.ServeMux here! ServeMux automatically sanitizes paths and returns 307 redirects
	// for requests with directory traversal (e.g. /../../etc/passwd) or double slashes (//wp-login.php),
	// which prevents those attack payloads from reaching our decoy handler and logging logic.
	s.httpServer = &http.Server{
		Handler:        http.HandlerFunc(s.handleAll),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 16 * 1024, // 16KB limit to mitigate large-header memory attacks
		ConnState:      s.onConnState,
	}

	return s
}

func (s *Server) onConnState(c net.Conn, state http.ConnState) {
	s.activeConnsMu.Lock()
	defer s.activeConnsMu.Unlock()
	switch state {
	case http.StateNew:
		s.activeConns[c] = struct{}{}
	case http.StateClosed, http.StateHijacked:
		delete(s.activeConns, c)
	}
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
		"bind_port":   s.port,
		"public_port": s.publicPort,
		"service":     s.serviceName,
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

// Port returns the bound listening port.
func (s *Server) Port() int {
	return s.port
}

func (s *Server) handleAll(w http.ResponseWriter, r *http.Request) {
	// Apply connection semaphore
	select {
	case s.connSemaphore <- struct{}{}:
		defer func() { <-s.connSemaphore }()
	default:
		// Connection limit reached
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// Always attach decoy headers
	w.Header().Set("Server", headerServer)
	w.Header().Set("X-Powered-By", headerPoweredBy)

	rawPath := r.URL.Path
	if r.URL.RawPath != "" {
		rawPath = r.URL.RawPath
	}
	// Also inspect raw request URI before URL decoding
	reqURI := r.RequestURI

	isKubeProbe := strings.HasPrefix(r.UserAgent(), "kube-probe/")
	isHealthz := rawPath == "/healthz" || strings.HasPrefix(reqURI, "/healthz")

	// If this is an internal probe from kubelet, respond quietly without logging honeypot_attack
	if isHealthz && isKubeProbe {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}

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

	// Determine client source IP:
	// Prioritize CF-Connecting-IP when present and valid (e.g. via Cloudflare Tunnel).
	// Validate with net.ParseIP to prevent arbitrary string injection and VictoriaLogs pollution.
	// Always record real connection IP (r.RemoteAddr) and src_ip_source for auditability and spoofing detection.
	// Do NOT trust X-Forwarded-For or X-Real-IP as they can be easily spoofed by attackers.
	realIP := logger.ExtractIP(r.RemoteAddr)
	clientIP := realIP
	srcIPSource := "remote_addr"
	var invalidCFIP string

	if rawCFIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); rawCFIP != "" {
		extractedCFIP := logger.ExtractIP(rawCFIP)
		if parsed := net.ParseIP(extractedCFIP); parsed != nil {
			clientIP = parsed.String()
			srcIPSource = "cf-connecting-ip"
		} else {
			invalidCFIP = rawCFIP
		}
	}

	details := map[string]interface{}{
		"method":        r.Method,
		"path":          rawPath,
		"request_uri":   reqURI,
		"query":         r.URL.RawQuery,
		"user_agent":    r.UserAgent(),
		"headers":       headers,
		"body":          bodySnippet,
		"host":          r.Host,
		"remote_addr":   r.RemoteAddr,
		"remote_ip":     realIP,
		"src_ip_source": srcIPSource,
	}

	if invalidCFIP != "" {
		details["invalid_cf_connecting_ip"] = invalidCFIP
	}

	if country := strings.TrimSpace(r.Header.Get("CF-IPCountry")); country != "" {
		details["country"] = country
	}
	if rayID := strings.TrimSpace(r.Header.Get("CF-Ray")); rayID != "" {
		details["ray_id"] = rayID
	}

	s.logger.LogAttackWithDomain("http", clientIP, s.publicPort, s.serviceName, normalizeDomain(r.Host), details)

	if isHealthz {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}

	switch {
	case rawPath == "/" || rawPath == "/index.html" || rawPath == "/index.php":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(portalHTML))
	case rawPath == "/login":
		// Decoy authentication failure
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(loginFailedHTML))
	case rawPath == "/robots.txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(robotsTxtContent))
	default:
		w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(apache404HTML))
	}
}

// maxDomainLength is the maximum length of a DNS name (RFC 1035).
const maxDomainLength = 253

// normalizeDomain turns an attacker-controlled Host header into a lowercase domain without port
// or trailing dot. It returns "" when the value is not a plausible hostname, so that arbitrary
// strings do not pollute the domain field in VictoriaLogs. The raw value stays in details.host.
func normalizeDomain(host string) string {
	h := strings.TrimSpace(host)
	if splitHost, _, err := net.SplitHostPort(h); err == nil {
		h = splitHost
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")

	if h == "" || len(h) > maxDomainLength {
		return ""
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return ip.String()
	}
	for _, c := range h {
		isAlnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !isAlnum && c != '-' && c != '.' && c != '_' {
			return ""
		}
	}
	return h
}

// Stop gracefully stops the HTTP server and forcibly closes any remaining open connections.
func (s *Server) Stop(ctx context.Context) error {
	err := s.httpServer.Shutdown(ctx)

	s.activeConnsMu.Lock()
	for c := range s.activeConns {
		_ = c.Close()
	}
	s.activeConns = make(map[net.Conn]struct{})
	s.activeConnsMu.Unlock()

	if err == nil {
		s.logger.Info("HTTP honeypot stopped", map[string]interface{}{"port": s.port})
	}
	return err
}
