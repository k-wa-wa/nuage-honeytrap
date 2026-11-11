package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
	gossh "golang.org/x/crypto/ssh"
)

const defaultSSHBanner = "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"

// Server is an SSH honeypot server that captures credentials and refuses all logins.
type Server struct {
	port          int
	publicPort    int
	serviceName   string
	logger        *logger.Logger
	listener      net.Listener
	sshConfig     *gossh.ServerConfig
	wg            sync.WaitGroup
	quit          chan struct{}
	activeConnsMu sync.Mutex
	activeConns   map[net.Conn]struct{}
	stopped       bool
	connSemaphore chan struct{}
}

// Config holds options for the SSH honeypot.
type Config struct {
	Port           int
	PublicPort     int
	ServiceName    string
	Logger         *logger.Logger
	Signer         gossh.Signer // optional: if nil, an ephemeral Ed25519 host key is generated
	MaxConnections int
}

// NewServer creates a new SSH honeypot server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = logger.DefaultLogger
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "bastion-dev"
	}
	if cfg.PublicPort <= 0 {
		cfg.PublicPort = 22
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 100
	}

	signer := cfg.Signer
	if signer == nil {
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 host key: %w", err)
		}
		var sErr error
		signer, sErr = gossh.NewSignerFromKey(privKey)
		if sErr != nil {
			return nil, fmt.Errorf("failed to create signer from ed25519 key: %w", sErr)
		}
	}

	s := &Server{
		port:          cfg.Port,
		publicPort:    cfg.PublicPort,
		serviceName:   cfg.ServiceName,
		logger:        cfg.Logger,
		quit:          make(chan struct{}),
		activeConns:   make(map[net.Conn]struct{}),
		connSemaphore: make(chan struct{}, cfg.MaxConnections),
	}

	// We pass a per-connection context or hook via conn wrapping or callbacks
	sshConfig := &gossh.ServerConfig{
		ServerVersion: defaultSSHBanner,
		NoClientAuth:  true, // Enable NoClientAuth so NoClientAuthCallback is invoked for "none" auth
	}
	sshConfig.AddHostKey(signer)
	s.sshConfig = sshConfig

	return s, nil
}

// Start begins listening on the configured port.
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

	s.logger.Info("SSH honeypot started", map[string]interface{}{
		"bind_port":   s.port,
		"public_port": s.publicPort,
		"service":     s.serviceName,
	})

	s.wg.Add(1)
	go s.serve()

	return nil
}

// Port returns the bound listening port.
func (s *Server) Port() int {
	return s.port
}

func (s *Server) serve() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				s.logger.Error("SSH accept error", map[string]interface{}{
					"error": err.Error(),
				})
				continue
			}
		}

		select {
		case s.connSemaphore <- struct{}{}:
		default:
			// Max connections exceeded
			_ = conn.Close()
			continue
		}

		if !s.trackConn(conn, true) {
			continue
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				<-s.connSemaphore
				s.trackConn(c, false)
				s.wg.Done()
			}()
			s.handleConn(c)
		}(conn)
	}
}

func (s *Server) trackConn(c net.Conn, add bool) bool {
	s.activeConnsMu.Lock()
	defer s.activeConnsMu.Unlock()
	if s.stopped && add {
		_ = c.Close()
		return false
	}
	if add {
		s.activeConns[c] = struct{}{}
	} else {
		delete(s.activeConns, c)
	}
	return true
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	var authAttempted int32 // 0: false, 1: true
	clientIP := logger.ExtractIP(conn.RemoteAddr().String())

	// Build a per-connection ServerConfig copy so we can track auth attempts
	cfg := *s.sshConfig
	cfg.NoClientAuthCallback = func(c gossh.ConnMetadata) (*gossh.Permissions, error) {
		atomic.StoreInt32(&authAttempted, 1)
		s.logger.LogAttack("ssh", clientIP, s.publicPort, s.serviceName, map[string]interface{}{
			"auth_method":    "none",
			"username":       c.User(),
			"client_version": string(c.ClientVersion()),
			"remote_addr":    c.RemoteAddr().String(),
		})
		return nil, errors.New("permission denied")
	}

	cfg.PasswordCallback = func(c gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
		atomic.StoreInt32(&authAttempted, 1)
		s.logger.LogAttack("ssh", clientIP, s.publicPort, s.serviceName, map[string]interface{}{
			"auth_method":    "password",
			"username":       c.User(),
			"password":       string(password),
			"client_version": string(c.ClientVersion()),
			"remote_addr":    c.RemoteAddr().String(),
		})
		return nil, errors.New("permission denied")
	}

	cfg.PublicKeyCallback = func(c gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		atomic.StoreInt32(&authAttempted, 1)
		pubKeyStr := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key)))
		s.logger.LogAttack("ssh", clientIP, s.publicPort, s.serviceName, map[string]interface{}{
			"auth_method":    "publickey",
			"username":       c.User(),
			"key_type":       key.Type(),
			"fingerprint":    gossh.FingerprintSHA256(key),
			"public_key":     pubKeyStr,
			"client_version": string(c.ClientVersion()),
			"remote_addr":    c.RemoteAddr().String(),
		})
		return nil, errors.New("permission denied")
	}

	sConn, _, _, err := gossh.NewServerConn(conn, &cfg)
	if err != nil {
		// If the client connected and completed banner exchange but disconnected before attempting auth
		// (e.g. ssh-keyscan, nmap banner inspection, probe), record the probing attempt.
		if atomic.LoadInt32(&authAttempted) == 0 {
			s.logger.LogAttack("ssh", clientIP, s.publicPort, s.serviceName, map[string]interface{}{
				"stage":       "pre_auth",
				"remote_addr": conn.RemoteAddr().String(),
				"error":       err.Error(),
			})
		}
		return
	}

	// Defensive safeguard: never permit an interactive session
	if sConn != nil {
		_ = sConn.Close()
	}
}

// Stop gracefully shuts down the SSH honeypot and terminates active connections.
func (s *Server) Stop(ctx context.Context) error {
	select {
	case <-s.quit:
		return nil // already stopped
	default:
		close(s.quit)
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	// Forcibly close all active connections so graceful shutdown does not block
	s.activeConnsMu.Lock()
	s.stopped = true
	for c := range s.activeConns {
		_ = c.Close()
	}
	s.activeConnsMu.Unlock()

	c := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(c)
	}()

	select {
	case <-c:
		s.logger.Info("SSH honeypot stopped", map[string]interface{}{"port": s.port})
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
