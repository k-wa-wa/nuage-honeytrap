package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
	gossh "golang.org/x/crypto/ssh"
)

const defaultSSHBanner = "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"

// Server is an SSH honeypot server that captures credentials and refuses all logins.
type Server struct {
	port        int
	serviceName string
	logger      *logger.Logger
	listener    net.Listener
	sshConfig   *gossh.ServerConfig
	wg          sync.WaitGroup
	quit        chan struct{}
}

// Config holds options for the SSH honeypot.
type Config struct {
	Port        int
	ServiceName string
	Logger      *logger.Logger
	Signer      gossh.Signer // optional: if nil, an ephemeral Ed25519 host key is generated
}

// NewServer creates a new SSH honeypot server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = logger.DefaultLogger
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "bastion-dev"
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
		port:        cfg.Port,
		serviceName: cfg.ServiceName,
		logger:      cfg.Logger,
		quit:        make(chan struct{}),
	}

	sshConfig := &gossh.ServerConfig{
		ServerVersion: defaultSSHBanner,
		NoClientAuth:  false,
		NoClientAuthCallback: func(conn gossh.ConnMetadata) (*gossh.Permissions, error) {
			s.logger.LogAttack("ssh", logger.ExtractIP(conn.RemoteAddr().String()), s.port, s.serviceName, map[string]interface{}{
				"auth_method":    "none",
				"username":       conn.User(),
				"client_version": string(conn.ClientVersion()),
				"remote_addr":    conn.RemoteAddr().String(),
			})
			return nil, errors.New("permission denied")
		},
		PasswordCallback: func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			s.logger.LogAttack("ssh", logger.ExtractIP(conn.RemoteAddr().String()), s.port, s.serviceName, map[string]interface{}{
				"auth_method":    "password",
				"username":       conn.User(),
				"password":       string(password),
				"client_version": string(conn.ClientVersion()),
				"remote_addr":    conn.RemoteAddr().String(),
			})
			return nil, errors.New("permission denied")
		},
		PublicKeyCallback: func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			s.logger.LogAttack("ssh", logger.ExtractIP(conn.RemoteAddr().String()), s.port, s.serviceName, map[string]interface{}{
				"auth_method":    "publickey",
				"username":       conn.User(),
				"key_type":       key.Type(),
				"fingerprint":    gossh.FingerprintSHA256(key),
				"client_version": string(conn.ClientVersion()),
				"remote_addr":    conn.RemoteAddr().String(),
			})
			return nil, errors.New("permission denied")
		},
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

	// If port 0 was passed, update port to assigned listener port
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		s.port = tcpAddr.Port
	}

	s.logger.Info("SSH honeypot started", map[string]interface{}{
		"port":    s.port,
		"service": s.serviceName,
	})

	s.wg.Add(1)
	go s.serve()

	return nil
}

// Port returns the listening port.
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

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c)
		}(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// Set timeout for handshake
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	sConn, _, _, err := gossh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		// Handshake/auth failed as expected
		return
	}
	// Defensive: Even if an auth bug occurs, close immediately and never grant a shell
	if sConn != nil {
		_ = sConn.Close()
	}
}

// Stop gracefully shuts down the SSH honeypot.
func (s *Server) Stop(ctx context.Context) error {
	close(s.quit)
	if s.listener != nil {
		_ = s.listener.Close()
	}

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
