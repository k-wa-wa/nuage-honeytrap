package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

const (
	sslRequestCode    = 80877103 // 1234.5679
	gssEncRequestCode = 80877104 // 1234.5680
	cancelRequestCode = 80877102 // 1234.5678
)

// Server is a PostgreSQL honeypot server capturing connection handshake details.
type Server struct {
	port          int
	publicPort    int
	serviceName   string
	logger        *logger.Logger
	listener      net.Listener
	wg            sync.WaitGroup
	quit          chan struct{}
	activeConnsMu sync.Mutex
	activeConns   map[net.Conn]struct{}
	stopped       bool
	connSemaphore chan struct{}
}

// Config holds options for the PostgreSQL honeypot.
type Config struct {
	Port           int
	PublicPort     int
	ServiceName    string
	Logger         *logger.Logger
	MaxConnections int
}

// NewServer creates a new PostgreSQL honeypot server.
func NewServer(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = logger.DefaultLogger
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "postgres-staging"
	}
	if cfg.PublicPort <= 0 {
		cfg.PublicPort = 5432
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 100
	}

	return &Server{
		port:          cfg.Port,
		publicPort:    cfg.PublicPort,
		serviceName:   cfg.ServiceName,
		logger:        cfg.Logger,
		quit:          make(chan struct{}),
		activeConns:   make(map[net.Conn]struct{}),
		connSemaphore: make(chan struct{}, cfg.MaxConnections),
	}
}

// Start begins listening for PostgreSQL connections.
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

	s.logger.Info("PostgreSQL honeypot started", map[string]interface{}{
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
				s.logger.Error("PostgreSQL accept error", map[string]interface{}{
					"error": err.Error(),
				})
				continue
			}
		}

		select {
		case s.connSemaphore <- struct{}{}:
		default:
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

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	clientIP := logger.ExtractIP(conn.RemoteAddr().String())

	var header [8]byte
	sslRequested := false
	gssRequested := false

	// Handle initial negotiation requests (SSLRequest, GSSENCRequest) in a loop
	// (e.g. libpq with Kerberos may send GSSENCRequest, receive 'N', and then send SSLRequest).
	for i := 0; i < 5; i++ {
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			// Connection closed or timed out before complete header
			s.logger.LogAttack("postgres", clientIP, s.publicPort, s.serviceName, map[string]interface{}{
				"stage":       "handshake_aborted",
				"remote_addr": conn.RemoteAddr().String(),
				"error":       err.Error(),
			})
			return
		}

		// Detect direct TLS ClientHello (starts with 0x16 0x03 0x01/0x02/0x03)
		if header[0] == 0x16 && header[1] == 0x03 {
			s.logger.LogAttack("postgres", clientIP, s.publicPort, s.serviceName, map[string]interface{}{
				"stage":       "tls_direct",
				"remote_addr": conn.RemoteAddr().String(),
				"error":       "client sent direct TLS ClientHello without negotiation",
			})
			return
		}

		length := int32(binary.BigEndian.Uint32(header[0:4]))
		code := int32(binary.BigEndian.Uint32(header[4:8]))

		if length == 8 && code == gssEncRequestCode {
			gssRequested = true
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
			continue
		}

		if length == 8 && code == sslRequestCode {
			sslRequested = true
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
			continue
		}

		if length == 16 && code == cancelRequestCode {
			s.logger.LogAttack("postgres", clientIP, s.publicPort, s.serviceName, map[string]interface{}{
				"stage":       "cancel_request",
				"remote_addr": conn.RemoteAddr().String(),
			})
			return
		}

		// Not a negotiation packet; proceed to StartupMessage processing
		s.handleStartupMessage(conn, header, length, code, clientIP, sslRequested, gssRequested)
		return
	}
}

func (s *Server) handleStartupMessage(conn net.Conn, header [8]byte, length, code int32, clientIP string, sslReq, gssReq bool) {
	// StartupMessage length must be at least 8 (includes length and protocol code) and not excessively large
	if length < 8 || length > 10000 {
		s.logger.LogAttack("postgres", clientIP, s.publicPort, s.serviceName, map[string]interface{}{
			"stage":         "invalid_packet_length",
			"packet_length": length,
			"protocol_code": code,
			"remote_addr":   conn.RemoteAddr().String(),
			"ssl_requested": sslReq,
			"gss_requested": gssReq,
		})
		return
	}

	payloadLen := length - 8
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		s.logger.LogAttack("postgres", clientIP, s.publicPort, s.serviceName, map[string]interface{}{
			"stage":       "payload_read_truncated",
			"remote_addr": conn.RemoteAddr().String(),
			"error":       err.Error(),
		})
		return
	}

	params := parseStartupParams(payload)
	user := params["user"]
	database := params["database"]

	protoVersionStr := fmt.Sprintf("%d.%d", code>>16, code&0xffff)

	s.logger.LogAttack("postgres", clientIP, s.publicPort, s.serviceName, map[string]interface{}{
		"user":             user,
		"database":         database,
		"parameters":       params,
		"ssl_requested":    sslReq,
		"gss_requested":    gssReq,
		"protocol_version": protoVersionStr,
		"remote_addr":      conn.RemoteAddr().String(),
	})

	_ = s.sendAuthenticationError(conn, user)
}

func parseStartupParams(payload []byte) map[string]string {
	params := make(map[string]string)
	entries := bytes.Split(payload, []byte{0})

	for i := 0; i+1 < len(entries); i += 2 {
		key := string(entries[i])
		if key == "" {
			break
		}
		val := string(entries[i+1])
		params[key] = val
	}
	return params
}

func (s *Server) sendAuthenticationError(conn net.Conn, user string) error {
	errMsg := fmt.Sprintf("password authentication failed for user \"%s\"", user)

	var buf bytes.Buffer
	buf.WriteByte('S')
	buf.WriteString("FATAL")
	buf.WriteByte(0)

	buf.WriteByte('V')
	buf.WriteString("FATAL")
	buf.WriteByte(0)

	buf.WriteByte('C')
	buf.WriteString("28P01")
	buf.WriteByte(0)

	buf.WriteByte('M')
	buf.WriteString(errMsg)
	buf.WriteByte(0)

	buf.WriteByte(0) // terminator

	packetLen := int32(4 + buf.Len())

	var out bytes.Buffer
	out.WriteByte('E')
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(packetLen))
	out.Write(lenBytes[:])
	out.Write(buf.Bytes())

	_, err := conn.Write(out.Bytes())
	return err
}

// Stop gracefully stops the PostgreSQL honeypot server and forcibly closes active connections.
func (s *Server) Stop(ctx context.Context) error {
	select {
	case <-s.quit:
		return nil
	default:
		close(s.quit)
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	s.activeConnsMu.Lock()
	s.stopped = true
	for c := range s.activeConns {
		_ = c.Close()
	}
	s.activeConns = make(map[net.Conn]struct{})
	s.activeConnsMu.Unlock()

	c := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(c)
	}()

	select {
	case <-c:
		s.logger.Info("PostgreSQL honeypot stopped", map[string]interface{}{"port": s.port})
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
