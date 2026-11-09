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
	protocolVersion3  = 196608   // 3.0
)

// Server is a PostgreSQL honeypot server capturing connection handshake details.
type Server struct {
	port        int
	serviceName string
	logger      *logger.Logger
	listener    net.Listener
	wg          sync.WaitGroup
	quit        chan struct{}
}

// Config holds options for the PostgreSQL honeypot.
type Config struct {
	Port        int
	ServiceName string
	Logger      *logger.Logger
}

// NewServer creates a new PostgreSQL honeypot server.
func NewServer(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = logger.DefaultLogger
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "postgres-staging"
	}

	return &Server{
		port:        cfg.Port,
		serviceName: cfg.ServiceName,
		logger:      cfg.Logger,
		quit:        make(chan struct{}),
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
				s.logger.Error("PostgreSQL accept error", map[string]interface{}{
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

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	sslRequested := false

	// Read initial packet (header: length int32, code/version int32)
	var header [8]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return
	}

	length := int32(binary.BigEndian.Uint32(header[0:4]))
	code := int32(binary.BigEndian.Uint32(header[4:8]))

	// Check for SSLRequest or GSSENCRequest
	if length == 8 && (code == sslRequestCode || code == gssEncRequestCode) {
		if code == sslRequestCode {
			sslRequested = true
		}
		// Send 'N' to deny SSL / GSS
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return
		}

		// Read the subsequent StartupMessage header
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		length = int32(binary.BigEndian.Uint32(header[0:4]))
		code = int32(binary.BigEndian.Uint32(header[4:8]))
	}

	// Validate packet length (StartupMessage must be at least 8 bytes and not excessively large)
	if length < 8 || length > 10000 {
		return
	}

	payloadLen := length - 8
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return
	}

	params := parseStartupParams(payload)
	user := params["user"]
	database := params["database"]
	if database == "" {
		database = user
	}

	protoVersionStr := fmt.Sprintf("%d.%d", code>>16, code&0xffff)

	clientIP := logger.ExtractIP(conn.RemoteAddr().String())
	s.logger.LogAttack("postgres", clientIP, s.port, s.serviceName, map[string]interface{}{
		"user":             user,
		"database":         database,
		"parameters":       params,
		"ssl_requested":    sslRequested,
		"protocol_version": protoVersionStr,
		"remote_addr":      conn.RemoteAddr().String(),
	})

	// Respond with standard PostgreSQL FATAL ErrorResponse
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
	// Field 'S': Severity
	buf.WriteByte('S')
	buf.WriteString("FATAL")
	buf.WriteByte(0)

	// Field 'V': Non-localized Severity
	buf.WriteByte('V')
	buf.WriteString("FATAL")
	buf.WriteByte(0)

	// Field 'C': SQLSTATE code (28P01 = invalid_password)
	buf.WriteByte('C')
	buf.WriteString("28P01")
	buf.WriteByte(0)

	// Field 'M': Human-readable message
	buf.WriteByte('M')
	buf.WriteString(errMsg)
	buf.WriteByte(0)

	// Packet terminator
	buf.WriteByte(0)

	// Total length = 4 (for length itself) + len(buf)
	packetLen := int32(4 + buf.Len())

	var out bytes.Buffer
	out.WriteByte('E') // ErrorResponse type
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(packetLen))
	out.Write(lenBytes[:])
	out.Write(buf.Bytes())

	_, err := conn.Write(out.Bytes())
	return err
}

// Stop gracefully stops the PostgreSQL honeypot server.
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
		s.logger.Info("PostgreSQL honeypot stopped", map[string]interface{}{"port": s.port})
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
