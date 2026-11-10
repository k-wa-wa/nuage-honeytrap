package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestPostgresSequentialGSSAndSSLNegotiation(t *testing.T) {
	var sbuf safeBuffer
	l := logger.New(&sbuf)

	srv := NewServer(Config{
		Port:        0,
		PublicPort:  5432,
		ServiceName: "postgres-test",
		Logger:      l,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.Port()))
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// 1. Send GSSENCRequest
	var gssReq [8]byte
	binary.BigEndian.PutUint32(gssReq[0:4], 8)
	binary.BigEndian.PutUint32(gssReq[4:8], gssEncRequestCode)
	if _, err := conn.Write(gssReq[:]); err != nil {
		t.Fatalf("failed to send GSSENCRequest: %v", err)
	}

	var gssResp [1]byte
	if _, err := io.ReadFull(conn, gssResp[:]); err != nil || gssResp[0] != 'N' {
		t.Fatalf("expected 'N' for GSSENCRequest, got: %v, %c", err, gssResp[0])
	}

	// 2. Follow up immediately with SSLRequest (as libpq with gssencmode=prefer does)
	var sslReq [8]byte
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestCode)
	if _, err := conn.Write(sslReq[:]); err != nil {
		t.Fatalf("failed to send SSLRequest: %v", err)
	}

	var sslResp [1]byte
	if _, err := io.ReadFull(conn, sslResp[:]); err != nil || sslResp[0] != 'N' {
		t.Fatalf("expected 'N' for SSLRequest, got: %v, %c", err, sslResp[0])
	}

	// 3. Send StartupMessage
	var body bytes.Buffer
	body.WriteString("user")
	body.WriteByte(0)
	body.WriteString("db_admin")
	body.WriteByte(0)
	body.WriteString("database")
	body.WriteByte(0)
	body.WriteString("main_db")
	body.WriteByte(0)
	body.WriteByte(0)

	packetLen := int32(8 + body.Len())
	var startupHeader [8]byte
	binary.BigEndian.PutUint32(startupHeader[0:4], uint32(packetLen))
	binary.BigEndian.PutUint32(startupHeader[4:8], 196608)

	if _, err := conn.Write(startupHeader[:]); err != nil {
		t.Fatalf("failed to send header: %v", err)
	}
	if _, err := conn.Write(body.Bytes()); err != nil {
		t.Fatalf("failed to send body: %v", err)
	}

	// Read error response
	var errHeader [5]byte
	if _, err := io.ReadFull(conn, errHeader[:]); err != nil || errHeader[0] != 'E' {
		t.Fatalf("expected 'E', got: %v", err)
	}

	output := sbuf.String()
	var event logger.AttackEvent
	lines := strings.Split(strings.TrimSpace(output), "\n")
	found := false
	for _, line := range lines {
		if err := json.Unmarshal([]byte(line), &event); err == nil && event.Event == "honeypot_attack" {
			if event.Protocol == "postgres" && event.Details["user"] == "db_admin" {
				if event.DstPort != 5432 {
					t.Errorf("expected dst_port 5432, got %d", event.DstPort)
				}
				if event.Details["ssl_requested"] == true && event.Details["gss_requested"] == true {
					found = true
					break
				}
			}
		}
	}
	if !found {
		t.Fatalf("expected sequential negotiation attack event in logs:\n%s", output)
	}
}

func TestPostgresDirectTLSClientHello(t *testing.T) {
	var sbuf safeBuffer
	l := logger.New(&sbuf)

	srv := NewServer(Config{
		Port:        0,
		PublicPort:  5432,
		ServiceName: "postgres-test",
		Logger:      l,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.Port()))
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer conn.Close()

	// Send direct TLS ClientHello prefix (0x16, 0x03, 0x03 ...)
	fakeTLS := []byte{0x16, 0x03, 0x03, 0x00, 0x40, 0x01, 0x00, 0x00}
	_, _ = conn.Write(fakeTLS)

	time.Sleep(100 * time.Millisecond)

	output := sbuf.String()
	if !strings.Contains(output, "tls_direct") {
		t.Fatalf("expected tls_direct stage in logs, got:\n%s", output)
	}
}

func TestPostgresInvalidPacketLength(t *testing.T) {
	var sbuf safeBuffer
	l := logger.New(&sbuf)

	srv := NewServer(Config{
		Port:        0,
		PublicPort:  5432,
		ServiceName: "postgres-test",
		Logger:      l,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.Port()))
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer conn.Close()

	// Send length = 4 (less than 8 bytes)
	var badLen [8]byte
	binary.BigEndian.PutUint32(badLen[0:4], 4)
	binary.BigEndian.PutUint32(badLen[4:8], 196608)
	_, _ = conn.Write(badLen[:])

	time.Sleep(100 * time.Millisecond)

	output := sbuf.String()
	if !strings.Contains(output, "invalid_packet_length") {
		t.Fatalf("expected invalid_packet_length in logs, got:\n%s", output)
	}
}

func TestPostgresImmediateStopWithHangingConn(t *testing.T) {
	var sbuf safeBuffer
	l := logger.New(&sbuf)

	srv := NewServer(Config{
		Port:        0,
		PublicPort:  5432,
		ServiceName: "postgres-test",
		Logger:      l,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.Port()))
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := srv.Stop(ctx); err != nil {
		t.Fatalf("clean stop failed: %v", err)
	}

	elapsed := time.Since(start)
	if elapsed > 1*time.Second {
		t.Errorf("Stop took too long: %v (expected < 1s)", elapsed)
	}
}
