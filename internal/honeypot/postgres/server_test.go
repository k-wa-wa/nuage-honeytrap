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
	"testing"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
)

func TestPostgresSSLAndStartup(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf)

	srv := NewServer(Config{
		Port:        0,
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

	// 1. Send SSLRequest (8 bytes)
	var sslReq [8]byte
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestCode)
	if _, err := conn.Write(sslReq[:]); err != nil {
		t.Fatalf("failed to send SSLRequest: %v", err)
	}

	// Read SSL response ('N')
	var sslResp [1]byte
	if _, err := io.ReadFull(conn, sslResp[:]); err != nil {
		t.Fatalf("failed to read SSL response: %v", err)
	}
	if sslResp[0] != 'N' {
		t.Fatalf("expected 'N', got %c", sslResp[0])
	}

	// 2. Send StartupMessage
	var body bytes.Buffer
	body.WriteString("user")
	body.WriteByte(0)
	body.WriteString("secops")
	body.WriteByte(0)
	body.WriteString("database")
	body.WriteByte(0)
	body.WriteString("finance_prod")
	body.WriteByte(0)
	body.WriteByte(0) // terminator

	packetLen := int32(8 + body.Len())
	var startupHeader [8]byte
	binary.BigEndian.PutUint32(startupHeader[0:4], uint32(packetLen))
	binary.BigEndian.PutUint32(startupHeader[4:8], protocolVersion3)

	if _, err := conn.Write(startupHeader[:]); err != nil {
		t.Fatalf("failed to send startup header: %v", err)
	}
	if _, err := conn.Write(body.Bytes()); err != nil {
		t.Fatalf("failed to send startup body: %v", err)
	}

	// Read server error response ('E' + length + body)
	var errHeader [5]byte
	if _, err := io.ReadFull(conn, errHeader[:]); err != nil {
		t.Fatalf("failed to read error header: %v", err)
	}
	if errHeader[0] != 'E' {
		t.Fatalf("expected 'E', got %c", errHeader[0])
	}
	errLen := binary.BigEndian.Uint32(errHeader[1:5])
	errPayload := make([]byte, errLen-4)
	if _, err := io.ReadFull(conn, errPayload); err != nil {
		t.Fatalf("failed to read error payload: %v", err)
	}

	errStr := string(errPayload)
	if !strings.Contains(errStr, "FATAL") || !strings.Contains(errStr, "password authentication failed for user \"secops\"") {
		t.Fatalf("unexpected error response payload: %q", errStr)
	}

	// Verify attack log
	output := buf.String()
	var event logger.AttackEvent
	lines := strings.Split(strings.TrimSpace(output), "\n")
	found := false
	for _, line := range lines {
		if err := json.Unmarshal([]byte(line), &event); err == nil && event.Event == "honeypot_attack" {
			if event.Protocol == "postgres" && event.Details["user"] == "secops" && event.Details["database"] == "finance_prod" {
				if event.Details["ssl_requested"] == true {
					found = true
					break
				}
			}
		}
	}
	if !found {
		t.Fatalf("expected attack event in logs, got:\n%s", output)
	}
}

func TestPostgresDirectStartup(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf)

	srv := NewServer(Config{
		Port:        0,
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

	// Send direct StartupMessage without SSLRequest
	var body bytes.Buffer
	body.WriteString("user")
	body.WriteByte(0)
	body.WriteString("root")
	body.WriteByte(0)
	body.WriteByte(0)

	packetLen := int32(8 + body.Len())
	var startupHeader [8]byte
	binary.BigEndian.PutUint32(startupHeader[0:4], uint32(packetLen))
	binary.BigEndian.PutUint32(startupHeader[4:8], protocolVersion3)

	if _, err := conn.Write(startupHeader[:]); err != nil {
		t.Fatalf("failed to send header: %v", err)
	}
	if _, err := conn.Write(body.Bytes()); err != nil {
		t.Fatalf("failed to send body: %v", err)
	}

	var errHeader [5]byte
	if _, err := io.ReadFull(conn, errHeader[:]); err != nil {
		t.Fatalf("failed to read error header: %v", err)
	}
	if errHeader[0] != 'E' {
		t.Fatalf("expected 'E', got %c", errHeader[0])
	}
}
