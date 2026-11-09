package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/k-wa-wa/nuage-honeytrap/internal/logger"
	gossh "golang.org/x/crypto/ssh"
)

func TestSSHBanner(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf)

	srv, err := NewServer(Config{
		Port:        0, // dynamic port
		ServiceName: "bastion-test",
		Logger:      l,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

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

	bannerBuf := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(bannerBuf)
	if err != nil {
		t.Fatalf("failed to read banner: %v", err)
	}

	banner := string(bannerBuf[:n])
	if !strings.HasPrefix(banner, defaultSSHBanner) {
		t.Fatalf("unexpected banner: got %q, expected prefix %q", banner, defaultSSHBanner)
	}
}

func TestSSHPasswordAuthCapture(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf)

	srv, err := NewServer(Config{
		Port:        0,
		ServiceName: "bastion-test",
		Logger:      l,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	clientConfig := &gossh.ClientConfig{
		User: "admin",
		Auth: []gossh.AuthMethod{
			gossh.Password("SuperSecretP@ss!"),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	// Should fail authentication
	client, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.Port()), clientConfig)
	if err == nil {
		client.Close()
		t.Fatal("expected ssh dial to fail, but succeeded")
	}

	// Verify log
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	found := false
	for _, line := range lines {
		var event logger.AttackEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event.Event == "honeypot_attack" && event.Protocol == "ssh" {
			if event.Details["username"] == "admin" && event.Details["password"] == "SuperSecretP@ss!" {
				found = true
				break
			}
		}
	}

	if !found {
		t.Fatalf("did not find expected attack event in logs:\n%s", output)
	}
}

func TestSSHPublicKeyAuthCapture(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(&buf)

	srv, err := NewServer(Config{
		Port:        0,
		ServiceName: "bastion-test",
		Logger:      l,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	_, clientPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	clientSigner, err := gossh.NewSignerFromKey(clientPrivKey)
	if err != nil {
		t.Fatalf("failed to create client signer: %v", err)
	}

	clientConfig := &gossh.ClientConfig{
		User: "deployer",
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(clientSigner),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := gossh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.Port()), clientConfig)
	if err == nil {
		client.Close()
		t.Fatal("expected ssh dial to fail, but succeeded")
	}

	// Verify log
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	found := false
	for _, line := range lines {
		var event logger.AttackEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		if event.Event == "honeypot_attack" && event.Protocol == "ssh" {
			if event.Details["username"] == "deployer" && event.Details["auth_method"] == "publickey" {
				found = true
				break
			}
		}
	}

	if !found {
		t.Fatalf("did not find expected publickey attack event in logs:\n%s", output)
	}
}
