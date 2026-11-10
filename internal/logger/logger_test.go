package logger

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLogAttack(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	fixedTime := time.Date(2026, 11, 10, 2, 0, 0, 0, time.UTC)
	l.nowFunc = func() time.Time { return fixedTime }

	l.LogAttack("ssh", "10.244.0.123", 22, "bastion-dev", map[string]interface{}{
		"username": "root",
		"password": "123",
	})

	output := strings.TrimSpace(buf.String())
	var event AttackEvent
	if err := json.Unmarshal([]byte(output), &event); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	if event.Event != "honeypot_attack" {
		t.Errorf("expected event honeypot_attack, got %s", event.Event)
	}
	if event.Protocol != "ssh" {
		t.Errorf("expected protocol ssh, got %s", event.Protocol)
	}
	if event.SrcIP != "10.244.0.123" {
		t.Errorf("expected src_ip 10.244.0.123, got %s", event.SrcIP)
	}
	if event.DstPort != 22 {
		t.Errorf("expected dst_port 22, got %d", event.DstPort)
	}
	if event.Service != "bastion-dev" {
		t.Errorf("expected service bastion-dev, got %s", event.Service)
	}
	if event.Details["username"] != "root" || event.Details["password"] != "123" {
		t.Errorf("unexpected details: %v", event.Details)
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.5:43210", "192.168.1.5"},
		{"[2001:db8::1]:8080", "2001:db8::1"},
		{"invalid", "invalid"},
		{"127.0.0.1", "127.0.0.1"},
	}

	for _, tt := range tests {
		got := ExtractIP(tt.input)
		if got != tt.expected {
			t.Errorf("ExtractIP(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
