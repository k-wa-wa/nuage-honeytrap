package enricher

import (
	"testing"
)

func TestEnricher_Nil(t *testing.T) {
	var e *Enricher
	asn, org := e.Lookup("8.8.8.8")
	if asn != 0 || org != "" {
		t.Fatalf("expected 0, empty string from nil enricher, got %d, %s", asn, org)
	}

	if err := e.Close(); err != nil {
		t.Fatalf("unexpected error closing nil enricher: %v", err)
	}
}

func TestEnricher_EmptyPath(t *testing.T) {
	e, err := New("")
	if err != nil {
		t.Fatalf("unexpected error for empty path: %v", err)
	}
	if e != nil {
		t.Fatalf("expected nil enricher for empty path, got %v", e)
	}
}

func TestEnricher_NonExistentFile(t *testing.T) {
	e, err := New("/non/existent/path/to/GeoLite2-ASN.mmdb")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
	if e != nil {
		t.Fatalf("expected nil enricher on error, got %v", e)
	}
}

func TestEnricher_PrivateAndInvalidIP(t *testing.T) {
	e := &Enricher{}

	tests := []string{
		"invalid-ip",
		"",
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
		"::1",
		"0.0.0.0",
	}

	for _, ip := range tests {
		asn, org := e.Lookup(ip)
		if asn != 0 || org != "" {
			t.Errorf("expected 0, empty string for IP %q, got %d, %s", ip, asn, org)
		}
	}
}

func TestEnricher_LiveDB(t *testing.T) {
	mmdbPath := "/tmp/GeoLite2-ASN.mmdb"
	e, err := New(mmdbPath)
	if err != nil {
		t.Skipf("skipping live mmdb test (file not found at %s): %v", mmdbPath, err)
	}
	defer func() {
		_ = e.Close()
	}()

	tests := []struct {
		ip          string
		expectedASN uint
		containsOrg string
	}{
		{"8.8.8.8", 15169, "Google"},
		{"1.1.1.1", 13335, "Cloudflare"},
	}

	for _, tt := range tests {
		asn, org := e.Lookup(tt.ip)
		if asn != tt.expectedASN {
			t.Errorf("Lookup(%q) ASN = %d, want %d", tt.ip, asn, tt.expectedASN)
		}
		if org == "" || (tt.containsOrg != "" && !containsIgnoreCase(org, tt.containsOrg)) {
			t.Errorf("Lookup(%q) Org = %q, want containing %q", tt.ip, org, tt.containsOrg)
		}
	}
}

func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) > 0 && (stringsContains(s, substr)))
}

func stringsContains(s, substr string) bool {
	// Simple case-insensitive check
	sLower := []byte(s)
	subLower := []byte(substr)
	for i := range sLower {
		if sLower[i] >= 'A' && sLower[i] <= 'Z' {
			sLower[i] += 'a' - 'A'
		}
	}
	for i := range subLower {
		if subLower[i] >= 'A' && subLower[i] <= 'Z' {
			subLower[i] += 'a' - 'A'
		}
	}
	return bytesContains(sLower, subLower)
}

func bytesContains(b, sub []byte) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(b)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
