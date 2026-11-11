package enricher

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// Record represents the MaxMind GeoLite2-ASN database record structure.
type Record struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// Enricher performs thread-safe offline ASN lookups using a MaxMind GeoLite2-ASN database.
type Enricher struct {
	db *maxminddb.Reader
	mu sync.RWMutex
}

// New opens the MMDB file at the specified path and initializes an Enricher.
// If the path is empty, New returns nil, nil (enrichment disabled).
func New(path string) (*Enricher, error) {
	if path == "" {
		return nil, nil
	}

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("asn mmdb file not found at %s: %w", path, err)
	}

	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open asn mmdb at %s: %w", path, err)
	}

	return &Enricher{db: db}, nil
}

// Lookup resolves an IP address string to its Autonomous System Number and Organization name.
// Returns 0, "" if lookup fails, IP is invalid/private, or DB is not loaded.
func (e *Enricher) Lookup(ipStr string) (uint, string) {
	if e == nil {
		return 0, ""
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return 0, ""
	}

	// Skip lookup for loopback, private, and unspecified IP ranges
	if parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsUnspecified() {
		return 0, ""
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.db == nil {
		return 0, ""
	}

	var rec Record
	if err := e.db.Lookup(parsedIP, &rec); err != nil {
		return 0, ""
	}

	return rec.AutonomousSystemNumber, rec.AutonomousSystemOrganization
}

// Close releases resources associated with the reader.
func (e *Enricher) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.db != nil {
		err := e.db.Close()
		e.db = nil
		return err
	}
	return nil
}
