package logger

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// AttackEvent represents an attack or probing attempt detected by the honeypot.
type AttackEvent struct {
	Timestamp string                 `json:"timestamp"`
	Event     string                 `json:"event"`
	Protocol  string                 `json:"protocol"`
	SrcIP     string                 `json:"src_ip"`
	DstPort   int                    `json:"dst_port"`
	Service   string                 `json:"service"`
	Domain    string                 `json:"domain,omitempty"`
	Details   map[string]interface{} `json:"details"`
}

// SystemLog represents an internal operational log message.
type SystemLog struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// IPEnricher defines an interface for enriching IP addresses with ASN metadata.
type IPEnricher interface {
	Lookup(ipStr string) (asn uint, org string)
}

// Logger handles thread-safe structured JSON logging.
type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	nowFunc  func() time.Time
	enricher IPEnricher
}

// DefaultLogger is the default process-wide logger pointing to os.Stdout.
var DefaultLogger = New(os.Stdout)

// New creates a new Logger writing to the specified writer.
func New(out io.Writer) *Logger {
	return &Logger{
		out:     out,
		nowFunc: time.Now,
	}
}

// SetEnricher attaches an IPEnricher to automatically enrich attack events with ASN details.
func (l *Logger) SetEnricher(enricher IPEnricher) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enricher = enricher
}

// LogAttack writes an AttackEvent as a single JSON line.
func (l *Logger) LogAttack(protocol string, srcIP string, dstPort int, service string, details map[string]interface{}) {
	l.LogAttackWithDomain(protocol, srcIP, dstPort, service, "", details)
}

// LogAttackWithDomain writes an AttackEvent with the targeted domain as a single JSON line.
// An empty domain is omitted from the output.
func (l *Logger) LogAttackWithDomain(protocol string, srcIP string, dstPort int, service string, domain string, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}

	l.mu.Lock()
	enricher := l.enricher
	l.mu.Unlock()

	if enricher != nil && srcIP != "" {
		if asn, org := enricher.Lookup(srcIP); asn > 0 || org != "" {
			if _, exists := details["asn"]; !exists && asn > 0 {
				details["asn"] = asn
			}
			if _, exists := details["as_org"]; !exists && org != "" {
				details["as_org"] = org
			}
		}
	}

	event := AttackEvent{
		Timestamp: l.nowFunc().UTC().Format(time.RFC3339Nano),
		Event:     "honeypot_attack",
		Protocol:  protocol,
		SrcIP:     srcIP,
		DstPort:   dstPort,
		Service:   service,
		Domain:    domain,
		Details:   details,
	}

	l.writeJSON(event)
}

// Info writes an operational INFO log as JSON.
func (l *Logger) Info(message string, fields map[string]interface{}) {
	l.writeSystemLog("info", message, fields)
}

// Error writes an operational ERROR log as JSON.
func (l *Logger) Error(message string, fields map[string]interface{}) {
	l.writeSystemLog("error", message, fields)
}

func (l *Logger) writeSystemLog(level, message string, fields map[string]interface{}) {
	sysLog := SystemLog{
		Timestamp: l.nowFunc().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Message:   message,
		Fields:    fields,
	}
	l.writeJSON(sysLog)
}

func (l *Logger) writeJSON(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(data)
}

// ExtractIP extracts the IP address without port from a network address string (e.g. "192.0.2.1:1234").
func ExtractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
