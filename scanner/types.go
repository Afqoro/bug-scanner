package scanner

import (
	"fmt"
	"strings"
	"time"
)

// BugType describes what kind of bug was found
type BugType string

const (
	BugTypeSNI        BugType = "sni"
	BugTypeWebSocket  BugType = "websocket"
	BugTypeHTTPProxy  BugType = "http_proxy"
	BugTypeForwarding BugType = "forwarding"
)

// BugResult represents a confirmed working bug
type BugResult struct {
	Type        BugType `json:"type"`
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	SNI         string  `json:"sni,omitempty"`
	WSPath      string  `json:"ws_path,omitempty"`
	Protocol    string  `json:"protocol,omitempty"`
	LatencyMs   int64   `json:"latency_ms"`
	Region      string  `json:"region,omitempty"`
	ExitIP      string  `json:"exit_ip,omitempty"`
	Works       bool    `json:"works"`
	Description string  `json:"description,omitempty"`
	FoundAt     string  `json:"found_at"`
}

// ScanConfig holds all scanner configuration
type ScanConfig struct {
	OperatorASN    string
	OperatorName   string
	DNSResolver    string
	Ports          []int
	SNIList        []string
	HostList       []string
	WSPaths        []string
	Timeout        time.Duration
	Concurrency    int
	TestForwarding bool
	RegionOverride string
}

// DefaultPorts returns sensible default ports to scan
func DefaultPorts() []int {
	return []int{80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2087, 2096, 8880, 10000}
}

// DefaultWSPaths returns common WebSocket paths to try
func DefaultWSPaths() []string {
	return []string{"/", "/ws", "/websocket", "/wss", "/proxy", "/tunnel", "/bug", "/forward"}
}

func (s BugResult) String() string {
	var detail string
	switch s.Type {
	case BugTypeSNI:
		detail = fmt.Sprintf("SNI=%s", s.SNI)
	case BugTypeWebSocket:
		detail = fmt.Sprintf("WS=%s:%d%s", s.Host, s.Port, s.WSPath)
	case BugTypeHTTPProxy:
		detail = fmt.Sprintf("Proxy=%s:%d", s.Host, s.Port)
	default:
		detail = fmt.Sprintf("%s:%d", s.Host, s.Port)
	}
	return fmt.Sprintf("[%s] %s | %dms | %s | exit=%s",
		strings.ToUpper(string(s.Type)), detail, s.LatencyMs, s.Region, s.ExitIP)
}
