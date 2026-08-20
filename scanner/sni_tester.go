package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// SNITestResult holds the result of an SNI spoofing test
type SNITestResult struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	SNI      string `json:"sni"`
	Success  bool   `json:"success"`
	Latency  int64  `json:"latency_ms"`
	Error    string `json:"error,omitempty"`
	TLSVer   string `json:"tls_version,omitempty"`
	CertCN   string `json:"cert_cn,omitempty"`
}

// TestSNI tests whether a TLS connection with a spoofed SNI can be established
// to the target host:port. If the connection succeeds without being blocked,
// the SNI is a candidate bug.
func TestSNI(host string, port int, sni string, timeout time.Duration) SNITestResult {
	result := SNITestResult{
		Host: host,
		Port: port,
		SNI: sni,
	}

	address := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	// Attempt TLS handshake with custom SNI
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		address,
		&tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	)
	latency := time.Since(start).Milliseconds()
	result.Latency = latency

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	result.Success = true
	state := conn.ConnectionState()
	result.TLSVer = tlsVersionString(state.Version)

	// Extract cert CN if available
	if len(state.PeerCertificates) > 0 {
		result.CertCN = state.PeerCertificates[0].Subject.CommonName
	}

	return result
}

// TestSNIBatch tests multiple SNI values against multiple hosts concurrently
func TestSNIBatch(hosts []string, ports []int, sniList []string, timeout time.Duration, concurrency int) []SNITestResult {
	var results []SNITestResult
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, host := range hosts {
		for _, port := range ports {
			for _, sni := range sniList {
				wg.Add(1)
				go func(h string, p int, s string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					res := TestSNI(h, p, s, timeout)
					mu.Lock()
					results = append(results, res)
					mu.Unlock()
				}(host, port, sni)
			}
		}
	}

	wg.Wait()
	return results
}

// FilterSuccessfulSNI returns only SNI tests that succeeded
func FilterSuccessfulSNI(results []SNITestResult) []SNITestResult {
	var ok []SNITestResult
	for _, r := range results {
		if r.Success {
			ok = append(ok, r)
		}
	}
	return ok
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
