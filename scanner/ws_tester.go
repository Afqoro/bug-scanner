package scanner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WSTestResult holds the result of a WebSocket handshake test
type WSTestResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Path    string `json:"path"`
	SNI     string `json:"sni,omitempty"`
	UseTLS  bool   `json:"use_tls"`
	Success bool   `json:"success"`
	Latency int64  `json:"latency_ms"`
	Status  int    `json:"status,omitempty"`
	Error   string `json:"error,omitempty"`
}

// TestWebSocket tests a WebSocket handshake to host:port/path
// If useTLS is true, it uses wss:// (TLS) otherwise ws:// (plain)
func TestWebSocket(host string, port int, path, sni string, useTLS bool, timeout time.Duration) WSTestResult {
	result := WSTestResult{
		Host:   host,
		Port:   port,
		Path:   path,
		SNI:    sni,
		UseTLS: useTLS,
	}

	address := fmt.Sprintf("%s:%d", host, port)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	start := time.Now()

	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: timeout},
			"tcp",
			address,
			&tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		)
	} else {
		conn, err = net.DialTimeout("tcp", address, timeout)
	}
	if err != nil {
		result.Error = err.Error()
		result.Latency = time.Since(start).Milliseconds()
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send WebSocket upgrade request
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s:%d\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"User-Agent: Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36\r\n"+
			"\r\n",
		path, host, port,
	)

	_, err = conn.Write([]byte(req))
	if err != nil {
		result.Error = fmt.Sprintf("write: %v", err)
		result.Latency = time.Since(start).Milliseconds()
		return result
	}

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	result.Latency = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = fmt.Sprintf("read: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.Status = resp.StatusCode

	// Check if WebSocket upgrade succeeded
	upgrade := resp.Header.Get("Upgrade")
	connHdr := resp.Header.Get("Connection")
	if strings.EqualFold(upgrade, "websocket") || strings.Contains(strings.ToLower(connHdr), "upgrade") {
		result.Success = true
	} else if resp.StatusCode == 200 || resp.StatusCode == 101 {
		// Some servers return 200 or 101 without proper headers
		result.Success = true
	}

	return result
}

// TestWSBatch tests multiple WebSocket paths against hosts concurrently
func TestWSBatch(hosts []string, ports []int, paths []string, sniList []string, useTLS bool, timeout time.Duration, concurrency int) []WSTestResult {
	var results []WSTestResult
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, host := range hosts {
		for _, port := range ports {
			for _, path := range paths {
				for _, sni := range sniList {
					wg.Add(1)
					go func(h string, p int, pa, s string) {
						defer wg.Done()
						sem <- struct{}{}
						defer func() { <-sem }()

						res := TestWebSocket(h, p, pa, s, useTLS, timeout)
						mu.Lock()
						results = append(results, res)
						mu.Unlock()
					}(host, port, path, sni)
				}
			}
		}
	}

	wg.Wait()
	return results
}

// FilterSuccessfulWS returns only WebSocket tests that succeeded
func FilterSuccessfulWS(results []WSTestResult) []WSTestResult {
	var ok []WSTestResult
	for _, r := range results {
		if r.Success {
			ok = append(ok, r)
		}
	}
	return ok
}
