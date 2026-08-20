package scanner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// ForwardResult holds the result of an HTTP CONNECT forwarding test
type ForwardResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	SNI     string `json:"sni,omitempty"`
	UseTLS  bool   `json:"use_tls"`
	Success bool   `json:"success"`
	Latency int64  `json:"latency_ms"`
	Status  int    `json:"status,omitempty"`
	Error   string `json:"error,omitempty"`
}

// TestForwarding tests whether a host:port can act as an HTTP CONNECT proxy.
// It sends a CONNECT request to a test target and checks if the tunnel is established.
func TestForwarding(host string, port int, sni string, useTLS bool, timeout time.Duration) ForwardResult {
	result := ForwardResult{
		Host:   host,
		Port:   port,
		SNI:    sni,
		UseTLS: useTLS,
	}

	address := fmt.Sprintf("%s:%d", host, port)
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

	// Send HTTP CONNECT to a known test target
	connectReq := fmt.Sprintf(
		"CONNECT api.ipify.org:443 HTTP/1.1\r\n"+
			"Host: api.ipify.org:443\r\n"+
			"User-Agent: BugScanner/1.0\r\n"+
			"\r\n",
	)

	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		result.Error = fmt.Sprintf("write: %v", err)
		result.Latency = time.Since(start).Milliseconds()
		return result
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	result.Latency = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = fmt.Sprintf("read: %v", err)
		return result
	}

	// Parse HTTP status line
	var status int
	fmt.Sscanf(line, "HTTP/%*d.%*d %d", &status)
	result.Status = status

	// 200 = tunnel established, 40x/50x = blocked
	if status == 200 || status == 101 {
		result.Success = true
	}

	return result
}

// TestForwardingBatch tests forwarding on multiple hosts concurrently
func TestForwardingBatch(hosts []string, ports []int, sniList []string, useTLS bool, timeout time.Duration, concurrency int) []ForwardResult {
	var results []ForwardResult
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

					res := TestForwarding(h, p, s, useTLS, timeout)
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

// FilterSuccessfulForward returns only forwarding tests that succeeded
func FilterSuccessfulForward(results []ForwardResult) []ForwardResult {
	var ok []ForwardResult
	for _, r := range results {
		if r.Success {
			ok = append(ok, r)
		}
	}
	return ok
}
