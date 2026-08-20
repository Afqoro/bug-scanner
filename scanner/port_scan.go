package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// PortScanResult holds results of a port scan
// HostInfo holds info about a discovered host
type HostInfo struct {
	IP       string
	Ports    []int
	Hostname string
}

// PortResult holds a single port scan result
type PortResult struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Port     int    `json:"port"`
	Open     bool   `json:"open"`
	Latency  int64  `json:"latency_ms"`
}

// ScanPorts scans a list of hosts for open ports concurrently
func ScanPorts(hosts []string, ports []int, timeout time.Duration, concurrency int) []PortResult {
	var results []PortResult
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, host := range hosts {
		for _, port := range ports {
			wg.Add(1)
			go func(h string, p int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				result := scanPort(h, p, timeout)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}(host, port)
		}
	}

	wg.Wait()
	return results
}

func scanPort(host string, port int, timeout time.Duration) PortResult {
	address := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	latency := time.Since(start).Milliseconds()

	result := PortResult{
		IP:      host,
		Port:    port,
		Open:    false,
		Latency: latency,
	}

	if err == nil {
		conn.Close()
		result.Open = true
	}

	return result
}

// FilterOpenPorts returns only the open port results
func FilterOpenPorts(results []PortResult) []PortResult {
	var open []PortResult
	for _, r := range results {
		if r.Open {
			open = append(open, r)
		}
	}
	return open
}

// GroupByHost groups port results by host IP
func GroupByHost(results []PortResult) map[string][]PortResult {
	groups := make(map[string][]PortResult)
	for _, r := range results {
		groups[r.IP] = append(groups[r.IP], r)
	}
	return groups
}
