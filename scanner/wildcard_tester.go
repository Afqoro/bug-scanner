package scanner

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WildcardResult holds the result of a wildcard host test
type WildcardResult struct {
	WhitelistHost string `json:"whitelist_host"`
	WildcardHost  string `json:"wildcard_host"`
	Port          int    `json:"port"`
	WSPath        string `json:"ws_path"`
	Success       bool   `json:"success"`
	Status        int    `json:"status,omitempty"`
	Latency       int64  `json:"latency_ms"`
	Error         string `json:"error,omitempty"`
}

// Common wildcard server domains used by VPN/proxy providers
var CommonWildcardServers = []string{
	"mahavpn.web.id",
	"vpn.web.id",
	"tunnel.web.id",
	"proxy.web.id",
	"fastssh.com",
	"sshssh.com",
	"slotssh.com",
	"premiumssh.com",
	"fullssh.com",
	"cloudssh.net",
	"v2ray.com",
	"vmess.com",
	"trojan.com",
	"ssrsub.com",
	"akunssh.net",
	"myvpn.web.id",
	"freevpn.web.id",
	"jagoanssh.com",
	"creativessh.com",
	"sshdrops.com",
}

// Common WS paths used by wildcard configs
var CommonWSWildcardPaths = []string{
	"/alhamdulillah",
	"/vmess",
	"/vless",
	"/trojan",
	"/wss",
	"/ws",
	"/tunnel",
	"/proxy",
	"/bug",
	"/forward",
	"/ssh",
	"/vpn",
	"/fastssh",
	"/quila",
	"/buyung",
	"/alhamdulillah1",
	"/alhamdulillah2",
	"/mahavpn",
	"/jagoan",
	"/creatif",
}

// TestWildcard tests a wildcard host combination.
// It connects to whitelistHost:port (port 80, no TLS) and sends a WebSocket upgrade
// request with Host header = whitelistHost.wildcardServer, and path = wsPath.
// If the connection succeeds and gets a response, it's a potential wildcard bug.
func TestWildcard(whitelistHost, wildcardServer string, port int, wsPath string, timeout time.Duration) WildcardResult {
	wildcardHost := fmt.Sprintf("%s.%s", whitelistHost, wildcardServer)
	result := WildcardResult{
		WhitelistHost: whitelistHost,
		WildcardHost:  wildcardHost,
		Port:          port,
		WSPath:        wsPath,
	}

	address := fmt.Sprintf("%s:%d", whitelistHost, port)
	if !strings.HasPrefix(wsPath, "/") {
		wsPath = "/" + wsPath
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		result.Error = err.Error()
		result.Latency = time.Since(start).Milliseconds()
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send WS upgrade with wildcard Host header
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"User-Agent: Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36\r\n"+
			"\r\n",
		wsPath, wildcardHost,
	)

	_, err = conn.Write([]byte(req))
	if err != nil {
		result.Error = fmt.Sprintf("write: %v", err)
		result.Latency = time.Since(start).Milliseconds()
		return result
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	result.Latency = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = fmt.Sprintf("read: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.Status = resp.StatusCode

	// Success conditions for wildcard bug:
	// 101 = WS upgrade OK
	// 200 = server accepted and responded (some configs use non-standard)
	// Any non-4xx/5xx or 101 = potential bug
	if resp.StatusCode == 101 {
		result.Success = true
	} else if resp.StatusCode == 200 {
		upgrade := resp.Header.Get("Upgrade")
		connHdr := resp.Header.Get("Connection")
		if strings.EqualFold(upgrade, "websocket") ||
			strings.Contains(strings.ToLower(connHdr), "upgrade") {
			result.Success = true
		}
	}

	return result
}

// TestWildcardBatch tests all combinations of whitelist hosts × wildcard servers × ports × paths
func TestWildcardBatch(whitelistHosts, wildcardServers []string, ports []int, wsPaths []string, timeout time.Duration, concurrency int) []WildcardResult {
	var results []WildcardResult
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, wh := range whitelistHosts {
		for _, ws := range wildcardServers {
			for _, port := range ports {
				for _, path := range wsPaths {
					wg.Add(1)
					go func(w, s string, p int, pa string) {
						defer wg.Done()
						sem <- struct{}{}
						defer func() { <-sem }()

						res := TestWildcard(w, s, p, pa, timeout)
						mu.Lock()
						results = append(results, res)
						mu.Unlock()
					}(wh, ws, port, path)
				}
			}
		}
	}

	wg.Wait()
	return results
}

// FilterSuccessfulWildcard returns only wildcard tests that succeeded
func FilterSuccessfulWildcard(results []WildcardResult) []WildcardResult {
	var ok []WildcardResult
	for _, r := range results {
		if r.Success {
			ok = append(ok, r)
		}
	}
	return ok
}
