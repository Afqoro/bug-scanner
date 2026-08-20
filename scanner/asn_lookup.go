package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ASNResult holds ASN lookup results
type ASNResult struct {
	ASN      string   `json:"asn"`
	OrgName  string   `json:"org_name"`
	Country  string   `json:"country"`
	NetRanges []string `json:"net_ranges"`
	Prefixes []string  `json:"prefixes"`
}

// LookupASN looks up ASN info for a given IP or organization name
func LookupASN(query string) (*ASNResult, error) {
	// Try IP-based lookup first
	if net.ParseIP(query) != nil {
		return lookupASNByIP(query)
	}
	// Otherwise treat as organization name search
	return lookupASNByOrg(query)
}

func lookupASNByIP(ip string) (*ASNResult, error) {
	url := fmt.Sprintf("https://api.iptoasn.com/v1/as/ip/%s", ip)
	resp, err := httpGetWithTimeout(url, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("iptoasn lookup failed: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		ASN     int    `json:"as_number"`
		Country string `json:"as_country"`
		OrgName string `json:"as_name"`
		Range   string `json:"as_range"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode iptosas json: %w", err)
	}

	return &ASNResult{
		ASN:       fmt.Sprintf("AS%d", data.ASN),
		OrgName:   strings.TrimSpace(data.OrgName),
		Country:   data.Country,
		NetRanges: []string{data.Range},
		Prefixes:  []string{data.Range},
	}, nil
}

func lookupASNByOrg(orgName string) (*ASNResult, error) {
	// Use RIPEstat API for organization-based prefix lookup
	orgLower := strings.ToLower(strings.ReplaceAll(orgName, " ", "+"))
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=%s", orgLower)
	resp, err := httpGetWithTimeout(url, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ripestat lookup failed: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
			Resource string `json:"resource"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode ripestat json: %w", err)
	}

	var prefixes []string
	for _, p := range data.Data.Prefixes {
		prefixes = append(prefixes, p.Prefix)
	}

	return &ASNResult{
		ASN:       data.Data.Resource,
		OrgName:   orgName,
		NetRanges: prefixes,
		Prefixes:  prefixes,
	}, nil
}

// LookupCurrentIP gets the current public IP and its ASN info
func LookupCurrentIP() (string, *ASNResult, error) {
	resp, err := httpGetWithTimeout("https://api.ipify.org?format=json", 10*time.Second)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get current IP: %w", err)
	}
	defer resp.Body.Close()

	var ipResp struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ipResp); err != nil {
		return "", nil, fmt.Errorf("decode ipify json: %w", err)
	}

	asn, err := LookupASN(ipResp.IP)
	if err != nil {
		return ipResp.IP, nil, err
	}

	return ipResp.IP, asn, nil
}

func httpGetWithTimeout(url string, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "BugScanner/1.0")
	return client.Do(req)
}

func httpGetBody(url string, timeout time.Duration) ([]byte, error) {
	resp, err := httpGetWithTimeout(url, timeout)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
