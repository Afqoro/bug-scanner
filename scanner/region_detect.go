package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RegionInfo holds geolocation info for the current exit IP
type RegionInfo struct {
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	ISP       string  `json:"isp"`
	ASN       string  `json:"asn"`
	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lon"`
}

// DetectRegion looks up the geolocation of the current public IP.
func DetectRegion() (*RegionInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := "http://ip-api.com/json/?fields=status,message,country,regionName,city,isp,as,lat,lon,query"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "BugScanner/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ip-api lookup failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read ip-api body: %w", err)
	}

	var data struct {
		Status  string  `json:"status"`
		Message string  `json:"message"`
		Country string  `json:"country"`
		Region  string  `json:"regionName"`
		City    string  `json:"city"`
		ISP     string  `json:"isp"`
		AS      string  `json:"as"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
		Query   string  `json:"query"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("decode ip-api json: %w", err)
	}

	if data.Status != "success" {
		return nil, fmt.Errorf("ip-api error: %s", data.Message)
	}

	return &RegionInfo{
		IP:        data.Query,
		Country:   data.Country,
		Region:    data.Region,
		City:      data.City,
		ISP:       data.ISP,
		ASN:       data.AS,
		Latitude:  data.Lat,
		Longitude: data.Lon,
	}, nil
}

// String returns a compact region string like "Indonesia, Jawa Timur, Surabaya"
func (r *RegionInfo) String() string {
	parts := []string{r.Country, r.Region}
	if r.City != "" {
		parts = append(parts, r.City)
	}
	return strings.Join(parts, ", ")
}

// ExtractASNNumber extracts just the AS number from a string like "AS7713 Telekomunikasi Seluler"
func ExtractASNNumber(asnField string) string {
	for i, c := range asnField {
		if c == ' ' {
			return asnField[:i]
		}
	}
	return asnField
}
