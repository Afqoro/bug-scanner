package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ScanReport holds the complete results of a scan session
type ScanReport struct {
	Timestamp    string          `json:"timestamp"`
	Region       *RegionInfo     `json:"region,omitempty"`
	ExitIP       string         `json:"exit_ip,omitempty"`
	ASNResult    *ASNResult     `json:"asn,omitempty"`
	DNSResults   []DNSResult    `json:"dns_results,omitempty"`
	PortResults  []PortResult   `json:"port_results,omitempty"`
	SNIResults   []SNITestResult `json:"sni_results,omitempty"`
	WSResults    []WSTestResult  `json:"ws_results,omitempty"`
	FwdResults    []ForwardResult  `json:"forward_results,omitempty"`
	WildResults   []WildcardResult `json:"wildcard_results,omitempty"`
	Bugs          []BugResult      `json:"bugs,omitempty"`
	Summary      ScanSummary    `json:"summary"`
}

type ScanSummary struct {
	TotalDNS   int `json:"total_dns"`
	TotalPorts int `json:"total_ports_open"`
	TotalSNI   int `json:"total_sni_success"`
	TotalWS    int `json:"total_ws_success"`
	TotalFwd   int `json:"total_forward_success"`
	TotalBugs  int `json:"total_bugs"`
}

// NewScanReport creates a report with current timestamp
func NewScanReport() *ScanReport {
	return &ScanReport{
		Timestamp: time.Now().Format(time.RFC3339),
	}
}

// ComputeSummary fills in the summary counts
func (r *ScanReport) ComputeSummary() {
	r.Summary.TotalDNS = len(r.DNSResults)
	r.Summary.TotalPorts = len(FilterOpenPorts(r.PortResults))
	r.Summary.TotalSNI = len(FilterSuccessfulSNI(r.SNIResults))
	r.Summary.TotalWS = len(FilterSuccessfulWS(r.WSResults))
	r.Summary.TotalFwd = len(FilterSuccessfulForward(r.FwdResults))
	r.Summary.TotalBugs = len(r.Bugs)
	// count wildcard too
	if len(r.WildResults) > 0 {
		r.Summary.TotalFwd += len(FilterSuccessfulWildcard(r.WildResults))
	}
}

// SaveJSON writes the report to a JSON file
func (r *ScanReport) SaveJSON(path string) error {
	r.ComputeSummary()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// PrintSummary prints a human-readable summary to stdout
func (r *ScanReport) PrintSummary() {
	r.ComputeSummary()
	fmt.Println()
	fmt.Println("════════════════════════════════════════")
	fmt.Println("  BUG SCANNER — SCAN SUMMARY")
	fmt.Println("════════════════════════════════════════")
	fmt.Printf("  Time: %s\n", r.Timestamp)
	if r.Region != nil {
		fmt.Printf("  Region: %s\n", r.Region.String())
		fmt.Printf("  Exit IP: %s\n", r.Region.IP)
		fmt.Printf("  ISP: %s (%s)\n", r.Region.ISP, r.Region.ASN)
	}
	fmt.Println("────────────────────────────────────────")
	fmt.Printf("  DNS Results:    %d\n", r.Summary.TotalDNS)
	fmt.Printf("  Open Ports:     %d\n", r.Summary.TotalPorts)
	fmt.Printf("  SNI Success:    %d\n", r.Summary.TotalSNI)
	fmt.Printf("  WS Success:     %d\n", r.Summary.TotalWS)
	fmt.Printf("  Forward OK:     %d\n", r.Summary.TotalFwd)
	fmt.Printf("  Bugs Found:     %d\n", r.Summary.TotalBugs)
	fmt.Println("════════════════════════════════════════")

	if len(r.Bugs) > 0 {
		fmt.Println("\n  🐛 BUGS FOUND:")
		for i, bug := range r.Bugs {
			fmt.Printf("  %d. %s\n", i+1, bug.String())
		}
	}
}

// PrintBugsAsTable prints found bugs in a compact table format
func PrintBugsAsTable(bugs []BugResult) {
	if len(bugs) == 0 {
		fmt.Println("  No bugs found.")
		return
	}
	fmt.Println()
	fmt.Printf("  %-6s %-40s %-8s %-8s\n", "TYPE", "DETAIL", "LATENCY", "REGION")
	fmt.Println(strings.Repeat("─", 70))
	for _, b := range bugs {
		var detail string
		switch b.Type {
		case BugTypeSNI:
			detail = fmt.Sprintf("SNI=%s → %s:%d", b.SNI, b.Host, b.Port)
		case BugTypeWebSocket:
			detail = fmt.Sprintf("WS %s:%d%s (SNI=%s)", b.Host, b.Port, b.WSPath, b.SNI)
		case BugTypeHTTPProxy:
			detail = fmt.Sprintf("PROXY %s:%d", b.Host, b.Port)
		default:
			detail = fmt.Sprintf("%s:%d", b.Host, b.Port)
		}
		fmt.Printf("  %-6s %-40s %-8d %-8s\n", strings.ToUpper(string(b.Type)), detail, b.LatencyMs, b.Region)
	}
}
