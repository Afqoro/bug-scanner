package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Afqoro/bug-scanner/scanner"
)

func main() {
	operator := flag.String("operator", "telkomsel", "Operator name: telkomsel, xl, indosat, tri, smartfren, axis")
	asnQuery := flag.String("asn", "", "ASN/IP/org to lookup (e.g. 'AS7713' or '103.10.0.0/16' or 'PT Telekomunikasi Seluler')")
	customDNS := flag.String("dns", "", "Custom DNS resolver (default: operator's known DNS)")
	hostsFile := flag.String("hosts", "", "Custom hosts file (one host per line)")
	sniFile := flag.String("sni", "", "Custom SNI list file (one SNI per line)")
	portsStr := flag.String("ports", "", "Custom ports (comma-separated, e.g. '80,443,8080')")
	timeoutSec := flag.Int("timeout", 10, "Connection timeout in seconds")
	concurrency := flag.Int("concurrency", 50, "Max concurrent connections")
	skipDNS := flag.Bool("skip-dns", false, "Skip DNS enumeration phase")
	skipPort := flag.Bool("skip-port", false, "Skip port scanning phase")
	skipSNI := flag.Bool("skip-sni", false, "Skip SNI testing phase")
	skipWS := flag.Bool("skip-ws", false, "Skip WebSocket testing phase")
	skipFwd := flag.Bool("skip-fwd", false, "Skip forwarding test phase")
	useTLS := flag.Bool("tls", true, "Use TLS (wss/https) for WS and forwarding tests")
	outputJSON := flag.String("o", "", "Output JSON report to file")
	listOps := flag.Bool("list-operators", false, "List known operators and exit")
	flag.Parse()

	if *listOps {
		fmt.Println("Known operators:")
		for _, op := range []string{"telkomsel", "xl", "indosat", "tri", "smartfren", "axis"} {
			domains := scanner.GetOperatorDomains(op)
			dns := scanner.GetOperatorDNS(op)
			fmt.Printf("  %-12s DNS=%-16s domains=%d\n", op, dns, len(domains))
		}
		return
	}

	timeout := time.Duration(*timeoutSec) * time.Second
	report := scanner.NewScanReport()

	fmt.Println("\n╔══════════════════════════════════════╗")
	fmt.Println("║      BUG SCANNER v1.0                 ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Printf("  Operator: %s\n", *operator)
	fmt.Printf("  Timeout:  %ds\n", *timeoutSec)
	fmt.Printf("  Workers:  %d\n", *concurrency)

	// Phase 0: Region detection
	fmt.Println("\n[0/6] Detecting region...")
	region, err := scanner.DetectRegion()
	if err != nil {
		fmt.Printf("  ⚠ Region detection failed: %v\n", err)
	} else {
		report.Region = region
		report.ExitIP = region.IP
		fmt.Printf("  ✅ IP: %s\n", region.IP)
		fmt.Printf("  📍 %s\n", region.String())
		fmt.Printf("  🏢 %s (%s)\n", region.ISP, region.ASN)
	}

	// Phase 1: ASN lookup
	fmt.Println("\n[1/6] ASN lookup...")
	asnQ := *asnQuery
	if asnQ == "" {
		asnQ = *operator
	}
	asn, err := scanner.LookupASN(asnQ)
	if err != nil {
		fmt.Printf("  ⚠ ASN lookup failed: %v\n", err)
	} else if asn != nil {
		report.ASNResult = asn
		fmt.Printf("  AS: %s\n", asn.OrgName)
		fmt.Printf("  Prefixes: %d\n", len(asn.Prefixes))
		for i, p := range asn.Prefixes {
			if i >= 5 {
				fmt.Printf("    ... and %d more\n", len(asn.Prefixes)-5)
				break
			}
			fmt.Printf("    %s\n", p)
		}
	}

	// Phase 2: DNS enumeration
	if !*skipDNS {
		fmt.Println("\n[2/6] DNS enumeration...")
		domains := scanner.GetOperatorDomains(*operator)
		domains = append(domains, scanner.CommonWhitelistDomains...)
		dns := *customDNS
		if dns == "" {
			dns = scanner.GetOperatorDNS(*operator)
		}
		if dns != "" {
			fmt.Printf("  Resolver: %s\n", dns)
		} else {
			fmt.Println("  Resolver: system default")
		}
		fmt.Printf("  Domains: %d\n", len(domains))
		results := scanner.EnumerateDNS(domains, dns, timeout)
		report.DNSResults = results
		fmt.Printf("  ✅ Resolved: %d/%d\n", len(results), len(domains))
		for i, r := range results {
			if i >= 10 {
				fmt.Printf("    ... and %d more\n", len(results)-10)
				break
			}
			local := ""
			if r.HasLocal {
				local = " [LOCAL-ONLY]"
			}
			fmt.Printf("    %s → %v%s\n", r.Domain, r.Addresses, local)
		}
	}

	// Build host list for scanning
	hosts := buildHostList(report, *hostsFile)
	ports := scanner.DefaultPorts()
	if *portsStr != "" {
		ports = parsePorts(*portsStr)
	}

	// Phase 3: Port scan
	if !*skipPort && len(hosts) > 0 {
		fmt.Println("\n[3/6] Port scanning...")
		fmt.Printf("  Hosts: %d, Ports: %d\n", len(hosts), len(ports))
		portResults := scanner.ScanPorts(hosts, ports, timeout, *concurrency)
		report.PortResults = portResults
		openPorts := scanner.FilterOpenPorts(portResults)
		fmt.Printf("  ✅ Open: %d/%d\n", len(openPorts), len(portResults))
		for i, r := range openPorts {
			if i >= 20 {
				fmt.Printf("    ... and %d more\n", len(openPorts)-20)
				break
			}
			fmt.Printf("    %s:%d (%dms)\n", r.IP, r.Port, r.Latency)
		}
	}

	// Build SNI list
	sniList := buildSNIList(report, *sniFile)

	// Phase 4: SNI testing
	if !*skipSNI && len(hosts) > 0 && len(sniList) > 0 {
		fmt.Println("\n[4/6] SNI testing...")
		fmt.Printf("  Hosts: %d, SNI: %d\n", len(hosts), len(sniList))
		sniResults := scanner.TestSNIBatch(hosts, ports, sniList, timeout, *concurrency)
		report.SNIResults = sniResults
		success := scanner.FilterSuccessfulSNI(sniResults)
		fmt.Printf("  ✅ Success: %d/%d\n", len(success), len(sniResults))
		for i, r := range success {
			if i >= 15 {
				fmt.Printf("    ... and %d more\n", len(success)-15)
				break
			}
			fmt.Printf("    SNI=%s → %s:%d (%dms, %s)\n", r.SNI, r.Host, r.Port, r.Latency, r.TLSVer)
		}
	}

	// Phase 5: WebSocket testing
	if !*skipWS && len(hosts) > 0 {
		fmt.Println("\n[5/6] WebSocket testing...")
		wsPaths := scanner.DefaultWSPaths()
		fmt.Printf("  Hosts: %d, Paths: %d, TLS: %v\n", len(hosts), len(wsPaths), *useTLS)
		wsResults := scanner.TestWSBatch(hosts, ports, wsPaths, sniList, *useTLS, timeout, *concurrency)
		report.WSResults = wsResults
		success := scanner.FilterSuccessfulWS(wsResults)
		fmt.Printf("  ✅ Success: %d/%d\n", len(success), len(wsResults))
		for i, r := range success {
			if i >= 15 {
				fmt.Printf("    ... and %d more\n", len(success)-15)
				break
			}
			fmt.Printf("    %s:%d%s (SNI=%s, %dms)\n", r.Host, r.Port, r.Path, r.SNI, r.Latency)
		}
	}

	// Phase 6: Forwarding test
	if !*skipFwd && len(hosts) > 0 {
		fmt.Println("\n[6/6] Forwarding test...")
		fmt.Printf("  Hosts: %d, TLS: %v\n", len(hosts), *useTLS)
		fwdResults := scanner.TestForwardingBatch(hosts, ports, sniList, *useTLS, timeout, *concurrency)
		report.FwdResults = fwdResults
		success := scanner.FilterSuccessfulForward(fwdResults)
		fmt.Printf("  ✅ Forwardable: %d/%d\n", len(success), len(fwdResults))
		for i, r := range success {
			if i >= 10 {
				fmt.Printf("    ... and %d more\n", len(success)-10)
				break
			}
			fmt.Printf("    %s:%d (SNI=%s, status=%d, %dms)\n", r.Host, r.Port, r.SNI, r.Status, r.Latency)
		}
	}

	// Collect bugs
	report.Bugs = collectBugs(report)
	report.PrintSummary()

	if *outputJSON != "" {
		if err := report.SaveJSON(*outputJSON); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving JSON: %v\n", err)
		} else {
			fmt.Printf("\n📄 Report saved to: %s\n", *outputJSON)
		}
	}
}

func buildHostList(report *scanner.ScanReport, hostsFile string) []string {
	var hosts []string
	seen := make(map[string]bool)

	if hostsFile != "" {
		data, err := os.ReadFile(hostsFile)
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				h := strings.TrimSpace(line)
				if h != "" && !strings.HasPrefix(h, "#") && !seen[h] {
					hosts = append(hosts, h)
					seen[h] = true
				}
			}
		}
	}

	for _, dns := range report.DNSResults {
		for _, addr := range dns.Addresses {
			if !seen[addr] {
				hosts = append(hosts, addr)
				seen[addr] = true
			}
		}
	}

	if report.ASNResult != nil {
		for _, prefix := range report.ASNResult.Prefixes {
			if !seen[prefix] {
				hosts = append(hosts, prefix)
				seen[prefix] = true
			}
		}
	}

	return hosts
}

func buildSNIList(report *scanner.ScanReport, sniFile string) []string {
	var sniList []string
	seen := make(map[string]bool)

	if sniFile != "" {
		data, err := os.ReadFile(sniFile)
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				s := strings.TrimSpace(line)
				if s != "" && !strings.HasPrefix(s, "#") && !seen[s] {
					sniList = append(sniList, s)
					seen[s] = true
				}
			}
		}
	}

	for _, dns := range report.DNSResults {
		if !seen[dns.Domain] {
			sniList = append(sniList, dns.Domain)
			seen[dns.Domain] = true
		}
	}

	sniList = append(sniList, scanner.CommonWhitelistDomains...)
	return sniList
}

func parsePorts(s string) []int {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		var port int
		fmt.Sscanf(strings.TrimSpace(p), "%d", &port)
		if port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	return ports
}

func collectBugs(report *scanner.ScanReport) []scanner.BugResult {
	var bugs []scanner.BugResult
	regionStr := ""
	if report.Region != nil {
		regionStr = report.Region.String()
	}
	exitIP := ""
	if report.Region != nil {
		exitIP = report.Region.IP
	}

	for _, r := range scanner.FilterSuccessfulSNI(report.SNIResults) {
		bugs = append(bugs, scanner.BugResult{
			Type:      scanner.BugTypeSNI,
			Host:      r.Host,
			Port:      r.Port,
			SNI:       r.SNI,
			LatencyMs: r.Latency,
			Region:    regionStr,
			ExitIP:    exitIP,
			Works:     true,
			FoundAt:   report.Timestamp,
		})
	}

	for _, r := range scanner.FilterSuccessfulWS(report.WSResults) {
		bugs = append(bugs, scanner.BugResult{
			Type:      scanner.BugTypeWebSocket,
			Host:      r.Host,
			Port:      r.Port,
			SNI:       r.SNI,
			WSPath:    r.Path,
			LatencyMs: r.Latency,
			Region:    regionStr,
			ExitIP:    exitIP,
			Works:     true,
			FoundAt:   report.Timestamp,
		})
	}

	for _, r := range scanner.FilterSuccessfulForward(report.FwdResults) {
		bugs = append(bugs, scanner.BugResult{
			Type:      scanner.BugTypeHTTPProxy,
			Host:      r.Host,
			Port:      r.Port,
			SNI:       r.SNI,
			LatencyMs: r.Latency,
			Region:    regionStr,
			ExitIP:    exitIP,
			Works:     true,
			FoundAt:   report.Timestamp,
		})
	}

	return bugs
}
