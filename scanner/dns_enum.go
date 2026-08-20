package scanner

import (
	"context"
	"net"
	"strings"
	"time"
)

// DNSResult holds DNS enumeration results
type DNSResult struct {
	Domain    string   `json:"domain"`
	Resolver  string   `json:"resolver"`
	Addresses []string `json:"addresses"`
	CNAMEs    []string `json:"cnames"`
	HasLocal  bool     `json:"has_local_only"`
}

// Known operator app domains for DNS enumeration
var OperatorAppDomains = map[string][]string{
	"telkomsel": {
		"ace.tsel.me", "video.tsel.me", "cdn.tsel.me", "api.tsel.me",
		"mytelkomsel.com", "app.mytelkomsel.com", "m.tsel.me",
		"flash.tsel.me", "music.tsel.me", "games.tsel.me",
		"video.tsel-cdn.com", "static.tsel-cdn.com", "ssp.tsel.me",
		"uns.tsel.me", "luck.tsel.me", "dunia.tsel.me",
	},
	"xl": {
		"api.xlaxiata.co.id", "my.xl.co.id", "cdn.xl.co.id",
		"app.xl.co.id", "video.xl.co.id", "music.xl.co.id",
		"games.xl.co.id", "uns.xl.co.id", "static.xl.co.id",
		"media.xl.co.id", "portal.xl.co.id", "ssp.xl.co.id",
	},
	"indosat": {
		"api.indosatooredoo.com", "my.indosatooredoo.com",
		"cdn.indosatooredoo.com", "app.indosatooredoo.com",
		"video.indosatooredoo.com", "music.indosatooredoo.com",
		"games.indosatooredoo.com", "static.indosatooredoo.com",
		"media.indosatooredoo.com", "portal.indosatooredoo.com",
	},
	"tri": {
		"api.tri.co.id", "my.tri.co.id", "cdn.tri.co.id",
		"app.tri.co.id", "video.tri.co.id", "music.tri.co.id",
		"games.tri.co.id", "static.tri.co.id", "media.tri.co.id",
		"portal.tri.co.id", "bima.tri.co.id", "shop.tri.co.id",
	},
	"smartfren": {
		"api.smartfren.com", "my.smartfren.com", "cdn.smartfren.com",
		"app.smartfren.com", "video.smartfren.com", "music.smartfren.com",
		"games.smartfren.com", "static.smartfren.com", "media.smartfren.com",
		"portal.smartfren.com", "shop.smartfren.com",
	},
	"axis": {
		"api.axisworld.co.id", "my.axisworld.co.id", "cdn.axisworld.co.id",
		"app.axisworld.co.id", "video.axisworld.co.id", "music.axisworld.co.id",
		"static.axisworld.co.id", "media.axisworld.co.id",
		"portal.axisworld.co.id", "shop.axisworld.co.id",
	},
}

// Common CDN/whitelist domains that operators often allow without billing
var CommonWhitelistDomains = []string{
	"connectivitycheck.gstatic.com",
	"www.google.com",
	"www.facebook.com",
	"m.facebook.com",
	"graph.facebook.com",
	"edge-chat.facebook.com",
	"edge-snapshots.facebook.com",
	"static.xx.fbcdn.net",
	"video.xx.fbcdn.net",
	"www.instagram.com",
	"graph.instagram.com",
	"scontent.cdninstagram.com",
	"www.tiktokv.com",
	"mssdk.tiktokv.com",
	"api.tiktokv.com",
	"www.whatsapp.net",
	"static.whatsapp.net",
	"e1.whatsapp.net",
	"g.whatsapp.net",
	"www.youtube.com",
	"i.ytimg.com",
	"googlevideo.com",
	"play.google.com",
	"android.clients.google.com",
	"www.googleapis.com",
	"firebaseinstallations.googleapis.com",
	"firebaselogging.googleapis.com",
	"fcm.googleapis.com",
	"api.telegram.org",
	"telegram.org",
	"cdn.telegram.org",
	"dns.google",
	"cloudflare-dns.com",
	"www.cloudflare.com",
	"api.twitter.com",
	"abs.twimg.com",
	"pbs.twimg.com",
	"api.x.com",
	"edge.twitch.tv",
	"www.linkedin.com",
	"static.licdn.com",
	"api.spotify.com",
	"scdn.line-apps.com",
	"tim.line.me",
	"obs.line.me",
	"www.dailymotion.com",
	"www.netflix.com",
	"nflxvideo.net",
	"assets.nflxext.com",
	"cdn-hls.netflix.com",
	"www.disneyplus.com",
	"disneyplus.com",
	"apps.apple.com",
	"play-lh.googleusercontent.com",
	"fonts.gstatic.com",
	"fonts.googleapis.com",
	"i.instagramstatic.com",
	"snap.licdn.com",
}

// EnumerateDNS resolves domains using a specific DNS resolver (e.g. operator's DNS)
func EnumerateDNS(domains []string, resolver string, timeout time.Duration) []DNSResult {
	var results []DNSResult
	resolverAddr := resolver
	if !strings.Contains(resolver, ":") {
		resolverAddr = resolver + ":53"
	}

	for _, domain := range domains {
		result := DNSResult{
			Domain:   domain,
			Resolver: resolver,
		}

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", resolverAddr)
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		addrs, err := r.LookupHost(ctx, domain)
		cancel()

		if err == nil && len(addrs) > 0 {
			result.Addresses = addrs
		}

		ctx2, cancel2 := context.WithTimeout(context.Background(), timeout)
		cnames, err := r.LookupCNAME(ctx2, domain)
		cancel2()
		if err == nil && cnames != "" {
			result.CNAMEs = []string{cnames}
		}

		// Check if domain resolves locally but not publicly
		publicAddrs, pubErr := net.LookupHost(domain)
		if len(result.Addresses) > 0 && (pubErr != nil || len(publicAddrs) == 0) {
			result.HasLocal = true
		}

		if len(result.Addresses) > 0 || len(result.CNAMEs) > 0 {
			results = append(results, result)
		}
	}

	return results
}

// GetOperatorDNS returns common operator DNS resolvers
func GetOperatorDNS(operator string) string {
	switch strings.ToLower(operator) {
	case "telkomsel", "tsel":
		return "10.134.82.62"
	case "xl", "axis":
		return "10.16.42.42"
	case "indosat", "im3":
		return "10.17.3.24"
	case "tri", "3":
		return "10.0.2.55"
	case "smartfren":
		return "10.18.3.18"
	default:
		return ""
	}
}

// GetOperatorDomains returns known app domains for an operator
func GetOperatorDomains(operator string) []string {
	key := strings.ToLower(operator)
	if domains, ok := OperatorAppDomains[key]; ok {
		return domains
	}
	return nil
}
