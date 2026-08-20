# 🐛 Bug Scanner

Tool untuk menemukan bug host/SNI/WebSocket pada operator seluler Indonesia. Dibangun dengan Go — single binary, ringan, cepat.

## Fitur

| Fase | Deskripsi |
|------|----------|
| **Region Detect** | Deteksi IP exit, ISP, dan regional otomatis |
| **ASN Lookup** | Cari IP range milik operator via RIPEstat & iptoasn |
| **DNS Enumeration** | Resolve domain-domain operator (MyTelkomsel, MyXL, dll) lewat DNS lokal operator |
| **Port Scanner** | Scan port umum proxy (80, 443, 8080, 8443, 2052, dll) |
| **SNI Tester** | Tes TLS handshake dengan SNI spoofing ke kandidat bug host |
| **WebSocket Tester** | Tes WS handshake ke berbagai path dengan SNI custom |
| **Forwarding Tester** | Tes apakah host bisa jadi HTTP CONNECT proxy |

## Instalasi

```bash
go build -o bug-scanner .
```

## Penggunaan

### Scan lengkap (semua fase)
```bash
./bug-scanner -operator telkomsel
```

### Scan operator tertentu
```bash
./bug-scanner -operator xl -timeout 15 -concurrency 100
```

### Skip fase tertentu
```bash
./bug-scanner -operator indosat -skip-dns -skip-port
```

### Custom wordlist
```bash
./bug-scanner -operator tri -hosts wordlists/hosts.txt -sni wordlists/sni_list.txt
```

### Custom ports
```bash
./bug-scanner -operator telkomsel -ports 80,443,8080,8443
```

### Tanpa TLS (ws:// bukan wss://)
```bash
./bug-scanner -operator smartfren -tls=false
```

### Output JSON report
```bash
./bug-scanner -operator telkomsel -o report.json
```

### List operator yang dikenal
```bash
./bug-scanner -list-operators
```

## Flags

| Flag | Default | Deskripsi |
|------|---------|----------|
| `-operator` | `telkomsel` | Operator: telkomsel, xl, indosat, tri, smartfren, axis |
| `-asn` | auto | ASN/IP/org untuk lookup |
| `-dns` | auto | DNS resolver custom |
| `-hosts` | | File daftar host custom |
| `-sni` | | File daftar SNI custom |
| `-ports` | default | Port custom (comma-separated) |
| `-timeout` | `10` | Timeout koneksi (detik) |
| `-concurrency` | `50` | Maks koneksi concurrent |
| `-skip-dns` | `false` | Skip DNS enumeration |
| `-skip-port` | `false` | Skip port scanning |
| `-skip-sni` | `false` | Skip SNI testing |
| `-skip-ws` | `false` | Skip WebSocket testing |
| `-skip-fwd` | `false` | Skip forwarding test |
| `-tls` | `true` | Gunakan TLS (wss/https) |
| `-o` | | Output JSON report |
| `-list-operators` | `false` | List operator dikenal |

## Operator yang Dikenal

| Operator | DNS Lokal | Domain App |
|----------|-----------|------------|
| Telkomsel | 10.134.82.62 | *.tsel.me, mytelkomsel.com, dll |
| XL/Axis | 10.16.42.42 | *.xl.co.id, *.axisworld.co.id |
| Indosat | 10.17.3.24 | *.indosatooredoo.com |
| Tri | 10.0.2.55 | *.tri.co.id, bima.tri.co.id |
| Smartfren | 10.18.3.18 | *.smartfren.com |

## Cara Kerja

1. **Region Detect**: Cek IP publik exit lewat ip-api.com → dapat ISP, regional, ASN
2. **ASN Lookup**: Cari prefix IP milik operator lewat RIPEstat
3. **DNS Enum**: Resolve domain-domain app operator lewat DNS lokal → dapat IP infrastruktur
4. **Port Scan**: Scan port umum proxy di semua IP yang ditemukan
5. **SNI Test**: Kirim TLS handshake dengan SNI = domain whitelist → cek apakah koneksi lolos
6. **WS Test**: Coba WebSocket upgrade ke host:port/path dengan SNI custom
7. **Forward Test**: Tes HTTP CONNECT → cek apakah bisa jadi proxy tunnel

## Kenapa Bug Milih Wilayah?

Operator Indonesia punya **GGSN/UPF regional** — traffic dari Jatim exit lewat IP pool berbeda dari Jabar. Konfigurasi billing/firewall per regional bisa tidak sinkron, jadi bug yang work di Jatim belum tentu work di Jabar.

Scanner ini otomatis mendeteksi regional saat scan, jalankan dari masing-masing wilayah untuk coverage penuh.

## Disclaimer

Tool ini untuk tujuan edukasi dan riset. Gunakan secara bertanggung jawab.

## License

MIT
