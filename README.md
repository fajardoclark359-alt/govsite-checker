# GovSite Checker

A government website uptime and security monitoring dashboard focused on Philippine government websites (`.gov.ph` domains).

## Features

- **Site Availability Checking** -- Concurrent HTTP probes with retry logic and failure classification (DNS, timeout, refused, TLS, WAF)
- **www-Fallback for Incomplete DNS** -- Many Philippine government domains only publish DNS records on the `www.` host (e.g. the bare `dti.gov.ph` has no A record; only `www.dti.gov.ph` resolves). The checker automatically tries a sequence of candidate URLs before declaring a site DOWN:
  1. Original URL
  2. Same scheme with `www.`-prefixed host
  3. `http://` with original host (catches HTTP-only sites that fail TLS)
  4. `http://` with `www.`-prefixed host
  
  A site is only reported **DOWN** when all candidates fail. The results also distinguish between: DOWN (all URL variants + DNS failed), HTTP error codes (site online but returning 4xx/5xx), and unreachable (timeout/refused/TLS errors).
- **Security Header Analysis** -- Checks for HSTS, CSP, and X-Frame-Options headers
- **Sensitive File Exposure Probing** -- Detects exposed `.git/config`, `.env`, `backup.zip`, `phpinfo.php`, and other sensitive paths
- **HaveIBeenPwned Breach Scanning** -- Optional domain breach lookup via HIBP API v3
- **Live Auto-Refresh** -- Continuous monitoring with configurable intervals (30s to 5m)
- **Export Reports** -- Export to real `.xlsx` (client-side generation), CSV, or clipboard

## OSINT Tools

| Tool | Description |
|------|-------------|
| IP Geolocation | Location, ISP, and ASN lookup via ip-api.com |
| WHOIS/RDAP Lookup | Registration dates, registrar, nameservers, status via RDAP |
| Email Header Analysis | Parses Received hops, origin IP geolocation, SPF/DKIM authentication |
| Domain Reputation | Suspicious TLD detection, phishing keyword analysis, typosquatting check |
| DNS Enumeration | A, AAAA, MX, NS, TXT, SOA, CNAME, SRV records + reverse DNS |
| SSL/TLS Certificate Analyzer | Certificate details, issuer, expiry, cipher, protocol version |
| Port Scanner | Common ports scan (22 ports) with concurrent probing and service detection |
| Technology Detection | Server, CMS, frameworks, analytics, CDN detection from headers and HTML |
| Subdomain Discovery | DNS-based subdomain enumeration against a list of common names |
| Google Dorking Helper | Pre-built dork queries (sensitive files, directory listings, login pages, etc.) |
| URLhaus Malware Check | Checks URLs against the URLhaus (abuse.ch) malware database |
| Reverse IP Lookup | Finds other domains hosted on the same IP via reverse DNS and HackerTarget |
| Security Headers Analysis | Comprehensive header audit with letter-grade scoring (HSTS, CSP, COOP, CORP, etc.) |

**Note:** DNS Enumeration and Subdomain Discovery rely on DNS-over-HTTPS queries to `dns.google` / `cloudflare-dns.com`. These tools require outbound HTTPS access.

## Prerequisites

- Python 3.7+
- `requests` library (`pip install requests`)

## Quick Start

```bash
# Option 1: Double-click start.bat (Windows)

# Option 2: Run directly in Python
python server.py
```

The server starts on `http://localhost:8000/` and opens automatically in your browser.

## Project Structure

```
govsite-checker/
  server.py          Backend: HTTP server with OSINT tools
  sites.json          Database of Philippine government websites
  start.bat           Windows launcher
  public/
    index.html        Dashboard UI
    app.js            Client-side JavaScript
    style.css         Styles
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/check` | Check site availability (body: `{urls, timeout}`) |
| POST | `/api/breach` | HIBP breach scan (body: `{domains, key}`) |
| POST | `/api/osint/ip-geolocate` | IP geolocation (body: `{ip}`) |
| POST | `/api/osint/whois` | WHOIS lookup (body: `{domain}`) |
| POST | `/api/osint/email-header` | Email header analysis (body: `{header}`) |
| POST | `/api/osint/domain-reputation` | Domain reputation check (body: `{domain}`) |
| POST | `/api/osint/dns` | DNS enumeration (body: `{domain}`) |
| POST | `/api/osint/ssl` | SSL/TLS certificate analysis (body: `{domain}`) |
| POST | `/api/osint/ports` | Port scanner (body: `{host}`) |
| POST | `/api/osint/tech` | Technology detection (body: `{url}`) |
| POST | `/api/osint/subdomains` | Subdomain discovery (body: `{domain}`) |
| POST | `/api/osint/dorks` | Google dorking helper (body: `{domain, engine}`) |
| POST | `/api/osint/urlhaus` | URLhaus malware check (body: `{url}`) |
| POST | `/api/osint/reverse-ip` | Reverse IP lookup (body: `{ip}`) |
| POST | `/api/osint/security-headers` | Security headers analysis (body: `{url}`) |
| GET | `/api/sites` | Returns the sites database |

## Developer

Clark Fajardo
