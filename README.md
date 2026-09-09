# GovSite Checker

A government website uptime and security monitoring dashboard focused on Philippine government websites (`.gov.ph` domains), with a full suite of OSINT reconnaissance tools.

> **Static demo on GitHub Pages:** https://fajardoclark359-alt.github.io/govsite-checker/
>
> The Pages site is a **static UI shell only** — GitHub Pages cannot run the
> Python backend, so the monitor and OSINT tools require running the server
> locally (see [Quick Start](#quick-start)).

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
| Email Header Analysis | Parses Received hops, origin IP geolocation, SPF/DKIM/DMARC authentication |
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

- Python 3.10+ (no framework — stdlib + `requests`)
- `requests` library (`pip install requests`)
- No `dig`/`nslookup` required — DNS tools use DNS-over-HTTPS

## Quick Start

```bash
# Option 1: Linux / macOS
./start.sh

# Option 2: Windows — double-click start.bat

# Option 3: Run directly
python3 server.py
```

The server starts on `http://localhost:8000/` and opens automatically in your browser (when a graphical session is present).

### Smoke test

```bash
python3 -c "import sys; sys.path.insert(0,'.'); import server; print('OK')"
```

## Project Structure

```
govsite-checker/
  server.py            Backend: Python http.server + requests, all OSINT tools
  sites.json           Database of Philippine government websites (175 entries)
  start.sh             Linux / macOS launcher
  start.bat            Windows launcher
  AGENTS.md            Maintainer notes (conventions, gotchas)
  public/
    index.html         Dashboard UI (monitor + OSINT tabs)
    app.js             Client-side JavaScript (vanilla, no build step)
    style.css          Styles
  .github/workflows/   GitHub Actions -> static GitHub Pages deploy
```

## Deployment

### Local (full functionality)

```bash
python3 server.py   # http://localhost:8000
```

All features work locally: site monitoring, breach scanning, export reports, and every OSINT tool.

### GitHub Pages (static shell)

The repo includes `.github/workflows/pages.yml`, which publishes the `public/`
directory to GitHub Pages on every push to `master`. See the note at the top of
this file: the Pages site renders the UI but cannot perform checks or lookups,
because GitHub Pages only serves static files and the backend runs in Python.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/check` | Check site availability (body: `{urls, timeout}`) |
| POST | `/api/breach` | HIBP breach scan (body: `{domains, key}`) |
| POST | `/api/osint/ip-geolocate` | IP geolocation (body: `{ip}`) |
| POST | `/api/osint/reverse-ip` | Reverse IP lookup (body: `{ip}`) |
| POST | `/api/osint/whois` | WHOIS lookup (body: `{domain}`) |
| POST | `/api/osint/dns` | DNS enumeration (body: `{domain}`) |
| POST | `/api/osint/ssl` | SSL/TLS certificate analysis (body: `{domain, port?}`) |
| POST | `/api/osint/ports` | Port scanner (body: `{domain, ports?}`) |
| POST | `/api/osint/tech` | Technology detection (body: `{url}`) |
| POST | `/api/osint/subdomains` | Subdomain discovery (body: `{domain}`) |
| POST | `/api/osint/security-headers` | Security headers analysis (body: `{url}`) |
| POST | `/api/osint/dorks` | Google dorking helper (body: `{domain}`) |
| POST | `/api/osint/urlhaus` | URLhaus malware check (body: `{url}`) |
| POST | `/api/osint/email-header` | Email header analysis (body: `{header}`) |
| POST | `/api/osint/domain-reputation` | Domain reputation check (body: `{domain}`) |
| GET | `/api/sites` | Returns the sites database |

All `POST` endpoints accept JSON bodies (`Content-Type: application/json`).

## Developer

Clark Fajardo
