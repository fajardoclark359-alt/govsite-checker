#!/usr/bin/env python3
"""
GovSite Checker - Government Website Monitor
Python backend replacing the PowerShell/C# version.
"""

import json
import os
import re
import sys
import time
import socket
import ssl
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------- config ----------
ROOT = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.join(ROOT, "public")
SITES_JSON = os.path.join(ROOT, "sites.json")
PORT = 8000

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"


# ---------- HTTP client factory ----------
def make_client(timeout_sec):
    """Create a requests Session with realistic browser headers."""
    s = requests.Session()
    retry = Retry(total=0)
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=20)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": USER_AGENT})
    s.timeout = timeout_sec
    return s


def normalize_url(url):
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url


# ---------- site checker ----------
def _candidate_urls(url):
    """Generate URL fallbacks so slow/broken-DNS gov sites still get checked.

    Many Philippine gov domains only publish DNS (A/AAAA) records on the
    ``www`` host (e.g. ``www.dti.gov.ph`` exists but the bare ``dti.gov.ph``
    does not resolve). IEEE 754 advice: a bare apex with no record is common.
    Order tried:
      1. original URL (https preferred)
      2. same scheme, host prefixed with ``www.``
      3. http scheme, original host
      4. http scheme, ``www.`` host
    """
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme
    netloc = parsed.netloc
    port = f":{parsed.port}" if parsed.port else ""
    www_netloc = None
    if host and not host.lower().startswith("www.") and "." in host:
        www_netloc = "www." + host + port

    candidates = [url]
    if www_netloc and www_netloc != netloc:
        candidates.append(
            urllib.parse.urlunsplit((scheme, www_netloc, parsed.path, parsed.query, ""))
        )
    if scheme == "https":
        # HTTP-only gov sites fail the TLS handshake; retry plain HTTP.
        candidates.append(
            urllib.parse.urlunsplit(("http", netloc, parsed.path, parsed.query, ""))
        )
        if www_netloc and www_netloc != netloc:
            candidates.append(
                urllib.parse.urlunsplit(("http", www_netloc, parsed.path, parsed.query, ""))
            )
    # dedupe, keep order
    seen, out = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _host_resolves(host):
    """Return True if the host has at least one A/AAAA record."""
    if not host:
        return False
    try:
        addrs = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
        return len(addrs) > 0
    except Exception:
        return False


def check_one(client, url, timeout_sec):
    """Check a single URL: HTTP status + security headers + exposure probes.

    Tries ``www.``/http URL fallbacks before declaring a site DOWN so that
    reachable-but-poorly-DNS'd government sites are not mis-flagged.
    """
    url = normalize_url(url)
    d = {
        "url": url, "usedUrl": url, "status": "DOWN", "reachable": False,
        "code": 0, "ms": 0, "error": "", "dns": True, "httpNote": "",
        "tries": 1, "downReason": "", "hsts": 0, "csp": 0, "xframe": 0,
        "exposed": [],
    }

    last_err = ""
    got_response = False
    sw = time.monotonic()
    attempts = 0

    for candidate in _candidate_urls(url):
        if candidate != url:
            d.setdefault("fallbacksUsed", [])
            d["fallbacksUsed"].append(candidate)
        for attempt in range(2):
            attempts += 1
            try:
                resp = client.get(candidate, timeout=timeout_sec,
                                  allow_redirects=True, verify=False)
                code = resp.status_code
                got_response = True
                d["usedUrl"] = candidate
                d["code"] = code
                d["reachable"] = True
                if 200 <= code <= 299:
                    d["httpNote"] = "OK"
                elif 300 <= code <= 399:
                    d["httpNote"] = "Redirect"
                elif 400 <= code <= 499:
                    d["httpNote"] = f"Online but restricted (HTTP {code})"
                elif code >= 500:
                    d["httpNote"] = f"Server reported an error (HTTP {code})"
                if candidate.lower().startswith("https://"):
                    d["usesTls"] = 1
                if "strict-transport-security" in resp.headers:
                    d["hsts"] = 1
                if "content-security-policy" in resp.headers:
                    d["csp"] = 1
                if "x-frame-options" in resp.headers:
                    d["xframe"] = 1
                break
            except Exception as ex:
                last_err = str(ex)
                d["tries"] = attempts
                detect_reason(d, ex)
        if got_response:
            break

    d["ms"] = int((time.monotonic() - sw) * 1000)

    if got_response:
        d["status"] = "UP"
    else:
        d["error"] = last_err
        # verify DNS: bare host first, then www fallback
        base_host = urllib.parse.urlparse(url).hostname
        dns_hosts = [base_host]
        if base_host and not base_host.lower().startswith("www."):
            dns_hosts.append("www." + base_host)
        for h in dns_hosts:
            if _host_resolves(h):
                d["dns"] = True
                break
        else:
            d["dns"] = False
        if not d["dns"]:
            d["error"] = "DNS resolution failed - domain does not resolve"

    d["remark"] = _build_remark(d, url, timeout_sec, last_err)

    # exposure probe against the URL that actually worked
    if got_response:
        base = d["usedUrl"]
        paths = ["/.git/config", "/.env", "/.env.bak", "/backup.zip",
                 "/server-status", "/.DS_Store", "/phpinfo.php"]
        exposed = []
        prober = make_client(4)
        try:
            with ThreadPoolExecutor(max_workers=7) as pool:
                futures = {pool.submit(probe, prober, base, p): p for p in paths}
                for f in as_completed(futures):
                    result = f.result()
                    if result:
                        exposed.append(result)
        finally:
            prober.close()
        exposed.sort()
        d["exposed"] = exposed

    return d


def _build_remark(d, url, timeout_sec, last_err):
    """Human-readable note explaining a site's UP/DOWN status context."""
    fb = d.get("fallbacksUsed") or []
    if d["status"] == "UP":
        if d["usedUrl"] != url:
            return ("Served at %s - the configured URL (%s) did not respond "
                    "directly. Common for PH gov sites whose bare apex has no "
                    "DNS record.") % (d["usedUrl"], url)
        return "Responded directly at the configured URL."

    tried = len(fb) + 1
    parts = ["Checked %d URL variant(s)" % tried]
    if fb:
        parts.append(": " + " -> ".join(fb))
    else:
        parts.append(" (as configured).")
    if not d["dns"]:
        parts.append(" Hostname has NO DNS records on either the apex or www. "
                     "This is a DNS problem, not slowness.")
    elif d["downReason"] == "timeout":
        parts.append(" Hostname resolves, but the server gave no answer "
                     "within %ss - likely offline, geo-blocked, or firewalled."
                     % timeout_sec)
    elif d["downReason"] == "tls":
        parts.append(" Hostname resolves, but the TLS/HTTPS handshake failed. "
                     "Check the HTTP fallback above / browser behavior.")
    elif d["downReason"] == "refused":
        parts.append(" Hostname resolves, but the connection was refused "
                     "(nothing listening, or port filtered).")
    elif d["downReason"] == "reset":
        parts.append(" Hostname resolves, but the connection was dropped/reset "
                     "(WAF or bot-filtering).")
    else:
        parts.append(" Last error: %s" % (last_err or "no response"))
    return "".join(parts)


def detect_reason(d, ex):
    """Classify why a host is unreachable."""
    r = "other"
    err_str = str(ex).lower()
    type_name = type(ex).__name__

    if type_name in ("Timeout", "ReadTimeout", "ConnectionError"):
        if "timeout" in err_str or type_name == "Timeout":
            r = "timeout"
        elif "refused" in err_str:
            r = "refused"
        elif "reset" in err_str or "closed" in err_str:
            r = "reset"
        elif "ssl" in err_str or "tls" in err_str or "certificate" in err_str:
            r = "tls"
        else:
            r = "refused"
    elif "ssl" in err_str or "tls" in err_str or "certificate" in err_str:
        r = "tls"
    elif "timeout" in err_str:
        r = "timeout"
    elif "refused" in err_str:
        r = "refused"
    elif "reset" in err_str or "closed" in err_str:
        r = "reset"
    elif "io" in type_name.lower():
        r = "reset"
    elif "auth" in type_name.lower():
        r = "tls"

    d["downReason"] = r


def probe(client, base_url, path):
    """Check if a sensitive path is exposed (returns 200)."""
    url = base_url.rstrip("/") + path
    try:
        resp = client.get(url, timeout=4, verify=False)
        if resp.status_code == 200:
            return path
    except Exception:
        pass
    return None


# ---------- breach check ----------
def breach_check(domains_raw, api_key):
    """Check domains against HaveIBeenPwned."""
    domains = [d.strip().lower() for d in domains_raw.split("\n") if d.strip()]
    results = []
    headers = {"User-Agent": "GovSiteChecker/1.0"}
    if api_key:
        headers["hibp-api-key"] = api_key

    for dom in domains:
        dd = {"domain": dom}
        if not api_key:
            dd["note"] = "No HIBP key set; using local exposure scan only"
        else:
            try:
                resp = requests.get(
                    f"https://haveibeenpwned.com/api/v3/domainsearch/{urllib.parse.quote(dom, safe='')}",
                    headers=headers, timeout=12
                )
                if resp.status_code == 200:
                    data = resp.json()
                    names = [item.get("Name", "") for item in data if isinstance(item, dict) and "Name" in item]
                    dd["breached"] = len(names) > 0
                    dd["names"] = names
                elif resp.status_code == 404:
                    dd["breached"] = False
                    dd["names"] = []
                elif resp.status_code == 401:
                    dd["note"] = "HIBP: invalid or unauthorized API key"
                elif resp.status_code == 429:
                    dd["note"] = "HIBP: rate limited (free tier)"
                else:
                    dd["note"] = f"HIBP: HTTP {resp.status_code}"
            except Exception as ex:
                dd["note"] = f"HIBP error: {ex}"
        results.append(dd)
    return results


# ---------- OSINT: IP geolocation ----------
def geolocate_ip(ip):
    ip = ip.strip()
    d = {"query": ip}
    if not ip:
        d["error"] = "Please enter an IP address"
        return d
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{urllib.parse.quote(ip, safe='')}",
            headers={"User-Agent": USER_AGENT}, timeout=10
        )
        data = resp.json()
        if data.get("status") == "fail":
            d["error"] = data.get("message", "Lookup failed - invalid IP or API error")
            return d
        for k in ("query", "country", "countryCode", "region", "regionName",
                   "city", "zip", "lat", "lon", "timezone", "isp", "org", "as"):
            if k in data:
                d[k] = data[k]
    except Exception as ex:
        d["error"] = f"Connection error: {ex}"
    return d


# ---------- OSINT: WHOIS via RDAP ----------
def fetch_rdap_data(domain):
    """Shared RDAP data fetcher."""
    try:
        resp = requests.get(
            f"https://rdap.org/domain/{urllib.parse.quote(domain, safe='')}",
            headers={"User-Agent": "GovSiteChecker/1.0"}, timeout=8
        )
        if resp.status_code != 200:
            return None
        parsed = resp.json()
        result = {}

        # events
        for ev in parsed.get("events", []):
            action = ev.get("eventAction", "")
            date = ev.get("eventDate", "")
            if action == "registration":
                result["created"] = date
            elif action == "expiration":
                result["expires"] = date
            elif action == "last update of RDAP database":
                result["updated"] = date

        # entities/vcard (registrar)
        for ent in parsed.get("entities", []):
            vcard = ent.get("vcardArray")
            if vcard and len(vcard) > 1:
                for f in vcard[1]:
                    if isinstance(f, list) and len(f) >= 3:
                        if f[0] == "fn":
                            result["registrar"] = f[3] if len(f) > 3 else ""

        # status
        statuses = parsed.get("status")
        if statuses:
            result["status"] = [s for s in statuses if isinstance(s, str)]

        # nameservers
        ns_arr = parsed.get("nameservers")
        if ns_arr:
            result["nameServers"] = [ns.get("ldhName", "") for ns in ns_arr
                                     if isinstance(ns, dict) and "ldhName" in ns]

        # raw text
        body = resp.text
        result["rawText"] = body[:3000] + "..." if len(body) > 3000 else body
        return result
    except Exception:
        return None


def whois_lookup(domain):
    domain = domain.strip().lower().strip(".")
    d = {"domain": domain}
    rdap = fetch_rdap_data(domain)
    if rdap:
        for k in ("created", "expires", "updated", "registrar", "status", "nameServers", "rawText"):
            if k in rdap:
                d[k] = rdap[k]
    else:
        d["error"] = "Domain not found in RDAP database"
    return d


# ---------- OSINT: Email header analysis ----------
def analyze_email_header(header_text):
    d = {}
    try:
        lines = re.split(r"\r\n|\n|\r", header_text)
        lines = [l for l in lines if l.strip()]

        for line in lines:
            if line.lower().startswith("from:"):
                d["from"] = line[5:].strip()
            elif line.lower().startswith("to:"):
                d["to"] = line[3:].strip()
            elif line.lower().startswith("subject:"):
                d["subject"] = line[8:].strip()
            elif line.lower().startswith("date:"):
                d["date"] = line[5:].strip()

        # Parse Received headers (reverse order)
        hops = []
        received_lines = []
        for line in reversed(lines):
            if line.lower().startswith("received:"):
                received_lines.append(line[9:].strip())
            elif received_lines and (line[0] in " \t"):
                received_lines[-1] += " " + line.strip()

        for recv in received_lines:
            hop = {}
            # from
            m = re.search(r'\bfrom\s+(\S+)', recv, re.IGNORECASE)
            if m:
                hop["from"] = m.group(1)
            # by
            m = re.search(r'\bby\s+(\S+)', recv, re.IGNORECASE)
            if m:
                hop["by"] = m.group(1)
            # IP in brackets
            m = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', recv)
            if m:
                hop["ip"] = m.group(1)
            # date after semicolon
            semi = recv.rfind(";")
            if semi >= 0:
                date_part = recv[semi + 1:].strip()
                if 5 < len(date_part) < 80:
                    hop["date"] = date_part
            if "from" in hop or "by" in hop:
                hops.append(hop)

        d["hops"] = hops

        # Origin IP geolocation
        if hops and "ip" in hops[0]:
            origin_ip = hops[0]["ip"]
            d["originIp"] = origin_ip
            try:
                geo = geolocate_ip(origin_ip)
                if "error" not in geo:
                    city = geo.get("city", "")
                    region = geo.get("regionName", "")
                    country = geo.get("country", "")
                    parts = [p for p in [city, region, country] if p]
                    d["originLocation"] = ", ".join(parts)
                    d["originIsp"] = geo.get("isp", "")
            except Exception:
                pass

        # Authentication headers
        auth = {}
        for line in lines:
            if line.lower().startswith("authentication-results:"):
                results = line[23:]
                m = re.search(r'spf=(\S+)', results, re.IGNORECASE)
                if m:
                    val = m.group(1).rstrip(";")
                    auth["spf"] = val
                    auth["spfResult"] = "pass" if val.lower() == "pass" else "fail"
                m = re.search(r'dkim=(\S+)', results, re.IGNORECASE)
                if m:
                    val = m.group(1).rstrip(";")
                    auth["dkim"] = val
                    auth["dkimResult"] = "pass" if val.lower() == "pass" else "fail"
                m = re.search(r'dmarc=(\S+)', results, re.IGNORECASE)
                if m:
                    val = m.group(1).rstrip(";")
                    auth["dmarc"] = val
                    auth["dmarcResult"] = "pass" if val.lower().startswith("pass") else "fail"
            elif line.lower().startswith("dkim-signature:"):
                auth.setdefault("dkim", "present")
            elif line.lower().startswith("arc-authentication-results:"):
                auth.setdefault("spf", "see ARC header")

        if auth:
            d["auth"] = auth
    except Exception as ex:
        d["error"] = str(ex)
    return d


# ---------- OSINT: Domain reputation ----------
def check_domain_reputation(domain):
    domain = domain.strip().lower().strip(".")
    d = {
        "domain": domain, "safe": True, "threats": [], "categories": [],
        "blacklisted": False,
    }

    # DNS liveness
    resolves = False
    try:
        addrs = socket.getaddrinfo(domain, None, socket.AF_UNSPEC)
        resolves = len(addrs) > 0
    except Exception:
        pass

    # suspicious TLDs
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    suspicious_tlds = {"xyz", "top", "club", "online", "site", "work", "biz",
                       "info", "buzz", "tk", "ml", "ga", "cf", "gq"}
    threats = []
    categories = []
    if tld in suspicious_tlds:
        threats.append(f"Suspicious TLD ({tld})")
        categories.append("High-risk TLD")

    # phishing keywords
    if any(kw in domain for kw in ("login", "verify", "secure", "account", "update")):
        if len(domain) > 20:
            threats.append("Possible phishing keyword pattern")
            categories.append("Phishing risk")

    # typosquatting
    known_brands = ["google", "facebook", "apple", "microsoft", "amazon",
                    "paypal", "netflix", "instagram", "twitter"]
    for brand in known_brands:
        if brand in domain and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.org"):
            threats.append(f"Possible typosquatting of {brand}")
            categories.append("Brand impersonation")
            break

    # RDAP for registrar info
    rdap = fetch_rdap_data(domain)
    if rdap:
        if "created" in rdap:
            d["created"] = rdap["created"]
        if "registrar" in rdap:
            d["registrar"] = rdap["registrar"]

    d["resolves"] = resolves
    d["threats"] = threats
    d["categories"] = categories
    if threats:
        d["safe"] = False
        d["blacklisted"] = True
    return d


# ================================================================
# ADVANCED OSINT TOOLS
# ================================================================

# ---------- OSINT: DNS Enumeration ----------
def _dns_query(domain, rtype):
    """Query DNS records using Python socket and requests."""
    results = []

    if rtype == "A":
        try:
            addrs = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            results = list(set(a[4][0] for a in addrs))
        except Exception:
            pass
    elif rtype == "AAAA":
        try:
            addrs = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
            results = list(set(a[4][0] for a in addrs))
        except Exception:
            pass
    elif rtype in ("MX", "NS", "CNAME", "SOA", "SRV"):
        if rtype == "MX":
            try:
                addrs = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
                mx_hosts = list(set(a[4][0] for a in addrs))
                for prefix in ["mail", "mx", "mx1", "mx2", "smtp"]:
                    fqdn = f"{prefix}.{domain}"
                    try:
                        ip = socket.gethostbyname(fqdn)
                        results.append(f"10 {fqdn}. ({ip})")
                    except Exception:
                        pass
            except Exception:
                pass
        elif rtype == "NS":
            for prefix in ["ns1", "ns2", "ns3", "ns4", "dns1", "dns2"]:
                fqdn = f"{prefix}.{domain}"
                try:
                    ip = socket.gethostbyname(fqdn)
                    results.append(f"{fqdn}. ({ip})")
                except Exception:
                    pass
        elif rtype == "SOA":
            try:
                resp = requests.get(
                    f"https://dns.google/resolve?name={domain}&type=SOA",
                    timeout=3
                )
                data = resp.json()
                for ans in data.get("Answer", []):
                    if ans.get("type") == 6:
                        results.append(ans.get("data", ""))
            except Exception:
                pass
        elif rtype == "CNAME":
            try:
                resp = requests.get(
                    f"https://dns.google/resolve?name={domain}&type=CNAME",
                    timeout=3
                )
                data = resp.json()
                for ans in data.get("Answer", []):
                    if ans.get("type") == 5:
                        results.append(ans.get("data", ""))
            except Exception:
                pass
        elif rtype == "SRV":
            for service in ["_sip._tcp", "_xmpp-client._tcp", "_autodiscover._tcp"]:
                fqdn = f"{service}.{domain}"
                try:
                    resp = requests.get(
                        f"https://dns.google/resolve?name={fqdn}&type=SRV",
                        timeout=3
                    )
                    data = resp.json()
                    for ans in data.get("Answer", []):
                        if ans.get("type") == 33:
                            results.append(f"{fqdn}: {ans.get('data', '')}")
                except Exception:
                    pass
    elif rtype == "TXT":
        try:
            resp = requests.get(
                f"https://dns.google/resolve?name={domain}&type=TXT",
                timeout=3
            )
            data = resp.json()
            for ans in data.get("Answer", []):
                if ans.get("type") == 16:
                    txt = ans.get("data", "").strip('"')
                    results.append(txt)
        except Exception:
            pass
    return results


def dns_enumerate(domain):
    """Full DNS record enumeration: A, AAAA, MX, NS, TXT, SOA, CNAME."""
    domain = domain.strip().lower().strip(".")
    d = {"domain": domain}

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]
    records = {}
    a_records = _dns_query(domain, "A")
    if a_records:
        records["A"] = a_records
    for rtype in record_types:
        if rtype == "A":
            continue
        answers = _dns_query(domain, rtype)
        if answers:
            records[rtype] = answers
    d["records"] = records
    d["totalRecords"] = sum(len(v) for v in records.values())

    # Reverse DNS for A records
    reverse_dns = []
    for ip in records.get("A", []):
        try:
            host = socket.gethostbyaddr(ip)
            reverse_dns.append({"ip": ip, "hostname": host[0]})
        except Exception:
            reverse_dns.append({"ip": ip, "hostname": None})
    d["reverseDns"] = reverse_dns
    return d


# ---------- OSINT: SSL/TLS Certificate Analysis ----------
def _decode_cert_der(der_bytes):
    """Decode a DER-encoded certificate into a text dict via stdlib."""
    import tempfile
    pem = ssl.DER_cert_to_PEM_cert(der_bytes)
    fd, path = tempfile.mkstemp()
    try:
        os.write(fd, pem.encode("ascii"))
    finally:
        os.close(fd)
    try:
        return ssl._ssl._test_decode_cert(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def ssl_analyze(domain, port=443):
    """Analyze SSL/TLS certificate details."""
    domain = domain.strip().lower().strip(".")
    d = {"domain": domain, "port": port}

    sock = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        conn = socket.create_connection((domain, port), timeout=8)
        sock = ctx.wrap_socket(conn, server_hostname=domain)

        # Protocol and cipher info — must read before closing the socket
        d["protocol"] = sock.version() if hasattr(sock, 'version') else "unknown"
        cipher = sock.cipher() if hasattr(sock, 'cipher') else None
        if cipher:
            d["cipher"] = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]}

        text_cert = _decode_cert_der(sock.getpeercert(binary_form=True))

        d["subject"] = dict(x[0] for x in text_cert.get("subject", []))
        d["issuer"] = dict(x[0] for x in text_cert.get("issuer", []))
        d["serialNumber"] = text_cert.get("serialNumber", "")
        d["notBefore"] = text_cert.get("notBefore", "")
        d["notAfter"] = text_cert.get("notAfter", "")
        d["subjectAltName"] = [v for t, v in text_cert.get("subjectAltName", [])
                               if t == "DNS"]

        # Calculate days until expiry
        try:
            expiry = datetime.strptime(d["notAfter"], "%b %d %H:%M:%S %Y %Z")
            d["daysUntilExpiry"] = (expiry - datetime.utcnow()).days
            d["expired"] = d["daysUntilExpiry"] < 0
        except Exception:
            pass

    except Exception as ex:
        d["error"] = f"SSL connection failed: {ex}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return d


# ---------- OSINT: Port Scanner ----------
def scan_ports(domain, ports=None):
    """Quick port scan of common ports."""
    domain = domain.strip().lower().strip(".")
    d = {"domain": domain, "openPorts": [], "closedPorts": []}

    if ports is None:
        ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200]

    # Resolve domain first
    try:
        ip = socket.gethostbyname(domain)
        d["ip"] = ip
    except Exception:
        d["error"] = f"Cannot resolve {domain}"
        return d

    common_services = {
        21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        8888: "HTTP-Proxy", 9200: "Elasticsearch"
    }

    open_ports = []
    closed_ports = []

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((domain, port))
            sock.close()
            return port, result == 0
        except Exception:
            return port, False

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(check_port, p): p for p in ports}
        for f in as_completed(futures):
            port, is_open = f.result()
            svc = common_services.get(port, "unknown")
            if is_open:
                open_ports.append({"port": port, "service": svc})
            else:
                closed_ports.append(port)

    open_ports.sort(key=lambda x: x["port"])
    d["openPorts"] = open_ports
    d["closedPorts"] = closed_ports
    d["scannedPorts"] = len(ports)
    return d


# ---------- OSINT: Technology Detection ----------
TECH_SIGNATURES = {
    "server": {
        "Apache": ["Apache"],
        "Nginx": ["nginx"],
        "IIS": ["Microsoft-IIS"],
        "Cloudflare": ["cloudflare"],
        "LiteSpeed": ["LiteSpeed"],
        "Caddy": ["Caddy"],
        "GWS": ["GWS"],
    },
    "language": {
        "PHP": ["PHP", "X-Powered-By: PHP"],
        "ASP.NET": ["ASP.NET", "X-Powered-By: ASP.NET"],
        "Express": ["X-Powered-By: Express"],
        "Python": ["X-Powered-By: Python", "Werkzeug", "gunicorn", "uvicorn"],
        "Ruby on Rails": ["X-Powered-By: Phusion Passenger", "X-Runtime"],
        "Node.js": ["X-Powered-By: Express"],
        "Java": ["JSESSIONID", "X-Powered-By: Servlet"],
        "Perl": ["X-Powered-By: Perl"],
    },
    "cms": {
        "WordPress": ["wp-content", "wp-includes", "wp-json"],
        "Drupal": ["Drupal", "drupal.js", "sites/default/files"],
        "Joomla": ["Joomla", "/components/com_"],
        "Ghost": ["ghost-"],
        "Hugo": ["Hugo", "generator"],
        "Laravel": ["laravel", "csrf-token"],
    },
    "framework": {
        "React": ["react", "ReactDOM", "_next"],
        "Angular": ["ng-version", "angular"],
        "Vue.js": ["vue", "vuejs"],
        "Next.js": ["_next/static"],
        "Django": ["csrfmiddlewaretoken", "django"],
        "Flask": ["Werkzeug"],
        "Laravel": ["laravel_session"],
        "Bootstrap": ["bootstrap"],
        "jQuery": ["jquery"],
        "Tailwind CSS": ["tailwindcss"],
    },
    "analytics": {
        "Google Analytics": ["google-analytics.com", "googletagmanager.com", "gtag"],
        "Facebook Pixel": ["fbevents.js", "facebook.com/tr"],
        "Hotjar": ["hotjar.com", "hj("],
        "Cloudflare Analytics": ["static.cloudflareinsights.com"],
    },
    "cdn": {
        "Cloudflare": ["cloudflare", "cf-ray"],
        "AWS CloudFront": ["cloudfront.net", "x-amz-cf"],
        "Akamai": ["akamai", "akamaihd.net"],
        "Fastly": ["fastly"],
        "Google CDN": ["googleapis.com", "gstatic.com"],
    }
}


def detect_technologies(url):
    """Detect web technologies from HTTP headers and HTML content."""
    url = normalize_url(url)
    d = {"url": url, "technologies": {}}

    try:
        resp = requests.get(url, timeout=10, verify=False,
                            headers={"User-Agent": USER_AGENT},
                            allow_redirects=True)
        d["statusCode"] = resp.status_code
        d["finalUrl"] = resp.url
        headers_text = str(resp.headers)
        body = resp.text[:50000]  # limit body scan
        combined = headers_text + "\n" + body

        detected = {}
        for category, techs in TECH_SIGNATURES.items():
            found = []
            for tech_name, patterns in techs.items():
                for pat in patterns:
                    if pat.lower() in combined.lower():
                        found.append(tech_name)
                        break
            if found:
                detected[category] = list(set(found))

        # Check specific headers
        if "x-powered-by" in resp.headers:
            detected.setdefault("headers", []).append(f"X-Powered-By: {resp.headers['x-powered-by']}")
        if "x-aspnet-version" in resp.headers:
            detected.setdefault("headers", []).append(f"X-AspNet-Version: {resp.headers['x-aspnet-version']}")
        if "x-generator" in resp.headers:
            detected.setdefault("headers", []).append(f"X-Generator: {resp.headers['x-generator']}")

        d["technologies"] = detected
        d["headers"] = dict(resp.headers)
    except Exception as ex:
        d["error"] = f"Detection failed: {ex}"
    return d


# ---------- OSINT: Subdomain Discovery ----------
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "api", "dev", "staging", "test", "beta", "alpha", "demo",
    "admin", "portal", "vpn", "gateway", "proxy",
    "cdn", "static", "media", "assets", "img", "images",
    "docs", "wiki", "help", "support", "kb",
    "blog", "news", "forum", "community",
    "shop", "store", "payment", "checkout",
    "app", "mobile", "m",
    "login", "auth", "sso", "id",
    "monitor", "status", "health", "grafana", "kibana",
    "git", "gitlab", "jenkins", "ci", "cd",
    "db", "database", "sql", "mysql", "postgres", "mongo", "redis", "elastic",
    "backup", "bak", "old", "legacy",
    "intranet", "internal", "corp", "office",
    "owa", "exchange", "autodiscover",
    "cpanel", "webmin", "plesk",
    "phpmyadmin", "adminer", "pgadmin"
]


def discover_subdomains(domain):
    """Discover subdomains by checking DNS for common names."""
    domain = domain.strip().lower().strip(".")
    d = {"domain": domain, "found": [], "checked": 0}

    found = []

    def check_sub(sub):
        fqdn = f"{sub}.{domain}"
        try:
            addrs = socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC)
            ips = list(set(a[4][0] for a in addrs))
            return fqdn, ips
        except Exception:
            return fqdn, None

    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(check_sub, sub): sub for sub in COMMON_SUBDOMAINS}
        for f in as_completed(futures):
            fqdn, ips = f.result()
            d["checked"] += 1
            if ips:
                found.append({"subdomain": fqdn, "ips": ips})

    found.sort(key=lambda x: x["subdomain"])
    d["found"] = found
    d["totalFound"] = len(found)
    return d


# ---------- OSINT: Google Dorking Helper ----------
def google_dorks(domain):
    """Generate Google dork queries for a domain."""
    domain = domain.strip().lower().strip(".")
    d = {"domain": domain, "dorks": []}

    dorks = [
        {"label": "Files containing sensitive data",
         "query": f'site:{domain} filetype:env OR filetype:sql OR filetype:log OR filetype:bak OR filetype:conf',
         "risk": "high"},
        {"label": "Directory listings",
         "query": f'site:{domain} intitle:"index of" OR intitle:"parent directory"',
         "risk": "high"},
        {"label": "Login pages",
         "query": f'site:{domain} inurl:login OR inurl:admin OR inurl:wp-admin OR inurl:signin',
         "risk": "medium"},
        {"label": "Exposed documents",
         "query": f'site:{domain} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:docx',
         "risk": "low"},
        {"label": "Error pages / stack traces",
         "query": f'site:{domain} "error" OR "exception" OR "stack trace" OR "warning:" OR "fatal error"',
         "risk": "medium"},
        {"label": "PHP info pages",
         "query": f'site:{domain} filetype:php inurl:info OR inurl:phpinfo OR "PHP Version"',
         "risk": "high"},
        {"label": "Configuration files",
         "query": f'site:{domain} filetype:xml OR filetype:yml OR filetype:yaml OR filetype:ini OR filetype:cfg',
         "risk": "medium"},
        {"label": "Backup archives",
         "query": f'site:{domain} filetype:zip OR filetype:tar.gz OR filetype:rar OR filetype:7z',
         "risk": "high"},
        {"label": "Email addresses",
         "query": f'site:{domain} "@{domain}" OR "email:" OR "contact@"',
         "risk": "low"},
        {"label": "Subdomains",
         "query": f'site:*.{domain} -www',
         "risk": "low"},
        {"label": "SQL dumps",
         "query": f'site:{domain} filetype:sql "INSERT INTO" OR "CREATE TABLE"',
         "risk": "high"},
        {"label": "Pastebin / paste sites",
         "query": f'site:pastebin.com "{domain}"',
         "risk": "high"},
        {"label": "GitHub / GitLab repos",
         "query": f'site:github.com OR site:gitlab.com "{domain}"',
         "risk": "medium"},
        {"label": "Publicly exposed APIs",
         "query": f'site:{domain} inurl:api OR inurl:v1 OR inurl:v2 OR inurl:graphql',
         "risk": "medium"},
        {"label": "JavaScript files with secrets",
         "query": f'site:{domain} filetype:js "api_key" OR "apikey" OR "token" OR "secret"',
         "risk": "high"},
        {"label": "Search engine cached pages",
         "query": f'cache:{domain}',
         "risk": "low"},
    ]

    d["dorks"] = dorks
    d["totalDorks"] = len(dorks)
    return d


# ---------- OSINT: URLhaus Malware Check ----------
def check_urlhaus(urls):
    """Check URLs against URLhaus malware database."""
    results = []
    url_list = [u.strip() for u in urls.split("\n") if u.strip()][:10]

    for url in url_list:
        dd = {"url": url}
        try:
            resp = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                timeout=10
            )
            data = resp.json()
            if data.get("query_status") == "ok":
                dd["threat"] = data.get("threat", "unknown")
                dd["tags"] = data.get("tags", [])
                dd["blacklists"] = data.get("blacklists", {})
                dd["dateAdded"] = data.get("date_added", "")
                dd["urlStatus"] = data.get("url_status", "")
                dd["host"] = data.get("host", "")
                dd["found"] = True
            else:
                dd["found"] = False
                dd["note"] = data.get("query_status", "Not found in URLhaus")
        except Exception as ex:
            dd["error"] = str(ex)
        results.append(dd)
    return results


# ---------- OSINT: Reverse IP Lookup ----------
def reverse_ip_lookup(ip):
    """Find other domains hosted on the same IP."""
    ip = ip.strip()
    d = {"ip": ip, "domains": []}

    try:
        # Validate IP
        socket.inet_aton(ip)
    except Exception:
        d["error"] = "Invalid IP address"
        return d

    # Try SecurityTrails-like approach via reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)
        d["primaryHostname"] = hostname[0]
        if hostname[1]:
            d["domains"] = list(hostname[1])
    except Exception:
        pass

    # Try to find via online API
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=10
        )
        if resp.status_code == 200 and "error" not in resp.text.lower():
            domains = [line.strip() for line in resp.text.strip().split("\n")
                       if line.strip() and not line.startswith("API")]
            d["domains"] = list(set(d.get("domains", []) + domains))
    except Exception:
        pass

    d["totalDomains"] = len(d.get("domains", []))
    return d


# ---------- OSINT: HTTP Security Headers Check ----------
def check_security_headers(url):
    """Detailed HTTP security headers analysis."""
    url = normalize_url(url)
    d = {"url": url, "headers": {}, "score": 0, "maxScore": 0, "findings": []}

    try:
        resp = requests.get(url, timeout=10, verify=False,
                            headers={"User-Agent": USER_AGENT},
                            allow_redirects=True)
        d["finalUrl"] = resp.url
        d["statusCode"] = resp.status_code
        headers = {k.lower(): v for k, v in resp.headers.items()}

        checks = [
            ("strict-transport-security", "HSTS", "HTTP Strict Transport Security",
             "Protects against protocol downgrade attacks", 2),
            ("content-security-policy", "CSP", "Content Security Policy",
             "Prevents XSS, code injection attacks", 2),
            ("x-frame-options", "XFO", "X-Frame-Options",
             "Prevents clickjacking attacks", 1),
            ("x-content-type-options", "XCTO", "X-Content-Type-Options",
             "Prevents MIME-type sniffing", 1),
            ("x-xss-protection", "XXSS", "X-XSS-Protection",
             "Legacy XSS filter (deprecated but still useful)", 0),
            ("referrer-policy", "RP", "Referrer-Policy",
             "Controls referrer information leakage", 1),
            ("permissions-policy", "PP", "Permissions-Policy",
             "Controls browser feature access (camera, mic, etc.)", 1),
            ("cross-origin-opener-policy", "COOP", "Cross-Origin-Opener-Policy",
             "Isolates browsing context", 1),
            ("cross-origin-resource-policy", "CORP", "Cross-Origin-Resource-Policy",
             "Controls resource loading", 1),
            ("cross-origin-embedder-policy", "COEP", "Cross-Origin-Embedder-Policy",
             "Enables cross-origin isolation", 1),
        ]

        for header_key, short, name, desc, points in checks:
            d["maxScore"] += points
            val = headers.get(header_key)
            if val:
                d["headers"][short] = {"name": name, "value": val, "present": True}
                d["score"] += points
                d["findings"].append({"header": name, "status": "present", "value": val})
            else:
                d["headers"][short] = {"name": name, "value": None, "present": False}
                d["findings"].append({"header": name, "status": "missing", "recommendation": desc})

        # Check for dangerous headers
        dangerous = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "server"]
        for h in dangerous:
            if h in headers:
                d["findings"].append({
                    "header": h.title(),
                    "status": "info_leak",
                    "value": headers[h],
                    "recommendation": f"Remove {h} header to avoid information disclosure"
                })

        # Check for cookies security
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Missing Secure flag")
            if "httponly" not in str(cookie).lower():
                issues.append("Missing HttpOnly flag")
            if "samesite" not in str(cookie).lower():
                issues.append("Missing SameSite attribute")
            if issues:
                d["findings"].append({
                    "header": f"Cookie: {cookie.name}",
                    "status": "insecure",
                    "issues": issues
                })

        d["grade"] = "A" if d["score"] >= d["maxScore"] * 0.8 else \
                     "B" if d["score"] >= d["maxScore"] * 0.6 else \
                     "C" if d["score"] >= d["maxScore"] * 0.4 else \
                     "D" if d["score"] >= d["maxScore"] * 0.2 else "F"

    except Exception as ex:
        d["error"] = f"Analysis failed: {ex}"
    return d


# ---------- HTTP handler ----------
class GovSiteHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PUBLIC, **kwargs)

    def log_message(self, format, *args):
        pass  # suppress default logging

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, max-age=0")
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, msg, status=400):
        self.send_json({"error": msg}, status)

    def read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def do_POST(self):
        path = self.path.split("?")[0]

        if path == "/api/check":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            urls = params.get("urls", [])
            if not urls:
                return self.send_error_json("No URLs provided")
            try:
                timeout = max(5, min(120, int(params.get("timeout", 12))))
            except (ValueError, TypeError):
                timeout = 15
            urls_list = [u.strip() for u in urls if u.strip()][:100]
            results = []
            client = make_client(timeout)
            try:
                with ThreadPoolExecutor(max_workers=16) as pool:
                    futures = {pool.submit(check_one, client, u, timeout): u for u in urls_list}
                    for f in as_completed(futures):
                        results.append(f.result())
            finally:
                client.close()
            return self.send_json(results)

        elif path == "/api/breach":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            domains_raw = "\n".join(
                d.strip().lower() for d in params.get("domains", []) if d.strip()
            )
            key = params.get("key", "")
            results = breach_check(domains_raw, key)
            return self.send_json(results)

        elif path == "/api/osint/ip-geolocate":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            ip = params.get("ip", "").strip()
            if ip and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                return self.send_error_json("Invalid IP address format")
            return self.send_json(geolocate_ip(ip))

        elif path == "/api/osint/whois":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            domain = params.get("domain", "").strip()
            if domain and not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$", domain):
                return self.send_error_json("Invalid domain format")
            return self.send_json(whois_lookup(domain))

        elif path == "/api/osint/email-header":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            header = params.get("header", "")
            if len(header) > 100000:
                return self.send_error_json("Email header too large (max 100KB)")
            return self.send_json(analyze_email_header(header))

        elif path == "/api/osint/domain-reputation":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            domain = params.get("domain", "").strip()
            if domain and not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$", domain):
                return self.send_error_json("Invalid domain format")
            return self.send_json(check_domain_reputation(domain))

        elif path == "/api/osint/dns":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            domain = params.get("domain", "").strip()
            if not domain:
                return self.send_error_json("Domain is required")
            if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$", domain):
                return self.send_error_json("Invalid domain format")
            return self.send_json(dns_enumerate(domain))

        elif path == "/api/osint/ssl":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            domain = params.get("domain", "").strip()
            try:
                port = int(params.get("port", 443))
            except (ValueError, TypeError):
                port = 443
            if not domain:
                return self.send_error_json("Domain is required")
            return self.send_json(ssl_analyze(domain, port))

        elif path == "/api/osint/ports":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            domain = params.get("domain", "").strip()
            if not domain:
                return self.send_error_json("Domain is required")
            custom_ports = params.get("ports")
            if custom_ports:
                try:
                    ports = [int(p) for p in custom_ports]
                except (ValueError, TypeError):
                    ports = None
            else:
                ports = None
            return self.send_json(scan_ports(domain, ports))

        elif path == "/api/osint/tech":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            url = params.get("url", "").strip()
            if not url:
                return self.send_error_json("URL is required")
            return self.send_json(detect_technologies(url))

        elif path == "/api/osint/subdomains":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            domain = params.get("domain", "").strip()
            if not domain:
                return self.send_error_json("Domain is required")
            if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$", domain):
                return self.send_error_json("Invalid domain format")
            return self.send_json(discover_subdomains(domain))

        elif path == "/api/osint/dorks":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            domain = params.get("domain", "").strip()
            if not domain:
                return self.send_error_json("Domain is required")
            return self.send_json(google_dorks(domain))

        elif path == "/api/osint/urlhaus":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            urls = params.get("urls", "")
            if not urls:
                return self.send_error_json("URLs are required")
            return self.send_json(check_urlhaus(urls))

        elif path == "/api/osint/reverse-ip":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            ip = params.get("ip", "").strip()
            if not ip:
                return self.send_error_json("IP address is required")
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                return self.send_error_json("Invalid IP address format")
            return self.send_json(reverse_ip_lookup(ip))

        elif path == "/api/osint/security-headers":
            params = self.read_json_body()
            if params is None:
                return self.send_error_json("Invalid or missing JSON body")
            url = params.get("url", "").strip()
            if not url:
                return self.send_error_json("URL is required")
            return self.send_json(check_security_headers(url))

        self.send_error_json("Not Found", 404)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/api/sites":
            with open(SITES_JSON, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # static files
        super().do_GET()


# ---------- main ----------
def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    server = HTTPServer(("localhost", PORT), GovSiteHandler)
    print()
    print("=" * 46, flush=True)
    print("  Government Site Checker is running", flush=True)
    print(f"  Open: http://localhost:{PORT}/", flush=True)
    print("  Press Ctrl+C to stop.", flush=True)
    print("=" * 46, flush=True)
    print(flush=True)

    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        try:
            import webbrowser
            webbrowser.open(f"http://localhost:{PORT}/")
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
