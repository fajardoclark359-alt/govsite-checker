# AGENTS.md — GovSite Checker

## Run

```
python3 server.py
```

Serves on `http://localhost:8000` and auto-opens a browser (only if `DISPLAY`/`WAYLAND_DISPLAY` is set). No `pip install` — only stdlib + `requests` (already present). Start with `start.sh` if preferred.

### Quick smoke test

```bash
python3 -c "import sys; sys.path.insert(0,'.'); import server; print('OK')"
```

## Architecture

- **Backend**: `server.py` — Python stdlib `http.server` + `requests`. No framework.
- **Frontend**: `public/index.html` + `public/app.js` (vanilla JS, IIFE, no build step) + `public/style.css`.
- **Data**: `sites.json` — `{"category": name, "sites": [{"name": ..., "url": ...}]}`
- ~185 Philippine government `.gov.ph` sites. Two tabs: GovSite Monitor + OSINT Tools.

## Critical: www DNS Fallback (DO NOT REMOVE)

Many PH government domains have **no DNS A/AAAA record on the bare apex** — only on the `www.` host (e.g. `dti.gov.ph` doesn't resolve; `www.dti.gov.ph` does). `check_one()` handles this via `_candidate_urls()` which tries: original → `www.` → `http://` → `http://www.` before declaring DOWN. **Never** mark such sites as DOWN or remove them — this is intentional. When adding new `.gov.ph` sites, prefer the `www.` URL variant, or verify with `socket.getaddrinfo` first.

## SSL

All HTTP checks use `verify=False` intentionally (many gov sites have broken certs). `urllib3.InsecureRequestWarning` is suppressed in `main()`. Do not "fix" this.

## Timeouts Are Slow by Design

Some PH sites take 10–20s to respond or time out entirely. The default timeout is 15s (selectable in UI: 10/15/30/60s). Do not tighten timeouts aggressively — it causes false DOWN results.

## DNS: No `dig`/`nslookup`

`dig` and `nslookup` are **not available** on this machine. DNS enumeration in the OSINT tab uses **DNS-over-HTTPS** (`dns.google` / `cloudflare-dns.com`). Never assume `dig` exists; use the DoH endpoints.

## sites.json Format

```json
[
  {
    "category": "Category Name",
    "sites": [
      { "name": "Site Name", "url": "https://example.gov.ph" }
    ]
  }
]
```

Validate after edits: `python3 -c "import json; json.load(open('sites.json'))"`

## Frontend Conventions

- `app.js` builds DOM via `document.createElement()` — never raw HTML string concatenation with server data. XSS was fixed; do not reintroduce `innerHTML` with unescaped server output.
- OSINT results render into `#*-results` containers using `osintTable()` which escapes via `escHtml()`.
- CSS variables: `--panel`, `--brand`, `--muted`, `--bg`, etc. in `public/style.css`.

## No Test Suite / Linter / CI

Verification = `python3 -c` smoke tests against functions + loading the server. There is no test runner, no ESLint, no CI pipeline.
