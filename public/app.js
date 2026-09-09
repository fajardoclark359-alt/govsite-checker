(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);

  // ---------------- state ----------------
  let hasServer = null;
  const state = {
    catalog: [],
    checked: {},
    results: {},
    breach: {},
    key: localStorage.getItem('hibpKey') || '',
    custom: [],
    checking: false,
    lastRun: null,
    progressTimer: null
  };

  // ---------------- threat intelligence (known PH gov incidents) ----------------
  const THREAT_DB = {
    'comelec.gov.ph': { type: 'data breach', year: 2016, detail: '55 million voter records leaked (700GB). Largest PH data breach. Leaked on darknet.', severity: 'critical' },
    'philhealth.gov.ph': { type: 'ransomware', year: 2023, detail: 'LockBit ransomware attack. Member data encrypted and exfiltrated. Service disrupted for months.', severity: 'critical' },
    'dilg.gov.ph': { type: 'data breach', year: 2023, detail: '346GB of internal data leaked by suspected Chinese hackers. Includes sensitive government documents.', severity: 'critical' },
    'pnp.gov.ph': { type: 'defacement', year: 2020, detail: 'Website defaced by unknown actors. Front page replaced with propaganda message.', severity: 'high' },
    'army.mil.ph': { type: 'data breach', year: 2021, detail: 'Military personnel records and internal documents leaked online.', severity: 'high' },
    'nbi.gov.ph': { type: 'data breach', year: 2021, detail: 'Employee credentials and case files reportedly leaked on darknet forums.', severity: 'high' },
    'bir.gov.ph': { type: 'phishing', year: 2022, detail: 'Fake phishing sites mimicking BIR portal to steal taxpayer credentials.', severity: 'high' },
    'lto.gov.ph': { type: 'data breach', year: 2022, detail: 'Driver license data of 10M+ individuals leaked. Sold on underground forums.', severity: 'critical' },
    'sss.gov.ph': { type: 'phishing', year: 2023, detail: 'Multiple phishing campaigns targeting SSS members with fake login pages.', severity: 'medium' },
    'pagibigfund.gov.ph': { type: 'phishing', year: 2023, detail: 'Phishing attacks impersonating Pag-IBIG to harvest member credentials.', severity: 'medium' },
    'gsis.gov.ph': { type: 'phishing', year: 2022, detail: 'Credential phishing campaigns targeting GSIS members.', severity: 'medium' },
    'doh.gov.ph': { type: 'defacement', year: 2021, detail: 'COVID-19 data portal targeted. Temporary defacement reported.', severity: 'high' },
    'deped.gov.ph': { type: 'data leak', year: 2022, detail: 'Student and teacher records exposed due to misconfigured cloud storage.', severity: 'high' },
    'dswd.gov.ph': { type: 'data leak', year: 2021, detail: 'Beneficiary personal data exposed through unsecured API endpoint.', severity: 'high' },
    'ico.gov.ph': { type: 'ransomware', year: 2022, detail: 'Internet Operations Center targeted. Brief service disruption.', severity: 'medium' },
    'smart.com.ph': { type: 'data breach', year: 2023, detail: '36 million user records (SIM registration data) leaked on hacker forum.', severity: 'critical' },
    'globe.com.ph': { type: 'data breach', year: 2023, detail: 'Customer data including names, emails, and addresses leaked.', severity: 'high' },
    'manila.gov.ph': { type: 'ransomware', year: 2023, detail: 'City government servers encrypted by ransomware. Services disrupted.', severity: 'critical' },
    'quezoncity.gov.ph': { type: 'data breach', year: 2022, detail: 'Resident records and permit data accessed by unauthorized parties.', severity: 'high' },
    'cebu.gov.ph': { type: 'defacement', year: 2021, detail: 'Provincial website defaced. Services temporarily unavailable.', severity: 'medium' },
    'davaocity.gov.ph': { type: 'ransomware', year: 2023, detail: 'City hall computer systems hit by ransomware. Recovery took weeks.', severity: 'high' },
    'dpwh.gov.ph': { type: 'data breach', year: 2022, detail: 'Infrastructure project data and procurement records leaked.', severity: 'high' },
    'sec.gov.ph': { type: 'phishing', year: 2023, detail: 'Phishing sites mimicking SEC portal to steal corporate filing credentials.', severity: 'medium' },
    'customs.gov.ph': { type: 'data breach', year: 2021, detail: 'Customs declaration data and importer records leaked.', severity: 'high' },
    'psa.gov.ph': { type: 'data breach', year: 2023, detail: 'National ID registration data reportedly compromised.', severity: 'critical' },
    'neda.gov.ph': { type: 'defacement', year: 2020, detail: 'Website defaced during political unrest period.', severity: 'medium' },
    'ostc.gov.ph': { type: 'ransomware', year: 2022, detail: 'Ransomware attack on government IT systems.', severity: 'high' },
    'dict.gov.ph': { type: 'breach', year: 2023, detail: 'National cybersecurity agency systems targeted. Incident under investigation.', severity: 'critical' },
    'bps.gov.ph': { type: 'data leak', year: 2022, detail: 'Budget and procurement data exposed through misconfigured server.', severity: 'high' },
    'dbm.gov.ph': { type: 'data breach', year: 2021, detail: 'Internal financial documents leaked.', severity: 'high' },
    'trc.gov.ph': { type: 'ransomware', year: 2023, detail: 'Tourism agency systems encrypted by ransomware group.', severity: 'high' },
    'nbi.gov.ph': { type: 'data breach', year: 2023, detail: 'NBI clearance system data compromised. Personal records at risk.', severity: 'critical' },
    'pdea.gov.ph': { type: 'defacement', year: 2020, detail: 'Anti-drug agency website briefly defaced.', severity: 'medium' },
    'afp.mil.ph': { type: 'data breach', year: 2021, detail: 'Armed forces personnel data leaked on darknet forum.', severity: 'critical' },
    'navy.mil.ph': { type: 'data breach', year: 2022, detail: 'Naval personnel records and deployment data reportedly accessed.', severity: 'high' },
    'paf.mil.ph': { type: 'data breach', year: 2022, detail: 'Air force personnel data exposed in credential leak.', severity: 'high' },
    'coastguard.gov.ph': { type: 'defacement', year: 2021, detail: 'Coast guard website temporarily taken down by attackers.', severity: 'medium' },
    'nda.gov.ph': { type: 'data leak', year: 2022, detail: 'Drug enforcement intelligence data reportedly compromised.', severity: 'critical' },
    'pcso.gov.ph': { type: 'ransomware', year: 2023, detail: 'Gaming and lottery systems disrupted by ransomware.', severity: 'high' },
    'poc.gov.ph': { type: 'defacement', year: 2021, detail: 'Olympic committee website defaced.', severity: 'low' },
  };

  function getThreatInfo(url) {
    const host = hostOf(url);
    for (const [domain, info] of Object.entries(THREAT_DB)) {
      if (host === domain || host.endsWith('.' + domain)) {
        return info;
      }
    }
    return null;
  }

  function threatBadge(info) {
    if (!info) return '';
    const sevColor = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#65a30d' };
    const color = sevColor[info.severity] || '#888';
    return '<span class="threat-badge" style="background:' + color + ';color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap;">' +
      escHtml(info.type.toUpperCase()) + ' (' + info.year + ')</span>';
  }

  const namesByUrl = () => {
    const map = {};
    state.catalog.forEach((c) => c.sites.forEach((s) => { map[s.url] = s.name; }));
    state.custom.forEach((s) => { if (!map[s.url]) map[s.url] = s.name; });
    return map;
  };

  const hostOf = (url) => { try { return new URL(url).hostname.toLowerCase(); } catch (e) { return url.replace(/^https?:\/\//i, '').trim(); } };

  const normalizeUrl = (u) => {
    u = u.trim();
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    return u;
  };

  async function detectServer() {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3000);
      const res = await fetch('/api/sites', { method: 'GET', signal: controller.signal });
      clearTimeout(timer);
      hasServer = res.ok;
    } catch (e) {
      hasServer = false;
    }
  }

  function candidateUrls(url) {
    const u = new URL(url);
    const host = u.hostname;
    const candidates = [url];
    if (!host.startsWith('www.') && host.includes('.')) {
      candidates.push(u.protocol + '//' + 'www.' + host + u.pathname + u.search);
    }
    if (u.protocol === 'https:') {
      candidates.push('http://' + u.host + u.pathname + u.search);
      if (!host.startsWith('www.') && host.includes('.')) {
        candidates.push('http://www.' + host + u.pathname + u.search);
      }
    }
    return [...new Set(candidates)];
  }

  const BROWSER_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1'
  };

  function jitterMs() { return Math.floor(Math.random() * 200) + 50; }

  async function clientCheck(url, timeoutSec) {
    const candidates = candidateUrls(url);
    const perUrlTimeout = Math.max(Math.floor(timeoutSec / candidates.length), 5);
    let lastError = '';
    let lastDownReason = 'other';
    const start = Date.now();

    for (let ci = 0; ci < candidates.length; ci++) {
      const candidate = candidates[ci];
      if (ci > 0) await new Promise((r) => setTimeout(r, jitterMs()));

      // Strategy 1: cors mode with browser headers (gets real status if CORS allowed)
      const ctrl1 = new AbortController();
      const timer1 = setTimeout(() => ctrl1.abort(), perUrlTimeout * 1000);
      try {
        const res = await fetch(candidate, {
          mode: 'cors',
          signal: ctrl1.signal,
          cache: 'no-store',
          redirect: 'follow',
          headers: BROWSER_HEADERS
        });
        clearTimeout(timer1);
        const ms = Date.now() - start;
        const code = res.status;
        const hdrs = {};
        try { res.headers.forEach((v, k) => { hdrs[k.toLowerCase()] = v; }); } catch (e) { /* ok */ }
        return {
          url: url, usedUrl: candidate, status: 'UP', reachable: true, code: code, ms: ms,
          error: '', dns: true,
          httpNote: (candidate !== url ? 'Fallback: ' : '') + 'CORS mode — HTTP ' + code,
          tries: candidates.length, downReason: '',
          hsts: hdrs['strict-transport-security'] ? 1 : 0,
          csp: hdrs['content-security-policy'] ? 1 : 0,
          xframe: hdrs['x-frame-options'] ? 1 : 0,
          exposed: [], clientSide: true,
          remark: candidate !== url ? 'Original URL failed; ' + candidate + ' responded.' : ''
        };
      } catch (e) {
        clearTimeout(timer1);
        // CORS error means server responded but no CORS headers — site is likely UP
        const errStr = (e.message || '').toLowerCase();
        if (errStr.includes('Failed to fetch') || errStr.includes('networkerror') || errStr.includes('cors')) {
          // Server responded but no CORS — opaque fallback
          const ctrl2 = new AbortController();
          const timer2 = setTimeout(() => ctrl2.abort(), Math.max(perUrlTimeout - 3, 2) * 1000);
          try {
            await fetch(candidate, { mode: 'no-cors', signal: ctrl2.signal, cache: 'no-store', redirect: 'follow' });
            clearTimeout(timer2);
            const ms = Date.now() - start;
            return {
              url: url, usedUrl: candidate, status: 'UP', reachable: true, code: 0, ms: ms,
              error: '', dns: true,
              httpNote: (candidate !== url ? 'Fallback: ' : '') + 'Opaque response (no CORS headers)',
              tries: candidates.length, downReason: '', hsts: 0, csp: 0, xframe: 0,
              exposed: [], clientSide: true,
              remark: candidate !== url ? 'Original URL failed; ' + candidate + ' responded.' : ''
            };
          } catch (e2) {
            clearTimeout(timer2);
            const err2 = (e2.message || '').toLowerCase();
            const name2 = (e2.name || '').toLowerCase();
            if (name2 === 'abort' || err2.includes('timeout')) lastDownReason = 'timeout';
            else if (err2.includes('ssl') || err2.includes('tls') || err2.includes('certificate')) lastDownReason = 'tls';
            else if (err2.includes('failed') || err2.includes('refused') || err2.includes('network')) lastDownReason = 'refused';
            else lastDownReason = 'reset';
            lastError = e2.message || 'Connection failed';
          }
        } else {
          const name = (e.name || '').toLowerCase();
          if (name === 'abort' || errStr.includes('timeout')) lastDownReason = 'timeout';
          else if (errStr.includes('ssl') || errStr.includes('tls') || errStr.includes('certificate')) lastDownReason = 'tls';
          else lastError = e.message || 'Connection failed';
        }
      }
    }

    const ms = Date.now() - start;
    return {
      url: url, usedUrl: url, status: 'DOWN', reachable: false, code: 0, ms: ms,
      error: lastError, dns: true, httpNote: '',
      tries: candidates.length, downReason: lastDownReason, hsts: 0, csp: 0, xframe: 0, exposed: [],
      remark: 'Tried ' + candidates.length + ' URL variant(s): ' + candidates.join(', ')
    };
  }

  // ---------------- classification ----------------
  const LEVEL_ORDER = ['down', 'error', 'breach', 'exposed', 'restricted', 'risk', 'clean', 'unknown'];

  function classify(url) {
    const r = state.results[url];
    if (!r) return { level: 'unknown', label: 'NOT CHECKED', detail: 'Has not been checked yet.' };
    if (r.status === 'DOWN') {
      let detail;
      if (r.dns === false)
        detail = 'Domain does not resolve in DNS - the hostname has no records. A browser on a different network/proxy could still open it if that network resolves differently.';
      else {
        const tries = r.tries || 1;
        const clientNote = r.clientSide ? ' (client-side check; run python3 server.py for accurate results)' : '';
        switch (r.downReason) {
          case 'timeout':
            detail = 'No HTTP response within ' + (r.timeoutSec || '?') + 's after ' + tries + ' URL variant(s). The site may be slow rather than down - open in a browser to confirm.';
            break;
          case 'refused':
            detail = 'Connection refused on all ' + tries + ' URL variant(s). The site may use a WAF or proxy that blocks non-browser requests. Open in a browser to verify.' + clientNote;
            break;
          case 'reset':
            detail = 'Connection dropped on all ' + tries + ' URL variant(s) (possible bot detection / WAF). The site will typically open in a real browser.' + clientNote;
            break;
          case 'tls':
            detail = 'SSL/TLS handshake failed on all ' + tries + ' URL variant(s). The site may have an expired or self-signed certificate.' + clientNote;
            break;
          default:
            detail = (r.error || 'No response received') + ' after ' + tries + ' URL variant(s). Verify in a browser.' + clientNote;
        }
      }
      return { level: 'down', label: 'DOWN', detail: r.remark ? r.remark + '\n\n' + detail : detail };
    }
    const host = hostOf(url);
    const b = state.breach[host];
    if (b && b.breached) return { level: 'breach', label: 'BREACHED', detail: (b.names || []).join(', ') || 'Listed in HaveIBeenPwned' };
    const threat = getThreatInfo(url);
    if (threat) {
      const sevLabel = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };
      return { level: 'breach', label: 'THREAT INTEL', detail: 'Known incident: ' + threat.type.toUpperCase() + ' (' + threat.year + ') — ' + threat.detail + ' [Severity: ' + (sevLabel[threat.severity] || threat.severity) + ']', threat: threat };
    }
    if (r.exposed && r.exposed.length > 0)
      return { level: 'exposed', label: 'EXPOSED', detail: 'Possible exposure detected (heuristic): ' + r.exposed.join(', ') };

    if (r.code >= 500)
      return { level: 'error', label: 'SERVER ERROR', detail: r.httpNote || 'Server returned an error (HTTP ' + r.code + ')' };
    if (r.code >= 400)
      return { level: 'restricted', label: 'ONLINE (BLOCKED)', detail: r.httpNote || 'Online but restricted (HTTP ' + r.code + ')' };

    const score = (r.hsts ? 0 : 1) + (r.csp ? 0 : 1) + (r.xframe ? 0 : 1);
    if (score >= 2) return { level: 'risk', label: 'AT RISK', detail: 'Heuristic: missing security headers (HSTS/CSP/X-Frame)' + (r.remark ? '\n\n' + r.remark : '') };
    return { level: 'clean', label: 'ONLINE', detail: 'Up and reachable. No exposure flags found (heuristic check, not a full security audit).' + (r.remark && r.usedUrl !== url ? '\n\n' + r.remark : '') };
  }

  function summary() {
    const urls = Object.keys(state.results);
    const count = (lvl) => urls.filter((u) => classify(u).level === lvl).length;
    return {
      total: urls.length,
      up: count('clean'),
      down: count('down'),
      error: count('error'),
      blocked: count('restricted'),
      risk: count('risk'),
      breach: count('breach'),
      exposed: count('exposed')
    };
  }

  // ---------------- catalog / sidebar ----------------
  async function loadCatalog() {
    let data = null;
    try {
      const res = await fetch('/api/sites');
      if (res.ok) data = await res.json();
    } catch (e) { /* fall through to static copy */ }
    if (!data) {
      try {
        const res = await fetch('sites.json');
        if (res.ok) data = await res.json();
      } catch (e) { /* fall through to empty */ }
    }
    if (!data) {
      try {
        const res = await fetch('./sites.json');
        if (res.ok) data = await res.json();
      } catch (e) { /* give up */ }
    }
    if (!data) {
      const el = document.getElementById('catalog');
      if (el) el.innerHTML = '<div class="osint-error" style="padding:12px;">Could not load site catalog. Check your connection or refresh the page.</div>';
      return;
    }
    state.catalog = data;
    state.catalog.forEach((c) => c.sites.forEach((s) => { state.checked[s.url] = true; }));
    buildSidebar();
    updateCheckButtons();
  }

  let searchTerm = '';
  function buildSidebar() {
    const wrap = $('#catalog');
    wrap.innerHTML = '';
    const term = searchTerm.toLowerCase();

    state.catalog.forEach((cat) => {
      const visibleSites = cat.sites.filter((s) => !term || s.name.toLowerCase().includes(term) || s.url.toLowerCase().includes(term));
      if (term && visibleSites.length === 0) return;

      const sec = document.createElement('div');
      sec.className = 'cat';

      const head = document.createElement('div');
      head.className = 'cat-head';
      const catCb = document.createElement('input');
      catCb.type = 'checkbox';
      const allChecked = cat.sites.every((s) => state.checked[s.url]);
      catCb.checked = allChecked;
      catCb.addEventListener('change', () => {
        cat.sites.forEach((s) => { state.checked[s.url] = catCb.checked; });
        buildSidebar();
        updateCheckButtons();
      });
      const nm = document.createElement('div');
      nm.className = 'cat-name';
      nm.textContent = cat.category;
      const cnt = document.createElement('span');
      cnt.className = 'cat-count';
      cnt.textContent = cat.sites.length;
      head.append(catCb, nm, cnt);
      head.addEventListener('click', (e) => { if (e.target !== catCb) { catCb.checked = !catCb.checked; catCb.dispatchEvent(new Event('change')); } });

      const rows = document.createElement('div');
      visibleSites.forEach((s) => rows.appendChild(siteRow(s)));

      sec.append(head, rows);
      wrap.appendChild(sec);
    });
    applyResultDots();
  }

  function siteRow(s) {
    const row = document.createElement('label');
    row.className = 'site-row';
    const dot = document.createElement('span');
    dot.className = 'site-dot';
    dot.id = 'dot-' + s.url.replace(/[^a-z0-9]/gi, '_');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = !!state.checked[s.url];
    cb.addEventListener('change', () => {
      state.checked[s.url] = cb.checked;
      updateCheckButtons();
    });
    const nm = document.createElement('span');
    nm.className = 'site-name';
    nm.textContent = s.name;
    const status = document.createElement('span');
    status.className = 'site-status';
    status.id = 'status-' + s.url.replace(/[^a-z0-9]/gi, '_');
    const cl = classify(s.url);
    if (cl.level !== 'unknown') {
      status.textContent = cl.level === 'clean' || cl.level === 'risk' || cl.level === 'restricted' ? 'ONLINE' : 'OFFLINE';
      status.className = 'site-status ' + (cl.level === 'clean' || cl.level === 'risk' || cl.level === 'restricted' ? 'online' : 'offline');
    }
    const b = state.breach[hostOf(s.url)];
    const breachBadge = document.createElement('span');
    breachBadge.className = 'site-status';
    breachBadge.id = 'breach-' + s.url.replace(/[^a-z0-9]/gi, '_');
    if (b && b.breached) {
      const names = (b.names || []).join(', ');
      breachBadge.textContent = 'BREACHED';
      breachBadge.className = 'site-status breach';
      breachBadge.title = names || 'Listed in HaveIBeenPwned';
    }
    row.append(cb, dot, nm, status, breachBadge);
    return row;
  }

  function applyResultDots() {
    Object.keys(state.results).forEach((url) => {
      const id = url.replace(/[^a-z0-9]/gi, '_');
      const dotEl = document.getElementById('dot-' + id);
      const statusEl = document.getElementById('status-' + id);
      if (dotEl) dotEl.className = 'site-dot ' + classify(url).level;
      if (statusEl) {
        const cl = classify(url);
        if (cl.level !== 'unknown') {
          const isUp = cl.level === 'clean' || cl.level === 'risk' || cl.level === 'restricted';
          statusEl.textContent = isUp ? 'ONLINE' : 'OFFLINE';
          statusEl.className = 'site-status ' + (isUp ? 'online' : 'offline');
        }
      }
    });
    Object.keys(state.breach).forEach((host) => {
      const b = state.breach[host];
      if (!b || !b.breached) return;
      Object.keys(state.results).forEach((url) => {
        if (hostOf(url) !== host) return;
        const id = url.replace(/[^a-z0-9]/gi, '_');
        const el = document.getElementById('breach-' + id);
        if (el) {
          const names = (b.names || []).join(', ');
          el.textContent = 'BREACHED';
          el.className = 'site-status breach';
          el.title = names || 'Listed in HaveIBeenPwned';
        }
      });
    });
  }

  function updateCheckButtons() {
    const n = Object.values(state.checked).filter(Boolean).length;
    $('#btnCheckSel').textContent = 'Check Selected (' + n + ')';
  }

  // ---------------- checking ----------------
  async function doCheck(urls) {
    if (!urls.length) return;
    setChecking(true);
    startProgress('Checking ' + urls.length + ' site(s)...');

    try {
      if (hasServer) {
        const res = await fetch('/api/check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ urls, timeout: selectedTimeout() })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        if (!Array.isArray(data)) throw new Error('Unexpected server response');
        data.forEach((r) => { r.checkedAt = Date.now(); r.timeoutSec = selectedTimeout(); state.results[r.url] = r; });
      } else {
        const concurrency = 10;
        const timeoutSec = selectedTimeout();
        const total = urls.length;
        let done = 0;
        for (let i = 0; i < urls.length; i += concurrency) {
          const batch = urls.slice(i, i + concurrency);
          const batchResults = await Promise.all(batch.map((u) => clientCheck(u, timeoutSec)));
          done += batchResults.length;
          batchResults.forEach((r) => { r.checkedAt = Date.now(); r.timeoutSec = timeoutSec; state.results[r.url] = r; });
          renderResults();
          applyResultDots();
          const pct = Math.round((done / total) * 100);
          startProgress('Checked ' + done + '/' + total + ' site(s) (' + pct + '%)...');
        }
      }
      state.lastRun = new Date();
      renderResults();
      applyResultDots();
      updateCheckButtons();
      if (hasServer && state.key) await breachScan(false);
      else renderBreachNote();
    } catch (err) {
      alert('Check failed: ' + err.message);
    } finally {
      setChecking(false);
      finishProgress();
    }
  }

  function selectedUrls() {
    const selected = Object.keys(state.checked).filter((u) => state.checked[u]);
    let urls = selected;
    if (urls.length === 0) {
      urls = allUrls();
    }
    return unique(urls.map(normalizeUrl));
  }

  function allUrls() {
    const map = namesByUrl();
    return unique(Object.keys(map));
  }

  function downUrls() {
    return Object.keys(state.results).filter((u) => state.results[u].status === 'DOWN');
  }

  function flaggedUrls() {
    return Object.keys(state.results).filter((u) => ['breach', 'exposed', 'risk'].includes(classify(u).level));
  }

  function unique(a) { return Array.from(new Set(a)); }

  function setChecking(v) {
    state.checking = v;
    ['#btnCheckSel', '#btnCheckAll', '#btnCheckDown', '#btnCheckFailed', '#btnBreachScan'].forEach((sel) => { $(sel).disabled = v; });
  }

  // ---------------- LIVE auto-refresh (real-time monitoring) ----------------
  let liveOn = false, liveTimer = null, liveCd = 60;

  function liveInterval() { return parseInt($('#liveInterval').value, 10) || 60; }
  function selectedTimeout() { return parseInt($('#timeoutSel').value, 10) || 15; }

  function liveUrls() {
    const checked = Object.keys(state.checked).filter((u) => state.checked[u]);
    return unique([...checked.map(normalizeUrl), ...Object.keys(state.results)]);
  }

  function liveTick() {
    if (!liveOn) return;
    if (liveCd > 0) {
      liveCd--;
      $('#btnLive').textContent = 'LIVE (' + liveCd + 's)';
    }
    if (liveCd <= 0) {
      if (state.checking) {
        liveCd = 2; // back off while a check is running, retry shortly
      } else {
        liveCd = liveInterval();
        $('#btnLive').textContent = 'LIVE (checking...)';
        doCheck(liveUrls());
      }
    }
  }

  function setLive(on) {
    liveOn = on;
    localStorage.setItem('liveMode', on ? '1' : '0');
    const btn = $('#btnLive');
    btn.textContent = on ? 'LIVE (' + liveCd + 's)' : 'LIVE OFF';
    btn.classList.toggle('btn-primary', on);
    btn.classList.toggle('live-on', on);
    if (on) {
      liveCd = liveInterval();
      if (!liveTimer) liveTimer = setInterval(liveTick, 1000);
    } else {
      if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
      btn.classList.remove('live-on');
    }
  }

  // ---------------- breach scan ----------------
  async function breachScan(force = true) {
    if (!state.key) return;
    if (!hasServer) { renderBreachNote(); return; }
    if (force) setChecking(true);
    const hosts = unique(Object.keys(state.results).map(hostOf));
    if (!hosts.length) return;
    try {
      const res = await fetch('/api/breach', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains: hosts, key: state.key })
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      if (!Array.isArray(data)) throw new Error('Unexpected server response');
      const arr = data;
      arr.forEach((d) => { if (d) state.breach[d.domain] = d; });
      renderResults();
      applyResultDots();
    } catch (err) {
      console.error('Breach scan failed:', err.message);
    } finally {
      if (force) setChecking(false);
    }
  }

  function renderBreachNote() {
    if (Object.keys(state.breach).length) {
      state.breach = {};
      renderResults();
      applyResultDots();
    }
    if (hasServer === false) {
      const el = document.getElementById('results');
      if (el && !el.querySelector('.breach-note')) {
        const note = document.createElement('div');
        note.className = 'breach-note server-banner';
        note.textContent = 'Breach scanning requires the Python server (HIBP API key). Run locally: python3 server.py';
        el.prepend(note);
      }
    }
  }

  // ---------------- rendering ----------------
  function renderResults() {
    const grid = document.createElement('div');
    grid.className = 'cards-grid';

    const urls = Object.keys(state.results);
    urls.sort((a, b) => LEVEL_ORDER.indexOf(classify(a).level) - LEVEL_ORDER.indexOf(classify(b).level));

    const names = namesByUrl();
    urls.forEach((url, i) => {
      const card = document.createElement('div');
      card.style.animationDelay = Math.min(i * 20, 400) + 'ms';
      card.appendChild(cardEl(url, names[url] || hostOf(url)));
      grid.appendChild(card);
    });

    const box = $('#results');
    box.innerHTML = '';
    box.appendChild(grid);
    $('#empty').style.display = urls.length ? 'none' : 'flex';
    renderChips();
    $('#lastRun').textContent = state.lastRun
      ? 'Last check: ' + state.lastRun.toLocaleString() + (liveOn ? '  |  LIVE monitoring active.' : '  |  Enable LIVE auto-refresh for real-time monitoring.') + '  |  Method: direct HTTPS probe with browser User-Agent. If a browser opens a site marked DOWN, the difference is usually timeouts, proxy/PAC config, or WAF bot-filtering - click "Open in browser" to confirm.'
      : 'No checks run yet. Enable LIVE to monitor automatically.';
  }

  function cardEl(url, name) {
    const r = state.results[url];
    const cl = classify(url);
    const wrap = document.createElement('div');
    wrap.className = 'card bd-' + cl.level;

    const top = document.createElement('div');
    top.className = 'card-top';
    const nm = document.createElement('div');
    const nmt = document.createElement('div');
    nmt.className = 'card-name';
    nmt.textContent = name;
    const host = document.createElement('div');
    host.className = 'card-host';
    host.textContent = url;
    nm.append(nmt, host);
    const badge = document.createElement('span');
    badge.className = 'badge ' + cl.level;
    badge.textContent = cl.label;
    const open = document.createElement('a');
    open.className = 'card-open';
    open.href = url;
    open.target = '_blank';
    open.rel = 'noopener';
    open.textContent = 'Open in browser ↗';
    top.append(nm, badge, open);
    wrap.appendChild(top);

    const threat = getThreatInfo(url);
    if (threat) {
      const threatDiv = document.createElement('div');
      threatDiv.className = 'card-threat';
      const sevColor = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#65a30d' };
      const color = sevColor[threat.severity] || '#888';
      threatDiv.innerHTML = '<span class="threat-badge" style="background:' + color + ';color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">' +
        escHtml(threat.type.toUpperCase()) + ' (' + threat.year + ')</span> ' +
        '<span style="color:#ccc;font-size:12px;">' + escHtml(threat.detail) + '</span>';
      wrap.appendChild(threatDiv);
    }

    if (cl.level === 'down' && cl.detail && cl.detail !== 'DOWN') {
      const err = document.createElement('div');
      err.className = 'card-err card-err-breach';
      err.textContent = cl.detail;
      wrap.appendChild(err);
    }

    if (cl.level === 'exposed') {
      const ex = document.createElement('div');
      ex.className = 'card-exposed';
      ex.innerHTML = '&#9888; Possible exposure detected: ';
      const code = document.createElement('code');
      code.textContent = (r.exposed || []).join(', ');
      ex.appendChild(code);
      wrap.appendChild(ex);
    }

    const meta = document.createElement('div');
    meta.className = 'card-meta';
    meta.appendChild(metaChip('HTTP', String(r.code), r.code >= 200 && r.code < 400 ? 'ok' : (r.code >= 500 ? 'bad' : 'warn')));
    meta.appendChild(metaChip('Time', r.ms + ' ms', r.ms < 1500 ? 'ok' : 'warn'));
    meta.appendChild(metaChip('HSTS', r.hsts ? 'yes' : 'no', r.hsts ? 'ok' : 'warn'));
    meta.appendChild(metaChip('CSP', r.csp ? 'yes' : 'no', r.csp ? 'ok' : 'warn'));
    meta.appendChild(metaChip('X-Frame', r.xframe ? 'yes' : 'no', r.xframe ? 'ok' : 'warn'));
    if (r.tries && r.tries > 1) meta.appendChild(metaChip('Attempts', String(r.tries), 'warn'));
    if (r.checkedAt) meta.appendChild(metaChip('Checked', new Date(r.checkedAt).toLocaleTimeString(), 'ok'));
    wrap.appendChild(meta);

    const notes = [];
    const b = state.breach[hostOf(url)];
    if (b && b.note) notes.push(b.note);
    if (cl.level === 'down') notes.push('DNS: ' + (r.dns ? 'resolves' : 'NOT resolving') + (r.tries > 1 ? ' (after ' + r.tries + ' attempts)' : ''));
    if (cl.level === 'breach') notes.push('Breach data: ' + cl.detail);
    if (cl.level === 'error' || cl.level === 'restricted' || cl.level === 'risk' || cl.level === 'clean') notes.push(cl.detail);
    if (notes.length) {
      const note = document.createElement('div');
      note.className = 'card-err card-err-breach';
      note.style.color = '#8fa3c0';
      note.style.background = '#16213a';
      note.textContent = notes.join('  |  ');
      wrap.appendChild(note);
    }
    return wrap;
  }

  function metaChip(label, value, cls) {
    const m = document.createElement('span');
    m.className = 'meta';
    const b = document.createElement('b');
    b.className = cls;
    b.textContent = value;
    m.textContent = label + ': ';
    m.appendChild(b);
    return m;
  }

  function renderChips() {
    const s = summary();
    const chips = [
      ['total', 'Total', s.total],
      ['up', 'Online', s.up],
      ['down', 'Down', s.down],
      ['err', 'Server Err', s.error],
      ['blocked', 'Blocked', s.blocked],
      ['breach', 'Breached', s.breach],
      ['exposed', 'Exposed', s.exposed],
      ['risk', 'At Risk', s.risk]
    ];
    const box = $('#chips');
    box.innerHTML = '';
    chips.forEach(([cls, label, val]) => {
      const c = document.createElement('div');
      c.className = 'chip ' + cls;
      const b = document.createElement('b');
      b.textContent = val;
      c.textContent = label + ' ';
      c.appendChild(b);
      box.appendChild(c);
    });
  }

  function escHtml(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  // ---------------- progress ----------------
  function startProgress(label) {
    $('#progress').classList.remove('hidden');
    $('#progressLabel').textContent = label;
    let p = 0;
    clearInterval(state.progressTimer);
    state.progressTimer = setInterval(() => {
      p = Math.min(p + 2 + Math.random() * 4, 92);
      $('#progressBar').style.width = p + '%';
    }, 250);
  }
  function finishProgress() {
    clearInterval(state.progressTimer);
    $('#progressBar').style.width = '100%';
    setTimeout(() => { $('#progress').classList.add('hidden'); $('#progressBar').style.width = '0%'; }, 400);
  }

  // ---------------- report rows ----------------
  function reportRows() {
    const names = namesByUrl();
    const checked = Object.keys(state.checked).filter((u) => state.checked[u]);
    const urls = unique([...checked.map(normalizeUrl), ...Object.keys(state.results)]);
    return urls.map((url) => {
      const r = state.results[url];
      const c = classify(url);
      return {
        name: names[url] || hostOf(url),
        url,
        status: r ? r.status : 'NOT CHECKED',
        code: r ? r.code : '',
        ms: r ? r.ms : '',
        hsts: r ? (r.hsts ? 'Yes' : 'No') : '',
        csp: r ? (r.csp ? 'Yes' : 'No') : '',
        xframe: r ? (r.xframe ? 'Yes' : 'No') : '',
        exposed: r ? (r.exposed || []).join(', ') : '',
        level: c.level,
        breachLevel: c.label,
        detail: c.detail
      };
    }).sort((a, b) => LEVEL_ORDER.indexOf(a.level) - LEVEL_ORDER.indexOf(b.level));
  }

  // ---------------- Excel export (real .xlsx, generated client-side) ----------------
  const XL_COLS = ['Site', 'URL', 'Status', 'HTTP Code', 'Response (ms)', 'HSTS', 'CSP', 'X-Frame', 'Exposed Files', 'Breach Classification', 'Detail / Notes'];
  const XL_WIDTHS = [26, 38, 10, 11, 15, 8, 8, 11, 32, 18, 50];
  const XL_STYLE = {
    plain:  { fill: null,     font: 'FF212529', bold: false },
    header: { fill: 'FF1D4ED8', font: 'FFFFFFFF', bold: true },
    up:     { fill: 'FFE8F5E9', font: 'FF1B5E20', bold: false },
    down:   { fill: 'FFFDECEA', font: 'FFB71C1C', bold: true },
    risk:   { fill: 'FFFFF3E0', font: 'FFE65100', bold: false },
    exposed:{ fill: 'FFFFF8E1', font: 'FFF57F17', bold: true },
    breach: { fill: 'FFB71C1C', font: 'FFFFFFFF', bold: true },
    unknown:{ fill: 'FFECEFF1', font: 'FF546E7A', bold: false }
  };
  const XL_KEYS = ['plain', 'header', 'up', 'down', 'risk', 'exposed', 'breach', 'unknown'];
  // cellXfs style index per key (fonts follow the same order)
  const XL_STYLE_INDEX = { plain: 0, header: 1, up: 2, down: 3, risk: 4, exposed: 5, breach: 6, unknown: 7 };
  const XL_LEVEL_STYLE = { down: 3, error: 3, breach: 6, exposed: 5, restricted: 4, risk: 4, clean: 2, up: 2, unknown: 7 };
  const XL_FILL_IDX = (() => { const m = {}; let i = 2; XL_KEYS.slice(1).forEach((k) => { m[k] = i++; }); return m; })();

  function escXml(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;'); }

  function colLetter(idx) {
    let s = '', n = idx + 1;
    while (n > 0) { const m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = Math.floor((n - m) / 26); }
    return s;
  }

  function textCell(r, c, value, sIdx) {
    return '<c r="' + colLetter(c) + r + '" s="' + sIdx + '" t="inlineStr"><is><t xml:space="preserve">' + escXml(String(value)) + '</t></is></c>';
  }
  function numCell(r, c, value, sIdx) {
    if (value === '' || value == null) return '<c r="' + colLetter(c) + r + '" s="' + sIdx + '"/>';
    return '<c r="' + colLetter(c) + r + '" s="' + sIdx + '"><v>' + (isNaN(value) ? '0' : value) + '</v></c>';
  }

  function buildStylesXml() {
    const fonts = ['<font><sz val="11"/><name val="Calibri"/></font>'];
    XL_KEYS.slice(1).forEach((k) => {
      const st = XL_STYLE[k];
      fonts.push('<font>' + (st.bold ? '<b/>' : '') + '<sz val="11"/>' + (st.font ? '<color rgb="' + st.font + '"/>' : '') + '<name val="Calibri"/></font>');
    });
    const fills = [
      '<fill><patternFill patternType="none"/></fill>',
      '<fill><patternFill patternType="gray125"/></fill>',
      ...XL_KEYS.slice(1).map((k) => '<fill><patternFill patternType="solid"><fgColor rgb="' + XL_STYLE[k].fill + '"/><bgColor indexed="64"/></patternFill></fill>')
    ];
    const borders = [
      '<border><left/><right/><top/><bottom/><diagonal/></border>',
      '<border><left style="thin"><color rgb="FF9AA7BC"/></left><right style="thin"><color rgb="FF9AA7BC"/></right><top style="thin"><color rgb="FF9AA7BC"/></top><bottom style="thin"><color rgb="FF9AA7BC"/></bottom><diagonal/></border>'
    ];
    const cellXfs = XL_KEYS.map((k, i) => {
      const fid = k === 'plain' ? 0 : XL_FILL_IDX[k];
      return '<xf numFmtId="0" fontId="' + i + '" fillId="' + fid + '" borderId="1" xfId="0"' +
        (i === 0 ? '' : ' applyFont="1"') + ' applyFill="' + (fid ? '1' : '0') + '" applyBorder="1"><alignment vertical="center"/></xf>';
    });
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
      '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
      '<fonts count="' + fonts.length + '">' + fonts.join('') + '</fonts>' +
      '<fills count="' + fills.length + '">' + fills.join('') + '</fills>' +
      '<borders count="2">' + borders.join('') + '</borders>' +
      '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
      '<cellXfs count="' + cellXfs.length + '">' + cellXfs.join('') + '</cellXfs>' +
      '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
      '<dxfs count="0"/><tableStyles count="0" defaultTableStyle="TableStyleMedium9" defaultPivotStyle="PivotStyleLight16"/>' +
      '</styleSheet>';
  }

  function xlsxSheetXml(rows) {
    const s = summary();
    const lastCol = colLetter(XL_COLS.length - 1);
    const start = 5;
    const lastRow = start + rows.length;
    const stO = (lvl) => (XL_LEVEL_STYLE[lvl] != null ? XL_LEVEL_STYLE[lvl] : XL_STYLE_INDEX.unknown);

    let out = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:' + lastCol + lastRow + '"/>';
    out += '<sheetViews><sheetView workbookViewId="0" tabSelected="1"><pane ySplit="' + (start - 1) + '" topLeftCell="A' + start + '" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A' + start + '" sqref="A' + start + '"/></sheetView></sheetViews>';
    out += '<sheetFormatPr defaultRowHeight="15"/>';
    out += '<cols>' + XL_WIDTHS.map((w, i) => '<col min="' + (i + 1) + '" max="' + (i + 1) + '" width="' + w + '" customWidth="1"/>').join('') + '</cols>';
    out += '<sheetData>';

    out += '<row r="1" ht="20" customHeight="1">' + textCell(1, 0, 'GOVERNMENT SITE CHECKER - PHILIPPINE GOVERNMENT WEBSITES', XL_STYLE_INDEX.header) + '</row>';
    out += '<row r="2">' + textCell(2, 0, 'Generated: ' + new Date().toLocaleString() + '  |  Developer: Clark Fajardo', XL_STYLE_INDEX.unknown) + '</row>';
    out += '<row r="3" ht="16" customHeight="1">' + textCell(3, 0, 'Total: ' + s.total + ' | Online: ' + s.up + ' | Down: ' + s.down + ' | Server Errors: ' + s.error + ' | Blocked: ' + s.blocked + ' | Breached: ' + s.breach + ' | Exposed: ' + s.exposed + ' | At Risk: ' + s.risk, XL_STYLE_INDEX.up) + '</row>';
    out += '<row r="4"/>';

    out += '<row r="5">' + XL_COLS.map((c, i) => textCell(5, i, c, XL_STYLE_INDEX.header)).join('') + '</row>';

    rows.forEach((r, i) => {
      const rn = start + 1 + i;
      const si = stO(r.level);
      out += '<row r="' + rn + '">';
      out += textCell(rn, 0, r.name, si) + textCell(rn, 1, r.url, si) + textCell(rn, 2, r.status, si);
      out += numCell(rn, 3, r.code, si) + numCell(rn, 4, r.ms, si);
      out += textCell(rn, 5, r.hsts, si) + textCell(rn, 6, r.csp, si) + textCell(rn, 7, r.xframe, si);
      out += textCell(rn, 8, r.exposed, si) + textCell(rn, 9, r.breachLevel, si) + textCell(rn, 10, r.detail, si);
      out += '</row>';
    });

    out += '</sheetData>';
    out += '<mergeCells count="2"><mergeCell ref="A1:' + lastCol + '1"/><mergeCell ref="A3:' + lastCol + '3"/></mergeCells>';
    out += '<autoFilter ref="A' + start + ':' + lastCol + lastRow + '"/>';
    out += '<pageMargins left="0.7" right="0.7" top="0.5" bottom="0.5" header="0.3" footer="0.3"/>';
    out += '</worksheet>';
    return out;
  }

  const contentTypesXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
    '<Default Extension="xml" ContentType="application/xml"/>' +
    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
    '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' +
    '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
    '</Types>';

  const rootRelsXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
    '</Relationships>';

  const workbookXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' +
    '<sheets><sheet name="GovSite Report" sheetId="1" r:id="rId1"/></sheets>' +
    '</workbook>';

  const workbookRelsXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>' +
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' +
    '</Relationships>';

  // -------- minimal ZIP (STORE, no compression) for xlsx --------
  const CRC_TABLE = (function () {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; }
    return t;
  })();

  function crc32(bytes) {
    let c = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }

  function makeXlsx(parts) {
    const enc = new TextEncoder();
    const now = new Date();
    const dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | Math.floor(now.getSeconds() / 2);
    const dosDate = (((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate()) & 0xFFFF;

    let total = 22;
    parts.forEach((p) => { p._nb = enc.encode(p.name); total += 30 + p._nb.length + p.data.length; });
    parts.forEach((p) => { total += 46 + p._nb.length; });

    const buf = new Uint8Array(total);
    const dv = new DataView(buf.buffer);
    let o = 0;
    const offs = [];
    const hdr = (sig) => { dv.setUint32(o, sig, true); o += 4; };
    const w16 = (v) => { dv.setUint16(o, v, true); o += 2; };
    const w32 = (v) => { dv.setUint32(o, v, true); o += 4; };

    parts.forEach((p) => {
      const crc = crc32(p.data);
      offs.push(o);
      hdr(0x04034b50); w16(20); w16(0x0800); w16(0);
      w16(dosTime); w16(dosDate);
      w32(crc); w32(p.data.length); w32(p.data.length);
      w16(p._nb.length); w16(0);
      buf.set(p._nb, o); o += p._nb.length;
      buf.set(p.data, o); o += p.data.length;
      p._crc = crc;
    });

    const cdStart = o;
    parts.forEach((p, i) => {
      hdr(0x02014b50); w16(20); w16(20); w16(0x0800); w16(0);
      w16(dosTime); w16(dosDate);
      w32(p._crc); w32(p.data.length); w32(p.data.length);
      w16(p._nb.length); w16(0); w16(0);
      w16(0); w16(0); w32(0);
      w32(offs[i]);
      buf.set(p._nb, o); o += p._nb.length;
    });

    const cdSize = o - cdStart;
    hdr(0x06054b50); w16(0); w16(0); w16(parts.length); w16(parts.length);
    w32(cdSize); w32(cdStart); w16(0);
    return buf;
  }

  function exportExcel() {
    const rows = reportRows();
    const enc = new TextEncoder();
    const parts = [
      { name: '[Content_Types].xml', data: enc.encode(contentTypesXml) },
      { name: '_rels/.rels', data: enc.encode(rootRelsXml) },
      { name: 'xl/workbook.xml', data: enc.encode(workbookXml) },
      { name: 'xl/_rels/workbook.xml.rels', data: enc.encode(workbookRelsXml) },
      { name: 'xl/worksheets/sheet1.xml', data: enc.encode(xlsxSheetXml(rows)) },
      { name: 'xl/styles.xml', data: enc.encode(buildStylesXml()) }
    ];
    const zip = makeXlsx(parts);
    const blob = new Blob([zip.buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'government-site-report.xlsx';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1500);
  }

  // ---------------- CSV export ----------------
  function exportCsv() {
    const rows = reportRows();
    const header = ['Site', 'URL', 'Status', 'HTTP Code', 'Response (ms)', 'HSTS', 'CSP', 'X-Frame', 'Exposed Files', 'Breach Classification', 'Detail / Notes'];
    const lines = [header.join(',')];
    rows.forEach((r) => {
      lines.push([r.name, r.url, r.status, r.code, r.ms, r.hsts, r.csp, r.xframe, r.exposed, r.breachLevel, r.detail]
        .map((v) => '"' + String(v).replace(/"/g, '""') + '"').join(','));
    });
    const s = summary();
    lines.unshift('');
    lines.unshift('Government Site Checker Report — ' + new Date().toLocaleString() + ' — Developer: Clark Fajardo');
    lines.unshift('Total,' + s.total + ',Online,' + s.up + ',Down,' + s.down + ',ServerErr,' + s.error + ',Blocked,' + s.blocked + ',Breached,' + s.breach + ',Exposed,' + s.exposed + ',AtRisk,' + s.risk);
    downloadBlob('text/csv;charset=utf-8', '\uFEFF' + lines.join('\r\n'), 'government-site-report.csv');
  }

  // ---------------- copy report ----------------
  function copyReport() {
    const rows = reportRows();
    const lines = ['GOVERNMENT SITE CHECKER REPORT — ' + new Date().toLocaleString() + ' — Developer: Clark Fajardo'];
    const s = summary();
    lines.push('Total: ' + s.total + ' | Online: ' + s.up + ' | Down: ' + s.down + ' | Server Errors: ' + s.error + ' | Blocked: ' + s.blocked + ' | Breached: ' + s.breach + ' | Exposed: ' + s.exposed + ' | At Risk: ' + s.risk);
    lines.push('');
    lines.push('Site | URL | Status | HTTP | Time(ms) | Breach Classification | Notes');
    rows.forEach((r) => {
      lines.push(r.name + ' | ' + r.url + ' | ' + r.status + ' | ' + r.code + ' | ' + r.ms + ' | ' + r.breachLevel + ' | ' + r.detail);
    });
    const txt = lines.join('\n');
    if (navigator.clipboard) {
      navigator.clipboard.writeText(txt).then(() => flashCopy('Report copied to clipboard.')).catch(() => manualCopy(txt));
    } else {
      manualCopy(txt);
    }
  }

  function manualCopy(txt) {
    const ta = document.createElement('textarea');
    ta.value = txt;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    flashCopy('Report copied to clipboard.');
  }

  function flashCopy(msg) {
    const old = $('#btnCopyReport').textContent;
    $('#btnCopyReport').textContent = '\u2713 ' + msg;
    setTimeout(() => { $('#btnCopyReport').textContent = old; }, 2200);
  }

  function downloadBlob(mime, content, filename) {
    const blob = new Blob([content], { type: mime });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1500);
  }

  // ---------------- add url ----------------
  function addCustomUrls(raw) {
    const parts = raw.split(/[,\n\r]+/).map((s) => s.trim()).filter(Boolean).map(normalizeUrl);
    const existing = new Set(Object.keys(namesByUrl()).map(normalizeUrl));
    const newOnes = [];
    parts.forEach((u) => {
      if (!existing.has(u) && !newOnes.includes(u)) {
        state.custom.push({ name: hostOf(u), url: u });
        newOnes.push(u);
      }
    });
    newOnes.forEach((u) => { state.checked[u] = true; });
    $('#customUrl').value = '';
    updateCheckButtons();
    return unique([...Object.keys(namesByUrl()).map(normalizeUrl)]);
  }

  // ---------------- events ----------------
  function wire() {
    $('#btnCheckSel').addEventListener('click', () => doCheck(selectedUrls()));
    $('#btnCheckAll').addEventListener('click', () => doCheck(allUrls()));
    $('#btnCheckDown').addEventListener('click', () => doCheck(downUrls()));
    $('#btnCheckFailed').addEventListener('click', () => doCheck(flaggedUrls()));
    $('#btnBreachScan').addEventListener('click', () => {
      if (!state.key) { openModal(); return; }
      breachScan(true);
    });
    $('#btnLive').addEventListener('click', () => setLive(!liveOn));
    $('#liveInterval').addEventListener('change', () => { if (liveOn) { liveCd = liveInterval(); $('#btnLive').textContent = 'LIVE (' + liveCd + 's)'; } });
    $('#btnAddUrl').addEventListener('click', () => doCheck(addCustomUrls($('#customUrl').value)));
    $('#customUrl').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#btnAddUrl').click(); });

    $('#btnExportExcel').addEventListener('click', () => { if (Object.keys(state.results).length) exportExcel(); });
    $('#btnExportCsv').addEventListener('click', () => { if (Object.keys(state.results).length) exportCsv(); });
    $('#btnCopyReport').addEventListener('click', () => { if (Object.keys(state.results).length) copyReport(); });

    $('#search').addEventListener('input', (e) => { searchTerm = e.target.value.trim(); buildSidebar(); });

    $('#btnSettings').addEventListener('click', () => { $('#hibpKey').value = state.key; openModal(); });
    $('#btnKeyCancel').addEventListener('click', closeModal);
    $('#btnKeySave').addEventListener('click', () => {
      state.key = $('#hibpKey').value.trim();
      localStorage.setItem('hibpKey', state.key);
      closeModal();
      if (Object.keys(state.results).length) breachScan(false);
    });
    $('#btnKeyClear').addEventListener('click', () => {
      state.key = ''; localStorage.removeItem('hibpKey'); $('#hibpKey').value = ''; closeModal();
    });
    $('#modal').addEventListener('click', (e) => { if (e.target === $('#modal')) closeModal(); });

    // Tab switching
    document.querySelectorAll('.tab').forEach((tab) => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
      });
    });

    // OSINT tool events
    wireOsint();
  }

  function openModal() { $('#modal').classList.remove('hidden'); }
  function closeModal() { $('#modal').classList.add('hidden'); }

  // ---------------- OSINT Tools ----------------
  function wireOsint() {
    $('#btnIpLookup').addEventListener('click', doIpLookup);
    $('#ipInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doIpLookup(); });

    $('#btnReverseIp').addEventListener('click', doReverseIp);
    $('#reverseIpInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doReverseIp(); });

    $('#btnDnsLookup').addEventListener('click', doDnsLookup);
    $('#dnsInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doDnsLookup(); });

    $('#btnWhoisLookup').addEventListener('click', doWhoisLookup);
    $('#whoisInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doWhoisLookup(); });

    $('#btnSslCheck').addEventListener('click', doSslCheck);
    $('#sslInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doSslCheck(); });

    $('#btnPortScan').addEventListener('click', doPortScan);
    $('#portInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doPortScan(); });

    $('#btnTechDetect').addEventListener('click', doTechDetect);
    $('#techInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doTechDetect(); });

    $('#btnSubdomain').addEventListener('click', doSubdomain);
    $('#subdomainInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doSubdomain(); });

    $('#btnSecHeaders').addEventListener('click', doSecHeaders);
    $('#secHeadersInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doSecHeaders(); });

    $('#btnDorks').addEventListener('click', doDorks);
    $('#dorkInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doDorks(); });

    $('#btnUrlhaus').addEventListener('click', doUrlhaus);

    $('#btnEmailAnalyze').addEventListener('click', doEmailAnalyze);

    $('#btnReputationCheck').addEventListener('click', doReputationCheck);
    $('#reputationInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doReputationCheck(); });
  }

  function showOsintLoading(elId) {
    const el = document.getElementById(elId);
    el.innerHTML = '<div class="osint-loading">Querying...</div>';
    el.classList.add('visible');
  }

  function showOsintError(elId, msg) {
    const el = document.getElementById(elId);
    el.innerHTML = '<div class="osint-error">Error: ' + escHtml(msg) + '</div>';
    el.classList.add('visible');
  }

  function requireServer(elId) {
    if (hasServer) return true;
    showOsintError(elId, 'Server not available. This OSINT tool requires running the Python backend locally (python3 server.py). On GitHub Pages, only site checking and email analysis work client-side.');
    return false;
  }

  async function osintPost(path, body) {
    if (hasServer) {
      const res = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      return await res.json();
    }
    return null;
  }

  function osintTable(rows, sectionLabel) {
    let html = '';
    if (sectionLabel) html += '<div class="osint-section">' + escHtml(sectionLabel) + '</div>';
    html += '<table>';
    rows.forEach(([k, v, cls, raw]) => {
      const val = (v === null || v === undefined) ? '-' : (raw ? String(v) : escHtml(String(v)));
      html += '<tr><td>' + escHtml(k) + '</td><td' + (cls ? ' class="' + escHtml(cls) + '"' : '') + '>' + val + '</td></tr>';
    });
    html += '</table>';
    return html;
  }

  async function doIpLookup() {
    const ip = $('#ipInput').value.trim();
    if (!ip) { showOsintError('ipResults', 'Please enter an IP address.'); return; }
    showOsintLoading('ipResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/ip-geolocate', { ip });
      } else {
        let res;
        try {
          res = await fetch('https://ipapi.co/' + encodeURIComponent(ip) + '/json/');
          data = await res.json();
          if (data.error) { data.error = data.reason || 'Lookup failed'; }
          else {
            data.query = data.ip;
            data.country = data.country_name;
            data.countryCode = data.country_code;
            data.regionName = data.region;
            data.lat = data.latitude;
            data.lon = data.longitude;
            data.org = data.org;
            data.barangay = data.district || null;
          }
        } catch (e1) {
          try {
            res = await fetch('https://ipwho.is/' + encodeURIComponent(ip));
            data = await res.json();
            if (!data.success) { data.error = data.message || 'Lookup failed'; }
            else {
              data.query = data.ip;
              data.country = data.country;
              data.countryCode = data.country_code;
              data.regionName = data.region;
              data.city = data.city;
              data.zip = data.postal;
              data.lat = data.latitude;
              data.lon = data.longitude;
              data.timezone = data.timezone?.id;
              data.isp = data.connection?.isp;
              data.org = data.connection?.org;
              data.as = data.connection?.asn;
              data.barangay = data.district || null;
            }
          } catch (e2) {
            data = { error: 'All geolocation APIs failed. Check your connection.' };
          }
        }
      }
      if (data.error) { showOsintError('ipResults', data.error); return; }
      const el = document.getElementById('ipResults');
      const country = data.country || '-';
      const countryCode = data.countryCode ? ' (' + data.countryCode + ')' : '';
      const rows = [
        ['IP Address', data.query || ip],
        ['Country', country + countryCode],
        ['Region', data.regionName || '-'],
        ['City', data.city || '-'],
        ['Barangay / District', data.barangay || '-'],
        ['Zip Code', data.zip || '-'],
        ['Latitude', data.lat != null ? data.lat : '-'],
        ['Longitude', data.lon != null ? data.lon : '-'],
        ['Timezone', data.timezone || '-'],
        ['ISP', data.isp || '-'],
        ['Organization', data.org || '-'],
        ['AS Number', data.as || '-']
      ];
      el.innerHTML = osintTable(rows, 'Geolocation Result');
      el.classList.add('visible');
    } catch (err) {
      showOsintError('ipResults', err.message);
    }
  }

  async function doReverseIp() {
    const ip = $('#reverseIpInput').value.trim();
    if (!ip) { showOsintError('reverseIpResults', 'Please enter an IP address.'); return; }
    showOsintLoading('reverseIpResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/reverse-ip', { ip });
      } else {
        let primaryHostname = null;
        try { primaryHostname = (await (await fetch('https://dns.google/resolve?name=' + encodeURIComponent(ip) + '&type=PTR')).json()).Answer?.[0]?.data?.replace(/\.$/, '') || null; } catch (e) { /* ok */ }
        const apiRes = await fetch('https://api.hackertarget.com/reverseiplookup/?q=' + encodeURIComponent(ip));
        const text = await apiRes.text();
        const domains = text.split('\n').filter((l) => l.trim() && !l.startsWith('error') && !l.startsWith('API'));
        data = { ip, primaryHostname, domains, totalDomains: domains.length };
      }
      if (data.error) { showOsintError('reverseIpResults', data.error); return; }
      const el = document.getElementById('reverseIpResults');
      let html = osintTable([
        ['IP Address', data.ip],
        ['Primary Hostname', data.primaryHostname || '-'],
        ['Domains Found', data.totalDomains || 0]
      ], 'Reverse IP Lookup');
      if (data.domains && data.domains.length) {
        html += '<div class="osint-section">Hosted Domains</div><ul style="margin:4px 0;padding-left:18px;max-height:200px;overflow-y:auto;">';
        data.domains.forEach((d) => { html += '<li>' + escHtml(d) + '</li>'; });
        html += '</ul>';
      }
      el.innerHTML = html;
      el.classList.add('visible');
    } catch (err) {
      showOsintError('reverseIpResults', err.message);
    }
  }

  async function doDnsLookup() {
    const domain = $('#dnsInput').value.trim();
    if (!domain) { showOsintError('dnsResults', 'Please enter a domain.'); return; }
    showOsintLoading('dnsResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/dns', { domain });
      } else {
        const records = {};
        const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV'];
        for (const t of types) {
          try {
            const res = await fetch('https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=' + t);
            const j = await res.json();
            if (j.Answer && j.Answer.length) {
              records[t] = j.Answer.filter((a) => a.type === ({A:1,AAAA:28,MX:15,NS:2,TXT:16,SOA:6,CNAME:5,SRV:33}[t])).map((a) => a.data);
              if (!records[t].length) delete records[t];
            }
          } catch (e) { /* skip */ }
        }
        const reverseDns = [];
        for (const ip of (records.A || [])) {
          try {
            const res = await fetch('https://dns.google/resolve?name=' + encodeURIComponent(ip) + '&type=PTR');
            const j = await res.json();
            reverseDns.push({ ip, hostname: j.Answer?.[0]?.data?.replace(/\.$/, '') || null });
          } catch (e) {
            reverseDns.push({ ip, hostname: null });
          }
        }
        data = { domain, records, reverseDns, totalRecords: Object.values(records).reduce((n, a) => n + a.length, 0) };
      }
      if (data.error) { showOsintError('dnsResults', data.error); return; }
      const el = document.getElementById('dnsResults');
      let html = osintTable([
        ['Domain', data.domain],
        ['Total Records', data.totalRecords]
      ], 'DNS Enumeration');
      const recordTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV'];
      recordTypes.forEach((rt) => {
        if (data.records[rt] && data.records[rt].length) {
          html += '<div class="osint-section">' + escHtml(rt) + ' Records</div><ul style="margin:4px 0;padding-left:18px;">';
          data.records[rt].forEach((r) => { html += '<li><code>' + escHtml(r) + '</code></li>'; });
          html += '</ul>';
        }
      });
      if (data.reverseDns && data.reverseDns.length) {
        html += '<div class="osint-section">Reverse DNS</div><table>';
        data.reverseDns.forEach((r) => {
          html += '<tr><td><code>' + escHtml(r.ip) + '</code></td><td>' + escHtml(r.hostname || 'No PTR') + '</td></tr>';
        });
        html += '</table>';
      }
      el.innerHTML = html;
      el.classList.add('visible');
    } catch (err) {
      showOsintError('dnsResults', err.message);
    }
  }

  async function doWhoisLookup() {
    const domain = $('#whoisInput').value.trim();
    if (!domain) { showOsintError('whoisResults', 'Please enter a domain.'); return; }
    showOsintLoading('whoisResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/whois', { domain });
      } else {
        const res = await fetch('https://rdap.org/domain/' + encodeURIComponent(domain));
        if (!res.ok) { data = { domain, error: 'Domain not found in RDAP database' }; }
        else {
          const parsed = await res.json();
          data = { domain };
          for (const ev of (parsed.events || [])) {
            if (ev.eventAction === 'registration') data.created = ev.eventDate;
            if (ev.eventAction === 'expiration') data.expires = ev.eventDate;
            if (ev.eventAction === 'last update of RDAP database') data.updated = ev.eventDate;
          }
          for (const ent of (parsed.entities || [])) {
            if (ent.vcardArray) {
              for (const f of ent.vcardArray[1] || []) {
                if (f[0] === 'fn') data.registrar = f[3] || '';
              }
            }
          }
          data.status = (parsed.status || []).filter((s) => typeof s === 'string');
          data.nameServers = (parsed.nameservers || []).map((n) => n.ldhName).filter(Boolean);
          data.rawText = JSON.stringify(parsed, null, 2).slice(0, 3000);
        }
      }
      if (data.error) { showOsintError('whoisResults', data.error); return; }
      const el = document.getElementById('whoisResults');
      let html = osintTable([
        ['Domain', data.domain],
        ['Registrar', data.registrar],
        ['Created', data.created],
        ['Expires', data.expires],
        ['Updated', data.updated],
        ['Status', data.status ? data.status.join(', ') : '-'],
        ['Name Servers', data.nameServers ? escHtml(data.nameServers.join(', ')) : '-']
      ], 'WHOIS Result');
      if (data.rawText) {
        html += '<div class="osint-section">Raw WHOIS Data</div>';
        html += '<pre style="white-space:pre-wrap;font-size:11px;color:var(--muted);margin-top:4px;">' + escHtml(data.rawText) + '</pre>';
      }
      el.innerHTML = html;
      el.classList.add('visible');
    } catch (err) {
      showOsintError('whoisResults', err.message);
    }
  }

  async function doSslCheck() {
    const domain = $('#sslInput').value.trim();
    if (!domain) { showOsintError('sslResults', 'Please enter a domain.'); return; }
    showOsintLoading('sslResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/ssl', { domain });
      } else {
        showOsintError('sslResults', 'SSL/TLS analysis requires the Python server (socket access needed). Run locally: python3 server.py');
        return;
      }
      if (data.error) { showOsintError('sslResults', data.error); return; }
      const el = document.getElementById('sslResults');
      const issuer = data.issuer || {};
      const subject = data.subject || {};
      let html = osintTable([
        ['Domain', data.domain],
        ['Port', data.port],
        ['Subject CN', subject.commonName || subject.CN || '-'],
        ['Issuer CN', issuer.commonName || issuer.CN || '-'],
        ['Issuer Org', issuer.organizationName || issuer.O || '-'],
        ['Serial', data.serialNumber || '-'],
        ['Valid From', data.notBefore || '-'],
        ['Valid Until', data.notAfter || '-'],
        ['Days Until Expiry', data.daysUntilExpiry != null ? data.daysUntilExpiry : '-'],
        ['Expired', data.expired ? 'YES' : 'No'],
        ['Protocol', data.protocol || '-'],
        ['Cipher', data.cipher ? data.cipher.name + ' (' + data.cipher.bits + ' bits)' : '-']
      ], 'SSL/TLS Certificate');
      if (data.subjectAltName && data.subjectAltName.length) {
        html += '<div class="osint-section">Subject Alternative Names</div><ul style="margin:4px 0;padding-left:18px;">';
        data.subjectAltName.forEach((s) => { html += '<li><code>' + escHtml(s) + '</code></li>'; });
        html += '</ul>';
      }
      el.innerHTML = html;
      el.classList.add('visible');
    } catch (err) {
      showOsintError('sslResults', err.message);
    }
  }

  async function doPortScan() {
    const domain = $('#portInput').value.trim();
    if (!domain) { showOsintError('portResults', 'Please enter a domain or IP.'); return; }
    showOsintLoading('portResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/ports', { domain });
      } else {
        showOsintError('portResults', 'Port scanning requires the Python server (socket access needed). Run locally: python3 server.py');
        return;
      }
      if (data.error) { showOsintError('portResults', data.error); return; }
      const el = document.getElementById('portResults');
      let html = osintTable([
        ['Domain', data.domain],
        ['Resolved IP', data.ip || '-'],
        ['Ports Scanned', data.scannedPorts],
        ['Open Ports', data.openPorts.length],
        ['Closed Ports', data.closedPorts.length]
      ], 'Port Scan Results');
      if (data.openPorts && data.openPorts.length) {
        html += '<div class="osint-section">Open Ports</div><table>';
        data.openPorts.forEach((p) => {
          html += '<tr><td><code class="osint-ok">' + escHtml(String(p.port)) + '</code></td><td>' + escHtml(p.service) + '</td></tr>';
        });
        html += '</table>';
      }
      el.innerHTML = html;
      el.classList.add('visible');
    } catch (err) {
      showOsintError('portResults', err.message);
    }
  }

  async function doTechDetect() {
    const url = $('#techInput').value.trim();
    if (!url) { showOsintError('techResults', 'Please enter a URL.'); return; }
    showOsintLoading('techResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/tech', { url });
      } else {
        try {
          const res = await fetch(url, { mode: 'no-cors' });
          data = { url, finalUrl: url, statusCode: 0, technologies: {} };
          const hdrs = {};
          res.headers.forEach((v, k) => { hdrs[k.toLowerCase()] = v; });
          const server = hdrs['server'] || '';
          if (server) data.technologies = { server: [server.split('/')[0].trim()] };
          else data.technologies = {};
        } catch (e) {
          data = { url, error: 'Client-side tech detection failed: ' + e.message };
        }
      }
      if (data.error) { showOsintError('techResults', data.error); return; }
      const el = document.getElementById('techResults');
      let html = osintTable([
        ['URL', data.url],
        ['Final URL', data.finalUrl || '-'],
        ['Status Code', data.statusCode || '-']
      ], 'Technology Detection');
      const tech = data.technologies || {};
      const categories = { server: 'Web Server', language: 'Programming Language', cms: 'CMS', framework: 'Framework', analytics: 'Analytics', cdn: 'CDN', headers: 'Custom Headers' };
      Object.keys(categories).forEach((cat) => {
        if (tech[cat] && tech[cat].length) {
          html += '<div class="osint-section">' + escHtml(categories[cat]) + '</div><ul style="margin:4px 0;padding-left:18px;">';
          tech[cat].forEach((t) => { html += '<li>' + escHtml(t) + '</li>'; });
          html += '</ul>';
        }
      });
      if (Object.keys(tech).length === 0) {
        html += '<div class="osint-warn">No technologies detected.</div>';
      }
      el.innerHTML = html;
      el.classList.add('visible');
    } catch (err) {
      showOsintError('techResults', err.message);
    }
  }

  async function doSubdomain() {
    const domain = $('#subdomainInput').value.trim();
    if (!domain) { showOsintError('subdomainResults', 'Please enter a domain.'); return; }
    showOsintLoading('subdomainResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/subdomains', { domain });
      } else {
        const subs = ['www','mail','ftp','smtp','pop','imap','webmail','mx','ns1','ns2','ns3','dns','api','dev','staging','test','admin','portal','vpn','cdn','static','blog','shop','app','login','monitor','status','git','jenkins','ci','db','redis','owa','cpanel'];
        const found = [];
        const check = async (s) => {
          try {
            const r = await fetch('https://dns.google/resolve?name=' + encodeURIComponent(s + '.' + domain) + '&type=A');
            const j = await r.json();
            if (j.Answer && j.Answer.some((a) => a.type === 1)) return { subdomain: s + '.' + domain, ips: j.Answer.filter((a) => a.type === 1).map((a) => a.data) };
          } catch (e) { /* skip */ }
          return null;
        };
        for (let i = 0; i < subs.length; i += 10) {
          const batch = subs.slice(i, i + 10);
          const results = await Promise.all(batch.map(check));
          results.filter(Boolean).forEach((r) => found.push(r));
        }
        found.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
        data = { domain, found, checked: subs.length, totalFound: found.length };
      }
      if (data.error) { showOsintError('subdomainResults', data.error); return; }
      const el = document.getElementById('subdomainResults');
      let html = osintTable([
        ['Domain', data.domain],
        ['Subdomains Checked', data.checked],
        ['Subdomains Found', data.totalFound]
      ], 'Subdomain Discovery');
      if (data.found && data.found.length) {
        html += '<div class="osint-section">Discovered Subdomains</div><table>';
        data.found.forEach((s) => {
          html += '<tr><td><code class="osint-ok">' + escHtml(s.subdomain) + '</code></td><td>' + escHtml(s.ips.join(', ')) + '</td></tr>';
        });
        html += '</table>';
      }
      el.innerHTML = html;
      el.classList.add('visible');
    } catch (err) {
      showOsintError('subdomainResults', err.message);
    }
  }

  async function doSecHeaders() {
    const url = $('#secHeadersInput').value.trim();
    if (!url) { showOsintError('secHeadersResults', 'Please enter a URL.'); return; }
    showOsintLoading('secHeadersResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/security-headers', { url });
      } else {
        const res = await fetch(url, { mode: 'no-cors' });
        const hdrs = {};
        try { res.headers.forEach((v, k) => { hdrs[k.toLowerCase()] = v; }); } catch (e) { /* no-cors */ }
        const checks = [
          ['strict-transport-security', 'HSTS', 2],
          ['content-security-policy', 'CSP', 2],
          ['x-frame-options', 'XFO', 1],
          ['x-content-type-options', 'XCTO', 1],
          ['referrer-policy', 'RP', 1],
          ['permissions-policy', 'PP', 1]
        ];
        let score = 0, maxScore = 0;
        const headers = {}, findings = [];
        checks.forEach(([k, name, pts]) => {
          maxScore += pts;
          if (hdrs[k]) { score += pts; headers[name] = { name: k, value: hdrs[k], present: true }; findings.push({ header: k, status: 'present', value: hdrs[k] }); }
          else { headers[name] = { name: k, value: null, present: false }; findings.push({ header: k, status: 'missing', recommendation: name }); }
        });
        const grade = score >= maxScore * 0.8 ? 'A' : score >= maxScore * 0.6 ? 'B' : score >= maxScore * 0.4 ? 'C' : score >= maxScore * 0.2 ? 'D' : 'F';
        data = { url, finalUrl: url, statusCode: 0, score, maxScore, grade, headers, findings };
        findings.push({ header: 'Note', status: 'info', recommendation: 'Client-side check: limited header visibility (no-cors mode). For full analysis, run the Python server locally.' });
      }
      if (data.error) { showOsintError('secHeadersResults', data.error); return; }
      const el = document.getElementById('secHeadersResults');
      const gradeColor = { A: 'osint-ok', B: 'osint-ok', C: 'osint-warn', D: 'osint-error', F: 'osint-error' };
      let html = osintTable([
        ['URL', data.finalUrl || data.url],
        ['Status Code', data.statusCode || '-'],
        ['Security Score', data.score + ' / ' + data.maxScore],
        ['Grade', '<span class="' + (gradeColor[data.grade] || '') + '" style="font-size:18px;font-weight:700;">' + escHtml(data.grade) + '</span>', '', true]
      ], 'Security Headers Analysis');
      if (data.headers) {
        html += '<div class="osint-section">Header Details</div><table>';
        Object.entries(data.headers).forEach(([k, v]) => {
          const status = v.present ? 'osint-ok' : 'osint-warn';
          html += '<tr><td>' + escHtml(v.name) + '</td><td class="' + status + '">';
          html += v.present ? escHtml(v.value) : '<span class="osint-error">Missing</span>';
          html += '</td></tr>';
        });
        html += '</table>';
      }
      if (data.findings && data.findings.length) {
        html += '<div class="osint-section">Findings</div><ul style="margin:4px 0;padding-left:18px;max-height:200px;overflow-y:auto;">';
        data.findings.forEach((f) => {
          const cls = f.status === 'present' ? 'osint-ok' : f.status === 'info_leak' ? 'osint-warn' : 'osint-error';
          html += '<li class="' + cls + '">' + escHtml(f.header) + ': ' + escHtml(f.status === 'present' ? 'Present' : f.status === 'missing' ? 'Missing' : f.recommendation || f.status) + '</li>';
        });
        html += '</ul>';
      }
      el.innerHTML = html;
      el.classList.add('visible');
    } catch (err) {
      showOsintError('secHeadersResults', err.message);
    }
  }

  async function doDorks() {
    const domain = $('#dorkInput').value.trim();
    if (!domain) { showOsintError('dorkResults', 'Please enter a domain.'); return; }
    showOsintLoading('dorkResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/dorks', { domain });
      } else {
        const dorks = [
          { label: 'Login Pages', query: 'site:' + domain + ' inurl:login OR inurl:admin OR inurl:portal', risk: 'medium' },
          { label: 'Exposed Files', query: 'site:' + domain + ' filetype:pdf OR filetype:doc OR filetype:xlsx', risk: 'low' },
          { label: 'Error Messages', query: 'site:' + domain + ' intext:"error" OR intext:"warning" OR intext:"exception"', risk: 'medium' },
          { label: 'Directory Listing', query: 'site:' + domain + ' intitle:"index of"', risk: 'high' },
          { label: 'Config Files', query: 'site:' + domain + ' filetype:env OR filetype:yml OR filetype:conf OR filetype:ini', risk: 'high' },
          { label: 'SQL Errors', query: 'site:' + domain + ' intext:"sql" OR intext:"mysql" OR intext:"syntax error"', risk: 'high' },
          { label: 'Backup Files', query: 'site:' + domain + ' filetype:bak OR filetype:old OR filetype:tmp', risk: 'high' },
          { label: 'Email Addresses', query: 'site:' + domain + ' intext:"@"', risk: 'low' },
          { label: 'API Endpoints', query: 'site:' + domain + ' inurl:api OR inurl:v1 OR inurl:v2', risk: 'medium' },
          { label: 'Public Docs', query: 'site:' + domain + ' filetype:doc OR filetype:pdf "public"', risk: 'low' }
        ];
        data = { domain, dorks, totalDorks: dorks.length };
      }
      if (data.error) { showOsintError('dorkResults', data.error); return; }
      const el = document.getElementById('dorkResults');
      let html = osintTable([
        ['Domain', data.domain],
        ['Total Dorks', data.totalDorks]
      ], 'Google Dorking Queries');
      if (data.dorks && data.dorks.length) {
        html += '<table style="width:100%;">';
        data.dorks.forEach((d) => {
          const riskColor = d.risk === 'high' ? 'osint-error' : d.risk === 'medium' ? 'osint-warn' : 'osint-ok';
          html += '<tr><td style="width:200px;"><span class="' + riskColor + '">' + escHtml(d.label) + '</span></td>';
          html += '<td><code style="font-size:11px;word-break:break-all;">' + escHtml(d.query) + '</code></td>';
          html += '<td style="width:60px;text-align:center;"><a href="https://www.google.com/search?q=' + encodeURIComponent(d.query) + '" target="_blank" rel="noopener" style="color:var(--brand);">Search</a></td></tr>';
        });
        html += '</table>';
      }
      el.innerHTML = html;
      el.classList.add('visible');
    } catch (err) {
      showOsintError('dorkResults', err.message);
    }
  }

  async function doUrlhaus() {
    const urls = $('#urlhausInput').value.trim();
    if (!urls) { showOsintError('urlhausResults', 'Please enter URLs to check.'); return; }
    showOsintLoading('urlhausResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/urlhaus', { urls });
      } else {
        const urlArr = urls.split('\n').map((s) => s.trim()).filter(Boolean);
        data = [];
        for (const url of urlArr) {
          try {
            const res = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: 'url=' + encodeURIComponent(url)
            });
            const j = await res.json();
            data.push({
              url,
              found: j.query_status === 'online',
              threat: j.threat || null,
              urlStatus: j.url_status || null,
              tags: j.tags || [],
              dateAdded: j.date_added || null
            });
          } catch (e) {
            data.push({ url, found: false, note: 'Lookup failed: ' + e.message });
          }
        }
      }
      if (data.error) { showOsintError('urlhausResults', data.error); return; }
      const el = document.getElementById('urlhausResults');
      let html = '<div class="osint-section">URLhaus Malware Check</div><table>';
      data.forEach((d) => {
        const status = d.found ? 'osint-error' : 'osint-ok';
        html += '<tr><td style="max-width:300px;word-break:break-all;">' + escHtml(d.url) + '</td>';
        html += '<td class="' + status + '">';
        if (d.found) {
          html += '<strong>THREAT FOUND</strong><br>';
          html += 'Type: ' + escHtml(d.threat || '-') + '<br>';
          html += 'Status: ' + escHtml(d.urlStatus || '-') + '<br>';
          if (d.tags && d.tags.length) html += 'Tags: ' + escHtml(d.tags.join(', ')) + '<br>';
          if (d.dateAdded) html += 'Added: ' + escHtml(d.dateAdded);
        } else {
          html += 'Not found in URLhaus';
          if (d.note) html += '<br><small>' + escHtml(d.note) + '</small>';
        }
        html += '</td></tr>';
      });
      html += '</table>';
      el.innerHTML = html;
      el.classList.add('visible');
    } catch (err) {
      showOsintError('urlhausResults', err.message);
    }
  }

  async function doEmailAnalyze() {
    const header = $('#emailHeaderInput').value.trim();
    if (!header) { showOsintError('emailResults', 'Please paste email headers.'); return; }
    showOsintLoading('emailResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/email-header', { header });
      } else {
        data = { hops: [], auth: {} };
        const getHeader = (name) => {
          const regex = new RegExp('^' + name + ':\\s*(.+)$', 'mi');
          const m = header.match(regex);
          return m ? m[1].trim() : null;
        };
        data.from = getHeader('From');
        data.to = getHeader('To');
        data.subject = getHeader('Subject');
        data.date = getHeader('Date');
        const receivedHeaders = header.match(/^Received:.*$/gmi) || [];
        data.hops = receivedHeaders.map((line) => {
          const hop = {};
          const fromMatch = line.match(/from\s+([^\s;]+)/i);
          const byMatch = line.match(/by\s+([^\s;]+)/i);
          const ipMatch = line.match(/\[([0-9.]+)\]/);
          const dateMatch = line.match(/;\s*(.+)/);
          hop.from = fromMatch ? fromMatch[1] : null;
          hop.by = byMatch ? byMatch[1] : null;
          hop.ip = ipMatch ? ipMatch[1] : null;
          hop.date = dateMatch ? dateMatch[1].trim() : null;
          return hop;
        }).reverse();
        data.originIp = data.hops.length ? data.hops[0].ip : null;
        const spfMatch = header.match(/authentication-results.*spf=(\w+)/i);
        const dkimMatch = header.match(/authentication-results.*dkim=(\w+)/i);
        const dmarcMatch = header.match(/authentication-results.*dmarc=(\w+)/i);
        if (spfMatch) data.auth = { ...data.auth, spf: spfMatch[1], spfResult: spfMatch[1] };
        if (dkimMatch) data.auth = { ...data.auth, dkim: dkimMatch[1], dkimResult: dkimMatch[1] };
        if (dmarcMatch) data.auth = { ...data.auth, dmarc: dmarcMatch[1], dmarcResult: dmarcMatch[1] };
      }
      if (data.error) { showOsintError('emailResults', data.error); return; }
      const el = document.getElementById('emailResults');
      let html = '';

      if (data.from) html += osintTable([
        ['From', escHtml(data.from)],
        ['To', escHtml(data.to)],
        ['Subject', escHtml(data.subject)],
        ['Date', escHtml(data.date)]
      ], 'Email Metadata');

      if (data.hops && data.hops.length) {
        html += '<div class="osint-section">Mail Route (' + data.hops.length + ' hops)</div><table>';
        data.hops.forEach((h, i) => {
          const cls = i === 0 ? 'hop-origin' : 'hop';
          html += '<tr><td class="' + cls + '">Hop ' + (data.hops.length - i) + '</td><td class="' + cls + '">';
          html += escHtml(h.from || '?');
          if (h.ip) html += ' <code>[' + escHtml(h.ip) + ']</code>';
          html += ' &#8594; ' + escHtml(h.by || '?');
          if (h.date) html += '<br><small style="color:var(--muted)">' + escHtml(h.date) + '</small>';
          html += '</td></tr>';
        });
        html += '</table>';
      }

      if (data.originIp) {
        html += osintTable([
          ['Originating IP', data.originIp, 'osint-warn'],
          ['Location', data.originLocation || '-'],
          ['ISP', data.originIsp || '-']
        ], 'Origin IP Geolocation');
      }

      if (data.auth) {
        html += osintTable([
          ['SPF', data.auth.spf || '-', data.auth.spfResult === 'pass' ? 'osint-ok' : (data.auth.spfResult === 'fail' ? 'osint-error' : '')],
          ['DKIM', data.auth.dkim || '-', data.auth.dkimResult === 'pass' ? 'osint-ok' : ''],
          ['DMARC', data.auth.dmarc || '-', data.auth.dmarcResult === 'pass' ? 'osint-ok' : '']
        ], 'Authentication');
      }

      el.innerHTML = html || '<div class="osint-warn">No useful data found in the provided headers.</div>';
      el.classList.add('visible');
    } catch (err) {
      showOsintError('emailResults', err.message);
    }
  }

  async function doReputationCheck() {
    const domain = $('#reputationInput').value.trim();
    if (!domain) { showOsintError('reputationResults', 'Please enter a domain.'); return; }
    showOsintLoading('reputationResults');
    try {
      let data;
      if (hasServer) {
        data = await osintPost('/api/osint/domain-reputation', { domain });
      } else {
        data = { domain, safe: true, threats: [], categories: [], blacklisted: false };
        try {
          const res = await fetch('https://rdap.org/domain/' + encodeURIComponent(domain));
          if (res.ok) {
            const parsed = await res.json();
            data.registrar = null;
            for (const ent of (parsed.entities || [])) {
              if (ent.vcardArray) {
                for (const f of ent.vcardArray[1] || []) {
                  if (f[0] === 'fn') data.registrar = f[3];
                }
              }
            }
            for (const ev of (parsed.events || [])) {
              if (ev.eventAction === 'registration') data.created = ev.eventDate;
            }
            const status = parsed.status || [];
            if (status.some((s) => s.toLowerCase().includes('redemption'))) {
              data.threats.push('Redemption period');
              data.safe = false;
            }
            if (status.some((s) => s.toLowerCase().includes('pending delete'))) {
              data.threats.push('Pending deletion');
              data.safe = false;
            }
          }
        } catch (e) { /* ok, basic analysis only */ }
        if (data.threats.length === 0) data.threats = ['None detected via basic analysis'];
        data.categories = ['RDAP lookup (basic)'];
      }
      if (data.error) { showOsintError('reputationResults', data.error); return; }
      const el = document.getElementById('reputationResults');
      let html = osintTable([
        ['Domain', data.domain],
        ['Safe', data.safe ? '<span class="osint-ok">Yes</span>' : '<span class="osint-error">No</span>', '', true],
        ['Threats', data.threats && data.threats.length ? escHtml(data.threats.join(', ')) : '<span class="osint-ok">None detected</span>', '', true],
        ['Categories', data.categories && data.categories.length ? escHtml(data.categories.join(', ')) : '-'],
        ['Blacklisted', data.blacklisted ? '<span class="osint-error">Yes</span>' : '<span class="osint-ok">No</span>', '', true],
        ['Registrar', data.registrar || '-'],
        ['Created', data.created || '-']
      ], 'Reputation Report');
      el.innerHTML = html;
      el.classList.add('visible');
    } catch (err) {
      showOsintError('reputationResults', err.message);
    }
  }

  // ---------------- init ----------------
  async function init() {
    wire();
    try { await detectServer(); } catch (e) { hasServer = false; }
    if (hasServer === false) {
      const banner = document.createElement('div');
      banner.className = 'server-banner';
      banner.textContent = 'Running on GitHub Pages (static mode). Site checking works client-side via browser fetch. Server-based OSINT tools are unavailable.';
      const main = document.querySelector('.content');
      if (main) main.prepend(banner);
    }
    try { await loadCatalog(); } catch (e) { console.error('loadCatalog failed:', e); }
    if (state.key) $('#btnBreachScan').textContent = 'Breach Scan (HIBP ON)';
    if (localStorage.getItem('liveMode') === '1') setLive(true);
  }

  init().catch((e) => console.error(e));
})();