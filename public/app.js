(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);

  // ---------------- state ----------------
  const state = {
    catalog: [],          // [{category, sites:[{name,url}]}]
    checked: {},          // url -> true
    results: {},          // url -> {status,code,ms,error,hsts,csp,xframe,exposed[]}
    breach: {},           // host -> {breached,names[],note}
    key: localStorage.getItem('hibpKey') || '',
    custom: [],           // [{name,url}]
    checking: false,
    lastRun: null,
    progressTimer: null
  };

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
        switch (r.downReason) {
          case 'timeout':
            detail = 'No HTTP response within ' + (r.timeoutSec || '?') + 's on ' + tries + ' attempt(s). The site may be slow rather than down - open in a browser to confirm.';
            break;
          case 'refused':
            detail = 'Connection refused - nothing is listening on this port. If the browser opens it, the difference is usually a proxy or a WAF routing rule.';
            break;
          case 'reset':
            detail = 'The connection was dropped by a network filter / WAF (bot detection). It will typically open fine in a real browser - verify below.';
            break;
          case 'tls':
            detail = 'Secure handshake failed. Browser may still succeed if it negotiates a newer HTTP/2 or TLS profile.';
            break;
          default:
            detail = (r.error || 'No response received') + ' - verify in a browser.';
        }
      }
      return { level: 'down', label: 'DOWN', detail: r.remark ? r.remark + '\n\n' + detail : detail };
    }
    const host = hostOf(url);
    const b = state.breach[host];
    if (b && b.breached) return { level: 'breach', label: 'BREACHED', detail: (b.names || []).join(', ') || 'Listed in HaveIBeenPwned' };
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
    const res = await fetch('/api/sites');
    state.catalog = await res.json();
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
    nm.textContent = s.name;
    row.append(cb, dot, nm);
    return row;
  }

  function applyResultDots() {
    Object.keys(state.results).forEach((url) => {
      const el = document.getElementById('dot-' + url.replace(/[^a-z0-9]/gi, '_'));
      if (el) el.className = 'site-dot ' + classify(url).level;
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
      const res = await fetch('/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls, timeout: selectedTimeout() })
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      if (!Array.isArray(data)) throw new Error('Unexpected server response');
      const arr = data;
      arr.forEach((r) => { r.checkedAt = Date.now(); r.timeoutSec = selectedTimeout(); state.results[r.url] = r; });
      state.lastRun = new Date();
      renderResults();
      applyResultDots();
      updateCheckButtons();
      if (state.key) await breachScan(false);
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
      const res = await fetch('/api/osint/ip-geolocate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      if (data.error) { showOsintError('ipResults', data.error); return; }
      const el = document.getElementById('ipResults');
      const country = data.country || '-';
      const countryCode = data.countryCode ? ' (' + data.countryCode + ')' : '';
      el.innerHTML = osintTable([
        ['IP Address', data.query || ip],
        ['Country', country + countryCode],
        ['Region', data.regionName || '-'],
        ['City', data.city || '-'],
        ['Zip Code', data.zip || '-'],
        ['Latitude', data.lat != null ? data.lat : '-'],
        ['Longitude', data.lon != null ? data.lon : '-'],
        ['Timezone', data.timezone || '-'],
        ['ISP', data.isp || '-'],
        ['Organization', data.org || '-'],
        ['AS Number', data.as || '-']
      ], 'Geolocation Result');
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
      const res = await fetch('/api/osint/reverse-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
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
      const res = await fetch('/api/osint/dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const data = await res.json();
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
      const res = await fetch('/api/osint/whois', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const data = await res.json();
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
      const res = await fetch('/api/osint/ssl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const data = await res.json();
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
      const res = await fetch('/api/osint/ports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const data = await res.json();
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
      const res = await fetch('/api/osint/tech', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
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
      const res = await fetch('/api/osint/subdomains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const data = await res.json();
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
      const res = await fetch('/api/osint/security-headers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
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
      const res = await fetch('/api/osint/dorks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const data = await res.json();
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
      const res = await fetch('/api/osint/urlhaus', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls })
      });
      const data = await res.json();
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
      const res = await fetch('/api/osint/email-header', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ header })
      });
      const data = await res.json();
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
      const res = await fetch('/api/osint/domain-reputation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const data = await res.json();
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
    await loadCatalog();
    if (state.key) $('#btnBreachScan').textContent = 'Breach Scan (HIBP ON)';
    if (localStorage.getItem('liveMode') === '1') setLive(true);
  }

  init().catch((e) => console.error(e));
})();