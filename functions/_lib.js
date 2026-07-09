// Pure, Worker-independent helpers for the /ip endpoint.
// Importable directly by node:test — no Workers-only globals at import time.

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/** Escape the five HTML-significant characters. null/undefined → "". */
export function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

/** Header names (lowercase) omitted entirely from echo and storage. */
export const SENSITIVE_HEADERS = new Set([
  'cookie',
  'set-cookie',
  'authorization',
  'proxy-authorization',
  'cf-access-jwt-assertion',
  'cf-access-authenticated-user-email',
]);

/** Convert a Headers instance to a plain object with lowercased keys. */
export function headersToObject(headers) {
  const out = {};
  for (const [key, value] of headers) out[key.toLowerCase()] = value;
  return out;
}

/** Return a new header object with sensitive headers removed (case-insensitive). */
export function redactHeaders(obj) {
  const out = {};
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_HEADERS.has(key.toLowerCase())) continue;
    out[key] = value;
  }
  return out;
}

/** Read a header, returning null when absent. */
function header(obj, name) {
  return obj[name] ?? null;
}

/** Read a cf property, returning null when absent. */
function cf(request, key) {
  return request.cf && request.cf[key] !== undefined ? request.cf[key] : null;
}

/**
 * Extract the flat field record echoed + logged for a request.
 * Missing cf/header values are null. `headers` is the redacted header map.
 */
export function extractFields(request) {
  const all = headersToObject(request.headers);
  return {
    ts: new Date().toISOString(),
    ip: header(all, 'cf-connecting-ip'),
    country: cf(request, 'country'),
    city: cf(request, 'city'),
    asn: cf(request, 'asn'),
    colo: cf(request, 'colo'),
    method: request.method,
    path: new URL(request.url).pathname,
    http_ver: cf(request, 'httpProtocol'),
    user_agent: header(all, 'user-agent'),
    referer: header(all, 'referer'),
    accept_lang: header(all, 'accept-language'),
    tls_version: cf(request, 'tlsVersion'),
    tls_cipher: cf(request, 'tlsCipher'),
    headers: redactHeaders(all),
  };
}

export function renderJson(fields) {
  return fields;
}

/** Render one label/value row; value is escaped, null → em dash. */
function row(label, value) {
  const shown = value === null || value === undefined || value === ''
    ? '—'
    : escapeHtml(value);
  return `<tr><th>${escapeHtml(label)}</th><td>${shown}</td></tr>`;
}

/** Render the redacted headers map as escaped <details> rows. */
function headerRows(headers) {
  return Object.entries(headers)
    .map(([k, v]) => `<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(v)}</td></tr>`)
    .join('');
}

/** Full HTML document echoing the request. Every value is escaped. */
export function renderHtml(f) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your request · True Positive</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%23161A22'/%3E%3Cpath d='M9 16.5l4.5 4.5L23 11' fill='none' stroke='%23D49A5C' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
:root{--bg:#0E1116;--panel:#161A22;--panel-high:#1F2530;--line:#2A323F;--text:#E8EBF0;--muted:#8A93A3;--bronze:#D49A5C;--bronze-bright:#F2C58A}
*{box-sizing:border-box}html,body{margin:0}
body{background:var(--bg);color:var(--text);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:720px;margin:0 auto;padding:clamp(2rem,6vw,4rem) 1.5rem 3rem}
h1{font-size:clamp(1.6rem,5vw,2.2rem);letter-spacing:-.02em;margin:0 0 .25rem}
.lede{color:var(--bronze-bright);margin:0 0 2rem}
h2{font-size:.82rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:2rem 0 .5rem}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:.55rem .9rem;vertical-align:top;border-top:1px solid var(--line);font-size:.92rem}
tr:first-child th,tr:first-child td{border-top:none}
th{color:var(--muted);font-weight:500;width:34%;white-space:nowrap}
td{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-word}
details{margin-top:.5rem}summary{cursor:pointer;color:var(--bronze-bright)}
</style>
</head>
<body>
<main>
<h1>Your request</h1>
<p class="lede">Here is what this server sees.</p>
<h2>Your source</h2>
<table>${row('IP', f.ip)}${row('Country', f.country)}${row('City', f.city)}${row('ASN', f.asn)}${row('Colo', f.colo)}</table>
<h2>Request</h2>
<table>${row('Method', f.method)}${row('Path', f.path)}${row('HTTP version', f.http_ver)}${row('User-Agent', f.user_agent)}${row('Referer', f.referer)}${row('Accept-Language', f.accept_lang)}${row('Time (UTC)', f.ts)}</table>
<h2>TLS</h2>
<table>${row('Version', f.tls_version)}${row('Cipher', f.tls_cipher)}</table>
<h2>All headers</h2>
<details><summary>Show ${Object.keys(f.headers).length} headers</summary>
<table>${headerRows(f.headers)}</table>
</details>
</main>
</body>
</html>`;
}
