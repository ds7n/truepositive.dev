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
 * Best-effort parse of a User-Agent string into structured fields. Pure and
 * dependency-free; covers the common desktop/mobile browsers, OSes, engines,
 * and obvious bots. Unknown pieces are null — the raw UA is always kept
 * separately by the caller, so a miss here never loses information.
 *
 * Returns { browser, browser_version, os, os_version, device, engine, bot }.
 */
export function parseUserAgent(ua) {
  const empty = {
    browser: null, browser_version: null, os: null, os_version: null,
    device: null, engine: null, bot: false,
  };
  if (!ua || typeof ua !== 'string') return empty;

  const out = { ...empty };

  // Bots / crawlers / tools first — they often masquerade with browser tokens.
  const botMatch = ua.match(/(bot|crawler|spider|crawling|slurp|curl|wget|python-requests|httpie|Googlebot|bingbot|DuckDuckBot|Baiduspider|YandexBot|facebookexternalhit|Twitterbot|Applebot|PetalBot)/i);
  if (botMatch) {
    out.bot = true;
    out.browser = botMatch[1];
    // curl/wget/httpie expose their own version.
    const toolVer = ua.match(/(?:curl|wget|HTTPie|python-requests)\/([\d.]+)/i);
    if (toolVer) out.browser_version = toolVer[1];
    return out;
  }

  // Engine.
  if (/Gecko\/\d/.test(ua) && /Firefox/.test(ua)) out.engine = 'Gecko';
  else if (/AppleWebKit/.test(ua)) out.engine = /Edg\//.test(ua) || /Chrome/.test(ua) ? 'Blink' : 'WebKit';

  // OS + version.
  let m;
  if ((m = ua.match(/Windows NT ([\d.]+)/))) {
    out.os = 'Windows';
    const winMap = { '10.0': '10/11', '6.3': '8.1', '6.2': '8', '6.1': '7' };
    out.os_version = winMap[m[1]] || m[1];
  } else if ((m = ua.match(/Mac OS X (\d+[._]\d+(?:[._]\d+)?)/))) {
    out.os = 'macOS';
    out.os_version = m[1].replace(/_/g, '.');
  } else if (/iPhone|iPad|iPod/.test(ua)) {
    out.os = 'iOS';
    if ((m = ua.match(/OS (\d+[._]\d+(?:[._]\d+)?)/))) out.os_version = m[1].replace(/_/g, '.');
  } else if ((m = ua.match(/Android ([\d.]+)/))) {
    out.os = 'Android';
    out.os_version = m[1];
  } else if (/CrOS/.test(ua)) {
    out.os = 'ChromeOS';
  } else if (/Linux/.test(ua)) {
    out.os = 'Linux';
  }

  // Browser + version. Order matters: Edge/Opera/Brave impersonate Chrome.
  if ((m = ua.match(/Edg(?:iOS|A)?\/([\d.]+)/))) { out.browser = 'Edge'; out.browser_version = m[1]; }
  else if ((m = ua.match(/OPR\/([\d.]+)/)) || (m = ua.match(/Opera\/([\d.]+)/))) { out.browser = 'Opera'; out.browser_version = m[1]; }
  else if ((m = ua.match(/SamsungBrowser\/([\d.]+)/))) { out.browser = 'Samsung Internet'; out.browser_version = m[1]; }
  else if ((m = ua.match(/Firefox\/([\d.]+)/))) { out.browser = 'Firefox'; out.browser_version = m[1]; }
  else if ((m = ua.match(/Chrome\/([\d.]+)/))) { out.browser = 'Chrome'; out.browser_version = m[1]; }
  else if (/Safari/.test(ua) && (m = ua.match(/Version\/([\d.]+)/))) { out.browser = 'Safari'; out.browser_version = m[1]; }

  // Device class.
  if (/iPad|Tablet/.test(ua) || (/Android/.test(ua) && !/Mobile/.test(ua))) out.device = 'Tablet';
  else if (/Mobi|iPhone|iPod|Android.*Mobile|Windows Phone/.test(ua)) out.device = 'Mobile';
  else out.device = 'Desktop';

  return out;
}

/**
 * Extract the flat field record echoed + logged for a request.
 * Missing cf/header values are null. `headers` is the redacted header map.
 * All available Cloudflare geo/network fields are included; the raw User-Agent
 * is always kept alongside its best-effort parse in `ua`.
 */
export function extractFields(request) {
  const all = headersToObject(request.headers);
  const user_agent = header(all, 'user-agent');
  return {
    ts: new Date().toISOString(),
    ip: header(all, 'cf-connecting-ip'),
    // geo
    country: cf(request, 'country'),
    region: cf(request, 'region'),
    region_code: cf(request, 'regionCode'),
    city: cf(request, 'city'),
    postal_code: cf(request, 'postalCode'),
    continent: cf(request, 'continent'),
    metro_code: cf(request, 'metroCode'),
    timezone: cf(request, 'timezone'),
    latitude: cf(request, 'latitude'),
    longitude: cf(request, 'longitude'),
    is_eu: cf(request, 'isEUCountry'),
    // network
    asn: cf(request, 'asn'),
    as_org: cf(request, 'asOrganization'),
    colo: cf(request, 'colo'),
    // request
    method: request.method,
    path: new URL(request.url).pathname,
    http_ver: cf(request, 'httpProtocol'),
    user_agent,
    ua: parseUserAgent(user_agent),
    referer: header(all, 'referer'),
    accept_lang: header(all, 'accept-language'),
    // tls
    tls_version: cf(request, 'tlsVersion'),
    tls_cipher: cf(request, 'tlsCipher'),
    headers: redactHeaders(all),
  };
}

export function renderJson(fields) {
  return fields;
}

/** Escape a value for direct HTML interpolation; null/empty → em dash. */
function dash(value) {
  return value === null || value === undefined || value === ''
    ? '—'
    : escapeHtml(value);
}

/** Render one label/value grid cell; value is escaped, null/empty → em dash. */
function cell(label, value) {
  return `<div class="cell"><span class="k">${escapeHtml(label)}</span><span class="v">${dash(value)}</span></div>`;
}

/** "City, ST, US" — best-effort human location line from raw fields (unescaped). */
function locationLine(f) {
  return [f.city, f.region_code || f.region, f.country].filter(Boolean).join(', ');
}

/** "Texas (TX)" or "Texas" or "TX" — region with code if both present (unescaped). */
function regionLine(f) {
  if (f.region && f.region_code && f.region !== f.region_code) return `${f.region} (${f.region_code})`;
  return f.region || f.region_code || null;
}

/** "32.7767, -96.7970" or null (unescaped). */
function coordLine(f) {
  return f.latitude && f.longitude ? `${f.latitude}, ${f.longitude}` : null;
}

/** "Chrome 127" / "Chrome" / null — name with optional version (unescaped). */
function versionLine(name, version) {
  if (!name) return null;
  return version ? `${name} ${version}` : name;
}

/** Render the redacted headers map as escaped monospace lines. */
function headerRows(headers) {
  const entries = Object.entries(headers);
  if (entries.length === 0) return '<div class="hline muted">— none —</div>';
  return entries
    .map(([k, v]) => `<div class="hline"><span class="hk">${escapeHtml(k)}</span><span class="hv">${escapeHtml(v)}</span></div>`)
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
body{background:var(--bg);color:var(--text);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:680px;margin:0 auto;padding:clamp(1.5rem,5vw,3rem) 1.25rem 2.5rem}
.eyebrow{color:var(--muted);font-size:.72rem;letter-spacing:.16em;text-transform:uppercase;margin:0 0 .4rem}
.ip{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:clamp(1.6rem,6vw,2.4rem);font-weight:650;letter-spacing:-.01em;color:var(--bronze-bright);margin:0 0 .3rem;word-break:break-all}
.sub{color:var(--muted);font-size:.9rem;margin:0 0 1.6rem}
h2{font-size:.7rem;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin:1.4rem 0 .5rem;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;background:var(--line);border:1px solid var(--line);border-radius:10px;overflow:hidden}
@media(max-width:460px){.grid{grid-template-columns:minmax(0,1fr)}}
.cell{background:var(--panel);padding:.5rem .8rem;min-width:0}
.cell .k{display:block;color:var(--muted);font-size:.68rem;letter-spacing:.06em;text-transform:uppercase;margin-bottom:.1rem}
.cell .v{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9rem;word-break:break-word}
.cell.wide{grid-column:1/-1}
.headers{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:.5rem .2rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem}
.hline{display:flex;gap:.6rem;padding:.2rem .8rem;word-break:break-word}
.hline .hk{color:var(--bronze);flex:0 0 auto;min-width:8.5rem}
.hline .hv{color:var(--text);min-width:0;word-break:break-word}
.muted{color:var(--muted)}
</style>
</head>
<body>
<main>
<p class="eyebrow">Your IP address</p>
<p class="ip">${dash(f.ip)}</p>
<p class="sub">${escapeHtml(locationLine(f) || 'Location unknown')}${f.asn ? ' · AS' + escapeHtml(f.asn) : ''}</p>

<h2>Location</h2>
<div class="grid">${cell('City', f.city)}${cell('Region', regionLine(f))}${cell('Postal code', f.postal_code)}${cell('Country', f.country)}${cell('Continent', f.continent)}${cell('Timezone', f.timezone)}${cell('Coordinates', coordLine(f))}${cell('Network', f.as_org)}</div>

<h2>Browser</h2>
<div class="grid">${cell('Browser', versionLine(f.ua.browser, f.ua.browser_version))}${cell('Operating system', versionLine(f.ua.os, f.ua.os_version))}${cell('Device', f.ua.device)}${cell('Engine', f.ua.engine)}${cell('Language', f.accept_lang)}${cell('Bot', f.ua.bot ? 'yes' : 'no')}<div class="cell wide"><span class="k">Raw user agent</span><span class="v">${dash(f.user_agent)}</span></div></div>

<h2>Request</h2>
<div class="grid">${cell('Method', f.method)}${cell('Path', f.path)}${cell('Referer', f.referer)}${cell('Received (UTC)', f.ts)}</div>

<h2>Connection</h2>
<div class="grid">${cell('TLS', f.tls_version)}${cell('HTTP', f.http_ver)}${cell('Cipher', f.tls_cipher)}${cell('Edge (colo)', f.colo)}</div>

<h2>Request headers</h2>
<div class="headers">${headerRows(f.headers)}</div>
</main>
</body>
</html>`;
}
