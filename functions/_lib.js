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
