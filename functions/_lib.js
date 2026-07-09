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
