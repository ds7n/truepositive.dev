import { extractFields, renderJson, renderHtml } from './_lib.js';

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};

const CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:";

/** Best-effort insert; never throws into the response path. */
async function logVisit(env, f) {
  try {
    if (!env || !env.DB) return;
    await env.DB.prepare(
      `INSERT INTO visits
        (ts, ip,
         country, region, region_code, city, postal_code, continent, metro_code,
         timezone, latitude, longitude, is_eu,
         asn, as_org, colo,
         method, path, http_ver,
         user_agent, ua_browser, ua_browser_version, ua_os, ua_os_version,
         ua_device, ua_engine, ua_bot,
         referer, accept_lang, tls_version, tls_cipher, headers_json)
       VALUES (?,?, ?,?,?,?,?,?,?, ?,?,?,?, ?,?,?, ?,?,?, ?,?,?,?,?, ?,?,?, ?,?,?,?,?)`,
    ).bind(
      f.ts, f.ip,
      f.country, f.region, f.region_code, f.city, f.postal_code, f.continent, f.metro_code,
      f.timezone, f.latitude, f.longitude, f.is_eu,
      f.asn, f.as_org, f.colo,
      f.method, f.path, f.http_ver,
      f.user_agent, f.ua.browser, f.ua.browser_version, f.ua.os, f.ua.os_version,
      f.ua.device, f.ua.engine, f.ua.bot ? 1 : 0,
      f.referer, f.accept_lang, f.tls_version, f.tls_cipher,
      JSON.stringify(f.headers),
    ).run();
  } catch (err) {
    // Logging is best-effort; never surface DB errors to the client.
    console.log('visit-log-failed', err && err.message);
  }
}

/**
 * Choose the response format. JSON wins when: the path ends in /json (the
 * dedicated /ip/json route), ?format=json is set, or the client isn't a
 * browser (no Accept: text/html). Otherwise HTML.
 */
function wantsHtml(request) {
  const url = new URL(request.url);
  if (url.pathname.replace(/\/$/, '').endsWith('/json')) return false;
  if ((url.searchParams.get('format') || '').toLowerCase() === 'json') return false;
  const accept = request.headers.get('accept') || '';
  return accept.includes('text/html');
}

async function handle(context) {
  const { request, env } = context;
  const fields = extractFields(request);
  await logVisit(env, fields);

  if (wantsHtml(request)) {
    return new Response(renderHtml(fields), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': CSP,
      },
    });
  }
  return new Response(JSON.stringify(renderJson(fields), null, 2), {
    headers: { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' },
  });
}

export async function onRequestGet(context) {
  try {
    return await handle(context);
  } catch (err) {
    console.log('ip-endpoint-error', err && err.message);
    return new Response('Internal error', { status: 500, headers: SECURITY_HEADERS });
  }
}

// HEAD: same headers, no body — reuse GET then strip the body.
export async function onRequestHead(context) {
  const res = await onRequestGet(context);
  return new Response(null, { status: res.status, headers: res.headers });
}

// GET and HEAD are handled by onRequestGet/onRequestHead above (Cloudflare
// routes method-specific handlers with precedence over onRequest). This
// catch-all therefore only runs for other methods → 405.
export function onRequest() {
  return new Response('Method Not Allowed', {
    status: 405,
    headers: { ...SECURITY_HEADERS, Allow: 'GET, HEAD' },
  });
}
