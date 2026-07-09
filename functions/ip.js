import { extractFields, renderJson, renderHtml } from './_lib.js';

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};

const CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:";

/** Best-effort insert; never throws into the response path. */
async function logVisit(env, fields) {
  try {
    if (!env || !env.DB) return;
    await env.DB.prepare(
      `INSERT INTO visits
        (ts, ip, country, city, asn, colo, method, path, http_ver,
         user_agent, referer, accept_lang, tls_version, tls_cipher, headers_json)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).bind(
      fields.ts, fields.ip, fields.country, fields.city, fields.asn, fields.colo,
      fields.method, fields.path, fields.http_ver, fields.user_agent,
      fields.referer, fields.accept_lang, fields.tls_version, fields.tls_cipher,
      JSON.stringify(fields.headers),
    ).run();
  } catch (err) {
    // Logging is best-effort; never surface DB errors to the client.
    console.log('visit-log-failed', err && err.message);
  }
}

/** Content-negotiate: browsers (Accept: text/html) get HTML, else JSON. */
function wantsHtml(request) {
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

// Any other method → 405.
export function onRequest(context) {
  const m = context.request.method;
  if (m === 'GET') return onRequestGet(context);
  if (m === 'HEAD') return onRequestHead(context);
  return new Response('Method Not Allowed', {
    status: 405,
    headers: { ...SECURITY_HEADERS, Allow: 'GET, HEAD' },
  });
}
